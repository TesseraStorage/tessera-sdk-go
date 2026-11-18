package siastorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/indexd/api"
	"go.sia.tech/indexd/hosts"
	"go.sia.tech/indexd/slabs"
	"go.uber.org/zap/zaptest"
	"lukechampine.com/frand"
)

// failingApp wraps an appClient and fails selected calls.
type failingApp struct {
	appClient
	hostsErr    error
	pinObjErr   error
	pinSlabsErr error
	// pinSlabsOK is the number of PinSlabs calls that succeed before
	// pinSlabsErr is returned.
	pinSlabsOK int
}

func (f *failingApp) Hosts(ctx context.Context, key types.PrivateKey, opts ...api.URLQueryParameterOption) ([]hosts.HostInfo, error) {
	if f.hostsErr != nil {
		return nil, f.hostsErr
	}
	return f.appClient.Hosts(ctx, key, opts...)
}

func (f *failingApp) PinSlabs(ctx context.Context, key types.PrivateKey, params ...slabs.SlabPinParams) ([]slabs.SlabID, error) {
	if f.pinSlabsErr != nil {
		if f.pinSlabsOK == 0 {
			return nil, f.pinSlabsErr
		}
		f.pinSlabsOK--
	}
	return f.appClient.PinSlabs(ctx, key, params...)
}

func (f *failingApp) PinObject(ctx context.Context, key types.PrivateKey, obj slabs.SealedObject) error {
	if f.pinObjErr != nil {
		return f.pinObjErr
	}
	return f.appClient.PinObject(ctx, key, obj)
}

func waitEvent[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(10 * time.Second):
		t.Fatal("hook was not called")
		panic("unreachable")
	}
}

func expectNoEvent[T any](t *testing.T, ch <-chan T) {
	t.Helper()
	select {
	case ev := <-ch:
		t.Fatalf("unexpected hook call: %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}

const hookData, hookParity = 3, 9

func TestAgentHooksUploadDownloadComplete(t *testing.T) {
	uploads := make(chan UploadCompleteEvent, 1)
	downloads := make(chan DownloadCompleteEvent, 2)
	failures := make(chan WriteFailedEvent, 1)
	sdk, _ := newTestSDK(t, hookData+hookParity, zaptest.NewLogger(t), WithAgentHooks(AgentHooks{
		OnUploadComplete:   func(ev UploadCompleteEvent) { uploads <- ev },
		OnDownloadComplete: func(ev DownloadCompleteEvent) { downloads <- ev },
		OnWriteFailed:      func(ev WriteFailedEvent) { failures <- ev },
	}))
	defer sdk.Close()

	// the caller's own progress callback still sees every shard
	var progress int
	data := frand.Bytes(3000)
	obj := NewEmptyObject()
	if err := sdk.Upload(t.Context(), &obj, bytes.NewReader(data), WithRedundancy(hookData, hookParity), WithUploadProgress(func(ShardProgress) { progress++ })); err != nil {
		t.Fatal(err)
	}
	up := waitEvent(t, uploads)
	if up.ObjectID != obj.ID() || up.Size != uint64(len(data)) || up.Slabs != 1 {
		t.Fatalf("unexpected upload event %+v", up)
	} else if up.ShardsAcknowledged != hookData+hookParity || progress != hookData+hookParity {
		t.Fatalf("expected %d shards, event %d, progress %d", hookData+hookParity, up.ShardsAcknowledged, progress)
	} else if up.Elapsed <= 0 {
		t.Fatal("expected elapsed time")
	}

	if err := sdk.PinObject(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	expectNoEvent(t, failures)

	// Read path
	rc, err := sdk.Download(obj)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(struct{ io.Reader }{rc}) // force the Read path
	rc.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("download mismatch", err)
	}
	dl := waitEvent(t, downloads)
	if dl.ObjectID != obj.ID() || dl.Bytes != uint64(len(data)) {
		t.Fatalf("unexpected download event %+v", dl)
	}

	// WriteTo path
	rc, err = sdk.Download(obj, WithDownloadRange(10, 100))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, rc); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if !bytes.Equal(buf.Bytes(), data[10:110]) {
		t.Fatal("range mismatch")
	}
	if dl := waitEvent(t, downloads); dl.Bytes != 100 {
		t.Fatalf("unexpected range download event %+v", dl)
	}
}

func TestAgentHooksDownloadClosedEarly(t *testing.T) {
	downloads := make(chan DownloadCompleteEvent, 1)
	sdk, _ := newTestSDK(t, hookData+hookParity, zaptest.NewLogger(t), WithAgentHooks(AgentHooks{
		OnDownloadComplete: func(ev DownloadCompleteEvent) { downloads <- ev },
	}))
	defer sdk.Close()

	obj := NewEmptyObject()
	if err := sdk.Upload(t.Context(), &obj, bytes.NewReader(frand.Bytes(5000)), WithRedundancy(hookData, hookParity)); err != nil {
		t.Fatal(err)
	}
	rc, err := sdk.Download(obj)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Read(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	expectNoEvent(t, downloads)
}

func TestAgentHooksAbsent(t *testing.T) {
	sdk, _ := newTestSDK(t, hookData+hookParity, zaptest.NewLogger(t))
	defer sdk.Close()

	data := frand.Bytes(2000)
	obj := NewEmptyObject()
	if err := sdk.Upload(t.Context(), &obj, bytes.NewReader(data), WithRedundancy(hookData, hookParity)); err != nil {
		t.Fatal(err)
	} else if err := sdk.PinObject(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	rc, err := sdk.Download(obj)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	// without hooks the SDK's own stream type is returned unwrapped
	if _, ok := rc.(*downloadStream); !ok {
		t.Fatalf("expected *downloadStream, got %T", rc)
	}
	got, err := io.ReadAll(rc)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("download mismatch", err)
	}
}

func TestAgentHooksPanicDoesNotFailTransfer(t *testing.T) {
	called := make(chan string, 4)
	sdk, _ := newTestSDK(t, hookData+hookParity, zaptest.NewLogger(t), WithAgentHooks(AgentHooks{
		OnUploadComplete:   func(UploadCompleteEvent) { called <- "upload"; panic("upload hook") },
		OnDownloadComplete: func(DownloadCompleteEvent) { called <- "download"; panic("download hook") },
		OnWriteFailed:      func(WriteFailedEvent) { called <- "failed"; panic("failed hook") },
	}))
	defer sdk.Close()

	data := frand.Bytes(2000)
	obj := NewEmptyObject()
	if err := sdk.Upload(t.Context(), &obj, bytes.NewReader(data), WithRedundancy(hookData, hookParity)); err != nil {
		t.Fatal(err)
	} else if err := sdk.PinObject(t.Context(), obj); err != nil {
		t.Fatal(err)
	}
	rc, err := sdk.Download(obj)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("download mismatch", err)
	}

	// a failing write still returns its own error, not the hook's panic
	sdk.app = &failingApp{appClient: sdk.app, pinObjErr: errors.New("pin down")}
	if err := sdk.PinObject(t.Context(), obj); err == nil || err.Error() != "pin down" {
		t.Fatal("unexpected", err)
	}

	seen := map[string]bool{}
	for range 3 {
		seen[waitEvent(t, called)] = true
	}
	if !seen["upload"] || !seen["download"] || !seen["failed"] {
		t.Fatalf("not every hook ran: %v", seen)
	}
	// give the recovered goroutines time to finish; the test binary would
	// crash here if a panic escaped
	time.Sleep(100 * time.Millisecond)
}

func TestAgentHooksWriteFailedStages(t *testing.T) {
	failures := make(chan WriteFailedEvent, 1)
	uploads := make(chan UploadCompleteEvent, 1)
	hooks := WithAgentHooks(AgentHooks{
		OnUploadComplete: func(ev UploadCompleteEvent) { uploads <- ev },
		OnWriteFailed:    func(ev WriteFailedEvent) { failures <- ev },
	})

	t.Run("not sent", func(t *testing.T) {
		sdk, hc := newTestSDK(t, hookData+hookParity, zaptest.NewLogger(t), hooks)
		defer sdk.Close()
		hostsErr := errors.New("hosts unavailable")
		sdk.app = &failingApp{appClient: sdk.app, hostsErr: hostsErr}

		obj := NewEmptyObject()
		err := sdk.Upload(t.Context(), &obj, bytes.NewReader(frand.Bytes(100)), WithRedundancy(hookData, hookParity))
		if !errors.Is(err, hostsErr) {
			t.Fatal("unexpected", err)
		}
		ev := waitEvent(t, failures)
		if ev.Stage != WriteNotSent || ev.WriteAttemptsStarted != 0 || ev.ShardsAcknowledged != 0 || !errors.Is(ev.Err, hostsErr) {
			t.Fatalf("unexpected event %+v", ev)
		} else if ev.Stage.String() != "not_sent" {
			t.Fatal(ev.Stage.String())
		}
		if len(hc.WriteCalls()) != 0 {
			t.Fatal("expected no writes")
		}
		expectNoEvent(t, uploads)
	})

	t.Run("sent not registered", func(t *testing.T) {
		sdk, hc := newTestSDK(t, hookData+hookParity, zaptest.NewLogger(t), hooks)
		defer sdk.Close()
		hc.SetErrHosts(t, hookData+hookParity, 1000, errors.New("host write failed"))

		obj := NewEmptyObject()
		err := sdk.Upload(t.Context(), &obj, bytes.NewReader(frand.Bytes(100)), WithRedundancy(hookData, hookParity))
		if err == nil {
			t.Fatal("expected upload to fail")
		}
		ev := waitEvent(t, failures)
		if ev.Stage != WriteSentNotRegistered || ev.WriteAttemptsStarted == 0 || ev.ShardsAcknowledged != 0 {
			t.Fatalf("unexpected event %+v", ev)
		} else if ev.Err != err {
			t.Fatal("event error differs from returned error")
		}
		expectNoEvent(t, uploads)
	})

	t.Run("pin failed", func(t *testing.T) {
		sdk, _ := newTestSDK(t, hookData+hookParity, zaptest.NewLogger(t), hooks)
		defer sdk.Close()

		obj := NewEmptyObject()
		if err := sdk.Upload(t.Context(), &obj, bytes.NewReader(frand.Bytes(1000)), WithRedundancy(hookData, hookParity)); err != nil {
			t.Fatal(err)
		}
		waitEvent(t, uploads)
		app := sdk.app

		// slabs pinned, object not saved
		pinErr := errors.New("indexer unavailable")
		sdk.app = &failingApp{appClient: app, pinObjErr: pinErr}
		if err := sdk.PinObject(t.Context(), obj); !errors.Is(err, pinErr) {
			t.Fatal("unexpected", err)
		}
		ev := waitEvent(t, failures)
		if ev.Stage != WritePinFailed || ev.SlabsPinned != 1 || ev.ObjectID != obj.ID() || ev.WriteAttemptsStarted != 0 {
			t.Fatalf("unexpected event %+v", ev)
		}

		// nothing pinned
		sdk.app = &failingApp{appClient: app, pinSlabsErr: pinErr}
		if err := sdk.PinObject(t.Context(), obj); !errors.Is(err, pinErr) {
			t.Fatal("unexpected", err)
		}
		if ev := waitEvent(t, failures); ev.Stage != WritePinFailed || ev.SlabsPinned != 0 {
			t.Fatalf("unexpected event %+v", ev)
		}

		// retrying the pin succeeds and fires nothing
		sdk.app = app
		if err := sdk.PinObject(t.Context(), obj); err != nil {
			t.Fatal(err)
		}
		expectNoEvent(t, failures)
	})
}

func TestAgentMetadata(t *testing.T) {
	obj := NewEmptyObject()
	if _, ok, err := obj.AgentMetadata(); err != nil || ok {
		t.Fatal("expected no agent metadata", ok, err)
	}

	// empty metadata becomes an object with only the agent key
	meta := AgentMetadata{Name: "indexer-bot", Run: "run-42", Task: "nightly export", Labels: map[string]string{"env": "test"}}
	if err := obj.SetAgentMetadata(meta); err != nil {
		t.Fatal(err)
	}
	got, ok, err := obj.AgentMetadata()
	if err != nil || !ok || got.Name != meta.Name || got.Run != meta.Run || got.Task != meta.Task || got.Labels["env"] != "test" {
		t.Fatalf("unexpected %+v %v %v", got, ok, err)
	}

	// existing keys are kept unchanged
	obj.UpdateMetadata(json.RawMessage(`{"name":"report.pdf","v":1,"tessera":{"sha256":"ab","size":3}}`))
	if err := obj.SetAgentMetadata(AgentMetadata{Name: "a"}); err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(obj.Metadata(), &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["name"]) != `"report.pdf"` || string(fields["v"]) != "1" || string(fields["tessera"]) != `{"sha256":"ab","size":3}` || string(fields["agent"]) != `{"name":"a"}` {
		t.Fatalf("unexpected metadata %s", obj.Metadata())
	}

	// metadata that is not a JSON object is never replaced
	obj.UpdateMetadata(json.RawMessage(`"plain"`))
	if err := obj.SetAgentMetadata(meta); !errors.Is(err, ErrMetadataNotObject) {
		t.Fatal("unexpected", err)
	} else if string(obj.Metadata()) != `"plain"` {
		t.Fatal("metadata was modified")
	}
	if _, _, err := obj.AgentMetadata(); !errors.Is(err, ErrMetadataNotObject) {
		t.Fatal("unexpected", err)
	}
}

func TestAgentMetadataSealRoundTrip(t *testing.T) {
	sdk, _ := newTestSDK(t, hookData+hookParity, zaptest.NewLogger(t))
	defer sdk.Close()

	obj := NewEmptyObject()
	if err := sdk.Upload(t.Context(), &obj, bytes.NewReader(frand.Bytes(100)), WithRedundancy(hookData, hookParity)); err != nil {
		t.Fatal(err)
	}
	if err := obj.SetAgentMetadata(AgentMetadata{Name: "bot", Task: "backup"}); err != nil {
		t.Fatal(err)
	}
	if err := sdk.PinObject(t.Context(), obj); err != nil {
		t.Fatal(err)
	}

	// the pinned (sealed) object does not carry the agent metadata in
	// plaintext, and opening it restores the same values
	sealed := obj.Seal(sdk.AppKey())
	raw, _ := json.Marshal(sealed)
	if bytes.Contains(raw, []byte("backup")) {
		t.Fatal("agent metadata visible in sealed object")
	}
	fetched, err := sdk.Object(t.Context(), obj.ID())
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := fetched.AgentMetadata()
	if err != nil || !ok || got.Name != "bot" || got.Task != "backup" {
		t.Fatalf("unexpected %+v %v %v", got, ok, err)
	}
}
