package siastorage

// Merge-precondition proof for egress reporting (P3b): with no egress endpoint
// configured, an SDK must be completely inert -- no HTTP request, no spool
// file, no reporter or background goroutine -- while a full mock
// upload/download cycle still succeeds with byte-identical results.
//
// The mock seams (Builder.mockApp/mockHost through newTestSDK) keep every app
// and host RPC in memory. Any HTTP request at all would therefore have to come
// from the SDK itself, and the egress reporter builds its http.Client with a
// nil Transport, which falls back to http.DefaultTransport at request time.
// Swapping http.DefaultTransport for a counting, always-failing transport for
// the duration of the test turns both facts into a tripwire: egress traffic is
// counted, and nothing can silently reach the real network.

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	proto "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/indexd/hosts"
	"go.uber.org/zap/zaptest"
	"lukechampine.com/frand"
)

// countingTransport counts every request and refuses it. The inertness proof
// requires zero requests; returning an error instead of delegating guarantees
// a broken build cannot reach the network while the test is running.
type countingTransport struct {
	calls atomic.Int64

	mu   sync.Mutex
	urls []string
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls.Add(1)
	c.mu.Lock()
	c.urls = append(c.urls, req.Method+" "+req.URL.String())
	c.mu.Unlock()
	return nil, fmt.Errorf("unexpected HTTP request with egress reporting unconfigured: %s %s", req.Method, req.URL)
}

// installCountingTransport swaps http.DefaultTransport for the duration of the
// test and restores it in t.Cleanup.
func installCountingTransport(t *testing.T) *countingTransport {
	t.Helper()
	ct := &countingTransport{}
	prev := http.DefaultTransport
	http.DefaultTransport = ct
	t.Cleanup(func() { http.DefaultTransport = prev })
	return ct
}

// assertZero fails with the observed requests when any HTTP request was made.
func (c *countingTransport) assertZero(t *testing.T) {
	t.Helper()
	if n := c.calls.Load(); n != 0 {
		c.mu.Lock()
		urls := append([]string(nil), c.urls...)
		c.mu.Unlock()
		t.Fatalf("%d HTTP request(s) issued with egress reporting unconfigured: %v", n, urls)
	}
}

// assertDirEmpty fails if dir contains any entry at all.
func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read %s: %v", dir, err)
	}
	if len(entries) != 0 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("directory %s is not empty: %v", dir, names)
	}
}

// runMockUploadDownloadCycle writes a fixture through the complete mock write
// path (Upload) and reads it back through the complete mock read path
// (Download), asserting the returned content is byte-identical to what was
// uploaded. The same shape is used by the existing mock network tests.
func runMockUploadDownloadCycle(t *testing.T, sdk *SDK, host *mockHostClient) []byte {
	t.Helper()
	data := frand.Bytes(int(proto.SectorSize) * 10)
	obj := NewEmptyObject()
	if err := sdk.Upload(t.Context(), &obj, bytes.NewReader(data),
		WithRedundancy(egressReadDataShards, egressReadParityShards)); err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	host.waitInflightDrained(t)

	got, err := readAll(sdk.Download(obj))
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("download returned %d bytes, want %d", len(got), len(data))
	} else if !bytes.Equal(got, data) {
		t.Fatal("download content differs from the uploaded fixture")
	}
	host.waitInflightDrained(t)
	return data
}

// TestEgressDisabledIsInert builds an SDK with only the mock seams and no
// egress options, then proves that a complete mock upload/download cycle:
//
//   - makes no HTTP request at all (http.DefaultTransport is a counting,
//     failing transport for the whole test; egress uses a nil-Transport
//     http.Client, so a reporter that wrongly started would be caught),
//   - creates no reporter (sdk.egress stays nil) and writes no spool file
//     (a t.TempDir is also installed as TMPDIR and must remain empty),
//   - returns exactly the uploaded fixture bytes, i.e. behaves normally.
//
// A second case sets only WithEgressSpoolPath (still no URL, so reporting is
// not configured): the configured spool must never be created either.
func TestEgressDisabledIsInert(t *testing.T) {
	t.Run("NoEgressOptions", func(t *testing.T) {
		ct := installCountingTransport(t)

		// any implicit temporary file would land here and stay visible
		tmp := t.TempDir()
		t.Setenv("TMPDIR", tmp)

		sdk, host := newTestSDK(t, egressReadTotalShards, zaptest.NewLogger(t))
		defer sdk.Close()

		if sdk.egress != nil {
			t.Fatal("egress reporter exists without WithEgressURL")
		}
		if sdk.egressCfg.url != "" || sdk.egressCfg.spoolPath != "" || sdk.egressCfg.post != nil {
			t.Fatalf("unexpected egress config: %+v", sdk.egressCfg)
		}

		runMockUploadDownloadCycle(t, sdk, host)

		ct.assertZero(t)
		if sdk.egress != nil {
			t.Fatal("egress reporter appeared after a completed cycle")
		}
		assertDirEmpty(t, tmp)
	})

	t.Run("SpoolPathWithoutURL", func(t *testing.T) {
		ct := installCountingTransport(t)

		dir := t.TempDir()
		spool := filepath.Join(dir, "egress.spool")

		// A spool path without an endpoint is not "reporting configured":
		// initEgress must ignore it and the file must never be created.
		sdk, host := newTestSDK(t, egressReadTotalShards, zaptest.NewLogger(t),
			WithEgressSpoolPath(spool))
		defer sdk.Close()

		if sdk.egress != nil {
			t.Fatal("egress reporter exists without WithEgressURL")
		}

		runMockUploadDownloadCycle(t, sdk, host)

		ct.assertZero(t)
		assertDirEmpty(t, dir)
	})
}

// TestEgressDisabledWithHostClientDecorator proves the fork's WithHostClient
// seam (covered in isolation by TestWithHostClientSeam) is still applied by
// the production constructor on an SDK built without egress options, and that
// decorated calls succeed. It exercises both clients that construction wraps:
// the write-path sdk.hosts and the per-object job-scoped client Download uses
// (newHosts).
func TestEgressDisabledWithHostClientDecorator(t *testing.T) {
	appKey := types.GeneratePrivateKey()
	hostStore := newMockHostStore(1)
	appMock := newMockAppClient(hostStore)
	hk := types.GeneratePrivateKey().PublicKey()

	obs := &observer{} // defined in hostclient_seam_test.go
	sdk, err := initSDK(appKey, appMock, WithHostClient(func(hc HostClient) HostClient {
		obs.HostClient = hc
		return obs
	}))
	if err != nil {
		t.Fatalf("initSDK failed: %v", err)
	}
	defer sdk.Close()

	if sdk.egress != nil {
		t.Fatal("egress reporter exists without WithEgressURL")
	}
	sdk.hostsCache.updateHosts([]hosts.HostInfo{{PublicKey: hk, GoodForUpload: true}})

	// write path: the decorator observes a successful pick/release, and a
	// store-reading call still delegates and succeeds.
	picked, release, remaining, ok := sdk.hosts.PickWrite([]types.PublicKey{hk})
	if !ok || picked != hk || len(remaining) != 0 {
		t.Fatalf("PickWrite = (%v, _, %v, %v), want (%v, _, [], true)", picked, remaining, ok, hk)
	}
	release()
	sdk.hosts.AddFailedRPC(hk)
	if got := sdk.hosts.Prioritize([]types.PublicKey{hk}); len(got) != 1 || got[0] != hk {
		t.Fatalf("Prioritize = %v, want [%v]", got, hk)
	}

	// download path: newHosts returns a decorated job-scoped client.
	scopedStore := newHostCache()
	scopedStore.updateHosts([]hosts.HostInfo{{PublicKey: hk, GoodForUpload: true}})
	scoped := sdk.newHosts(scopedStore)
	pickedScoped, releaseScoped, _, okScoped := scoped.PickWrite([]types.PublicKey{hk})
	if !okScoped || pickedScoped != hk {
		t.Fatalf("scoped PickWrite = (%v, _, _, %v), want (%v, _, _, true)", pickedScoped, okScoped, hk)
	}
	releaseScoped()
	scoped.Close()

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.picked) != 2 || obs.picked[0] != hk || obs.picked[1] != hk {
		t.Fatalf("decorator observed picks %v, want [%v %v]", obs.picked, hk, hk)
	}
	if obs.released != 2 {
		t.Fatalf("decorator observed %d releases, want 2", obs.released)
	}
	if len(obs.failed) != 1 || obs.failed[0] != hk {
		t.Fatalf("decorator observed failures %v, want [%v]", obs.failed, hk)
	}
}
