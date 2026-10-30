package siastorage

// Egress reporting has been removed from this SDK fork entirely (see
// egress.go): there is no option, type, config field, or internal hook left
// anywhere in the package that could build or send a read/egress report.
//
// TestNoEgressCapabilityExists keeps the one assertion from the old
// "reporting is off by default" test that is still meaningful once the whole
// feature is gone: a complete mock upload/download cycle makes zero HTTP
// requests and writes zero files, proving the capability cannot be
// resurrected by any caller, not just that nobody happens to invoke it today.

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
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
	return nil, fmt.Errorf("unexpected HTTP request from the SDK: %s %s", req.Method, req.URL)
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
		t.Fatalf("%d HTTP request(s) issued; the SDK must never call out over HTTP: %v", n, urls)
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

// TestNoEgressCapabilityExists builds an SDK with only the mock seams and
// proves that a complete mock upload/download cycle:
//   - makes no HTTP request at all (http.DefaultTransport is a counting,
//     failing transport for the whole test, so any request at all -- egress
//     or otherwise -- is caught),
//   - writes no file (a t.TempDir is also installed as TMPDIR and must
//     remain empty),
//   - returns exactly the uploaded fixture bytes, i.e. behaves normally.
func TestNoEgressCapabilityExists(t *testing.T) {
	ct := installCountingTransport(t)

	// any implicit temporary file would land here and stay visible
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	sdk, host := newTestSDK(t, 20, zaptest.NewLogger(t))
	defer sdk.Close()

	data := frand.Bytes(int(proto.SectorSize) * 3)
	obj := NewEmptyObject()
	if err := sdk.Upload(t.Context(), &obj, bytes.NewReader(data), WithRedundancy(4, 11)); err != nil {
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

	ct.assertZero(t)
	assertDirEmpty(t, tmp)
}

// TestWithHostClientDecorator proves the fork's WithHostClient seam (covered
// in isolation by TestWithHostClientSeam) is still applied by the production
// constructor, and that decorated calls succeed. It exercises both clients
// that construction wraps: the write-path sdk.hosts and the per-object
// job-scoped client Download uses (newHosts).
func TestWithHostClientDecorator(t *testing.T) {
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
