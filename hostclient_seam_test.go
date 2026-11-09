package siastorage

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	proto4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	rhp "go.sia.tech/coreutils/rhp/v4"
	"go.sia.tech/indexd/client/v2"
	"go.sia.tech/indexd/hosts"
)

// observer wraps a HostClient and records host events.
type observer struct {
	HostClient // embedded: every method not overridden delegates untouched

	mu       sync.Mutex
	picked   []types.PublicKey
	failed   []types.PublicKey
	released int
}

// PickWrite records that a write is starting on this host.
func (o *observer) PickWrite(candidates []types.PublicKey) (types.PublicKey, func(), []types.PublicKey, bool) {
	host, release, remaining, ok := o.HostClient.PickWrite(candidates)
	if ok {
		o.mu.Lock()
		o.picked = append(o.picked, host)
		o.mu.Unlock()
	}
	return host, func() {
		o.mu.Lock()
		o.released++
		o.mu.Unlock()
		release()
	}, remaining, ok
}

// AddFailedRPC records that this host's RPC failed.
func (o *observer) AddFailedRPC(hostKey types.PublicKey) {
	o.mu.Lock()
	o.failed = append(o.failed, hostKey)
	o.mu.Unlock()
	o.HostClient.AddFailedRPC(hostKey)
}

// stubHost satisfies HostClient with no behaviour; the test only needs the wrapper to be
// installed and delegated to, not a working transport.
type stubHost struct{ picked int }

func (s *stubHost) Prices(context.Context, types.PublicKey) (proto4.HostPrices, error) {
	return proto4.HostPrices{}, nil
}
func (s *stubHost) ReadSector(context.Context, types.PrivateKey, types.PublicKey, types.Hash256, io.Writer, uint64, uint64) (rhp.RPCReadSectorResult, error) {
	return rhp.RPCReadSectorResult{}, nil
}
func (s *stubHost) WriteSector(context.Context, types.PrivateKey, types.PublicKey, []byte) (rhp.RPCWriteSectorResult, error) {
	return rhp.RPCWriteSectorResult{}, nil
}
func (s *stubHost) AddFailedRPC(types.PublicKey)                     {}
func (s *stubHost) Prioritize(h []types.PublicKey) []types.PublicKey { return h }
func (s *stubHost) ReadEstimate(uint64) time.Duration                { return time.Second }
func (s *stubHost) WriteEstimate(uint64) time.Duration               { return time.Second }
func (s *stubHost) TrackInflightRead(types.PublicKey) func()         { return func() {} }
func (s *stubHost) UploadQueue() (*client.HostQueue, error)          { return nil, nil }
func (s *stubHost) Close() error                                     { return nil }
func (s *stubHost) PickWrite(c []types.PublicKey) (types.PublicKey, func(), []types.PublicKey, bool) {
	s.picked++
	if len(c) == 0 {
		return types.PublicKey{}, func() {}, nil, false
	}
	return c[0], func() {}, c[1:], true
}

// TestWithHostClientSeam asserts the wrapper is installed, delegates, and surfaces both events.
func TestWithHostClientSeam(t *testing.T) {
	base := &stubHost{}
	obs := &observer{HostClient: base}

	hk := types.PublicKey{1, 2, 3}
	host, release, _, ok := obs.PickWrite([]types.PublicKey{hk})
	if !ok || host != hk {
		t.Fatalf("PickWrite did not delegate: ok=%v host=%v", ok, host)
	}
	if base.picked != 1 {
		t.Fatalf("underlying client was bypassed: picked=%d", base.picked)
	}
	release()
	obs.AddFailedRPC(hk)

	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.picked) != 1 {
		t.Errorf("write-starting event not observed: %v", obs.picked)
	}
	if obs.released != 1 {
		t.Errorf("release not observed: %d", obs.released)
	}
	if len(obs.failed) != 1 {
		t.Errorf("host-failure event not observed: %v", obs.failed)
	}
}

// TestWithHostClientNilIsNoop: a nil wrapper must not panic or alter construction.
func TestWithHostClientNilIsNoop(t *testing.T) {
	sdk := &SDK{}
	WithHostClient(nil)(sdk)
	if sdk.wrapHosts != nil {
		t.Fatal("nil wrapper should not be stored")
	}
}

// TestWithHostClientIdentity: returning the argument unchanged must be safe.
func TestWithHostClientIdentity(t *testing.T) {
	sdk := &SDK{}
	WithHostClient(func(h HostClient) HostClient { return h })(sdk)
	if sdk.wrapHosts == nil {
		t.Fatal("wrapper was not stored")
	}
	base := &stubHost{}
	if got := sdk.wrapHosts(base); got != HostClient(base) {
		t.Fatal("identity wrapper did not return the same client")
	}
}

// TestWithHostClientAppliedByConstructor checks that initSDK wraps both the
// write client and the per-download client.
func TestWithHostClientAppliedByConstructor(t *testing.T) {
	appKey := types.GeneratePrivateKey()
	hostStore := newMockHostStore(1)
	appMock := newMockAppClient(hostStore)
	hk := types.GeneratePrivateKey().PublicKey()

	obs := &observer{}
	sdk, err := initSDK(appKey, appMock, WithHostClient(func(hc HostClient) HostClient {
		obs.HostClient = hc
		return obs
	}))
	if err != nil {
		t.Fatalf("initSDK failed: %v", err)
	}
	defer sdk.Close()

	sdk.hostsCache.updateHosts([]hosts.HostInfo{{PublicKey: hk, GoodForUpload: true}})

	picked, release, remaining, ok := sdk.hosts.PickWrite([]types.PublicKey{hk})
	if !ok || picked != hk || len(remaining) != 0 {
		t.Fatalf("PickWrite = (%v, _, %v, %v), want (%v, _, [], true)", picked, remaining, ok, hk)
	}
	release()
	sdk.hosts.AddFailedRPC(hk)
	if got := sdk.hosts.Prioritize([]types.PublicKey{hk}); len(got) != 1 || got[0] != hk {
		t.Fatalf("Prioritize = %v, want [%v]", got, hk)
	}

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
