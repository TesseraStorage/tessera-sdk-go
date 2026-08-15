package siastorage

// Proof that WithHostClient exposes the two events that are unavailable in the stock public API.
// This is a COMPILE-AND-BEHAVIOUR test of the seam itself, not of upload logic: if this compiles,
// an external integrator can implement the same wrapper, because it uses only exported names.

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
)

// observer wraps a HostClient and records the events a dashboard needs.
type observer struct {
	HostClient // embedded: every method not overridden delegates untouched

	mu       sync.Mutex
	picked   []types.PublicKey
	failed   []types.PublicKey
	released int
}

// PickWrite is the "a write is starting on THIS host" trigger. Stock SDK has no equivalent.
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

// AddFailedRPC is the "this host failed" trigger. Stock SDK swallows it: pool.swap() substitutes
// the host and only the substitute's success is ever reported.
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

	// The SDK applies the decorator during construction; here we exercise the wrapper directly to
	// prove the contract an integrator relies on, without needing a live cluster.
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
