package siastorage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"go.sia.tech/indexd/hosts"
	"go.uber.org/zap/zaptest"
	"lukechampine.com/frand"
)

// The read-path egress tests drive real mocked downloads over a 10-of-30 slab
// (the minimum allowed redundancy). Before downloading they hide every host
// except the 15 holding the first 15 sectors, so the initial overprovisioning
// reads exactly minShards*3/2 = 15 sectors -- every visible host -- and no
// spare host exists for racing: each visible sector read is attempted exactly
// once, and the tenth success cancels the remaining reads deterministically.
const (
	egressReadDataShards   = 10
	egressReadParityShards = 20
	egressReadTotalShards  = egressReadDataShards + egressReadParityShards

	// egressReadServedShards is both minShards*3/2 (the size of the initial
	// read wave) and the number of visible hosts, so every read is attempted
	// and none is replaceable.
	egressReadServedShards = egressReadDataShards * 3 / 2

	// egressReadRegionBytes is the per-sector region sectorRegion requests for
	// the 4 KiB first chunk: minChunkSize is LeafSize*MinShards = 640, so
	// ceil(4096/640)*64 = 448 bytes.
	egressReadRegionBytes = 448
)

// newEgressReadSDK builds a mocked, egress-enabled SDK whose host cache starts
// with one host per slab sector and an offline capture of every posted
// envelope.
func newEgressReadSDK(t *testing.T, capture *egressCapture, opts ...Option) (*SDK, *mockHostClient) {
	t.Helper()
	return newTestSDK(t, egressReadTotalShards, zaptest.NewLogger(t),
		append([]Option{
			WithEgressURL("http://egress.test/api/v1/usage/egress"),
			withEgressCapture(capture),
			WithEgressInterval(time.Hour),
			WithEgressBatchMax(500),
		}, opts...)...)
}

// uploadEgressReadObject uploads a random 10-of-30 slab holding exactly one
// chunk, then hides the hosts of every sector except the first
// egressReadServedShards so the download reads exactly those sectors.
func uploadEgressReadObject(t *testing.T, sdk *SDK) (Object, []byte) {
	t.Helper()
	data := frand.Bytes(4096) // one small chunk: the chunk iterator starts at 32 KiB
	obj := NewEmptyObject()
	if err := sdk.Upload(t.Context(), &obj, bytes.NewReader(data),
		WithRedundancy(egressReadDataShards, egressReadParityShards)); err != nil {
		t.Fatalf("failed to upload: %v", err)
	}
	if got := len(obj.Slabs()); got != 1 {
		t.Fatalf("upload produced %d slabs, want 1", got)
	}
	slab := obj.Slabs()[0]
	if slab.MinShards != egressReadDataShards || len(slab.Sectors) != egressReadTotalShards {
		t.Fatalf("unexpected slab shape: minShards=%d sectors=%d", slab.MinShards, len(slab.Sectors))
	}
	if offset, region := sectorRegion(slab); offset != 0 || region != egressReadRegionBytes {
		t.Fatalf("unexpected sector region: offset=%d length=%d, want 0/%d", offset, region, egressReadRegionBytes)
	}

	// a host is usable only while it is cached, so shrinking the cache is what
	// an indexer dropping hosts looks like to the SDK
	keep := make([]hosts.HostInfo, 0, egressReadServedShards)
	for _, sector := range slab.Sectors[:egressReadServedShards] {
		keep = append(keep, hosts.HostInfo{PublicKey: sector.HostKey, GoodForUpload: true})
	}
	sdk.hostsCache.updateHosts(keep)
	return obj, data
}

// reportedShard is one decoded event from a real posted envelope.
type reportedShard struct {
	hostKey    string
	shardIndex int
	bytes      int
}

// reportedShards decodes an envelope's events and asserts the wire shape every
// read-path event must have: a hex host key, integer shard index and byte
// count, and a null slab_id (slabs.SlabSlice carries no id).
func reportedShards(t *testing.T, value map[string]any) []reportedShard {
	t.Helper()
	raw, ok := value["events"].([]any)
	if !ok {
		t.Fatalf("events = %v, want an array", value["events"])
	}
	events := make([]reportedShard, 0, len(raw))
	for i, e := range raw {
		event, ok := e.(map[string]any)
		if !ok {
			t.Fatalf("event %d = %v, want an object", i, e)
		}
		if event["slab_id"] != nil {
			t.Fatalf("event %d slab_id = %v, want null (SlabSlice has no id)", i, event["slab_id"])
		}
		host, ok := event["host_key"].(string)
		if !ok {
			t.Fatalf("event %d host_key = %v", i, event["host_key"])
		}
		index, ok := event["shard_index"].(json.Number)
		if !ok {
			t.Fatalf("event %d shard_index = %v", i, event["shard_index"])
		}
		idx, err := index.Int64()
		if err != nil {
			t.Fatalf("event %d shard_index: %v", i, err)
		}
		count, ok := event["bytes"].(json.Number)
		if !ok {
			t.Fatalf("event %d bytes = %v", i, event["bytes"])
		}
		n, err := count.Int64()
		if err != nil {
			t.Fatalf("event %d bytes: %v", i, err)
		}
		events = append(events, reportedShard{hostKey: host, shardIndex: int(idx), bytes: int(n)})
	}
	return events
}

// waitForCondition polls ok until it returns true or the deadline passes.
func waitForCondition(t *testing.T, ok func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDownloadReportsServedShards verifies the read-path hook reports every
// successfully served shard, including an overprovisioned read that completes
// only after the chunk already has enough shards. The gated host's read writes
// the whole sector and then finishes only once the chunk's completion has
// cancelled it, so its result can never be selected; its event can only exist
// because record runs immediately after ReadSector returns, before the
// delivery select.
//
// Go's select chooses randomly between ready cases, so one gated read per
// download would catch a hook placed inside the delivery case only about half
// the time. The rounds make that misplacement fail with probability
// 1 - 2^-rounds.
func TestDownloadReportsServedShards(t *testing.T) {
	const rounds = 16

	capture := &egressCapture{}
	sdk, hosts := newEgressReadSDK(t, capture)
	defer sdk.Close()

	obj, data := uploadEgressReadObject(t, sdk)
	slab := obj.Slabs()[0]

	// servedOnCancel writes the full region, then reports success only after
	// the read context is cancelled: the host served the bytes, but the
	// result always loses the race for the chunk.
	servedOnCancel := func(ctx context.Context, w io.Writer, sector []byte) error {
		if _, err := w.Write(sector); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	}

	for round := 0; round < rounds; round++ {
		gated := slab.Sectors[round%egressReadServedShards].HostKey
		hosts.SetReadCompletion(gated, servedOnCancel)
		before := sdk.egress.queueLen()

		got, err := readAll(sdk.Download(obj))
		hosts.SetReadCompletion(gated, nil)
		if err != nil {
			t.Fatalf("round %d: download failed: %v", round, err)
		} else if !bytes.Equal(got, data) {
			t.Fatalf("round %d: data mismatch", round)
		}
		// Every sector read succeeds -- the gated one only after the chunk
		// completed -- so every served shard must be queued.
		if n := sdk.egress.queueLen() - before; n != egressReadServedShards {
			t.Fatalf("round %d: recorded %d served shard(s), want %d; the gated read returns only after cancellation",
				round, n, egressReadServedShards)
		}
	}

	// one envelope carries every served read; check its real wire contents
	sdk.egress.flushNow()
	if got := capture.count(); got != 1 {
		t.Fatalf("posted %d envelopes, want 1", got)
	}
	value := verifyEgressEnvelope(t, sdk.AppKey(), capture.bodies()[0])
	events := reportedShards(t, value)
	if len(events) != rounds*egressReadServedShards {
		t.Fatalf("envelope has %d events, want %d", len(events), rounds*egressReadServedShards)
	}
	totals, ok := value["totals"].(map[string]any)
	if !ok {
		t.Fatalf("totals = %v, want an object", value["totals"])
	}
	if want := json.Number(fmt.Sprint(rounds * egressReadServedShards)); totals["shards"] != want {
		t.Fatalf("totals.shards = %v, want %s", totals["shards"], want)
	}
	if want := json.Number(fmt.Sprint(rounds * egressReadServedShards * egressReadRegionBytes)); totals["bytes"] != want {
		t.Fatalf("totals.bytes = %v, want %s", totals["bytes"], want)
	}

	seen := make(map[string]int)
	for _, event := range events {
		if event.bytes != egressReadRegionBytes {
			t.Fatalf("event bytes = %d, want %d", event.bytes, egressReadRegionBytes)
		}
		if event.shardIndex < 0 || event.shardIndex >= egressReadServedShards {
			t.Fatalf("shard_index %d out of range", event.shardIndex)
		}
		if want := slab.Sectors[event.shardIndex].HostKey.String(); event.hostKey != want {
			t.Fatalf("event host %s for shard %d, want %s", event.hostKey, event.shardIndex, want)
		}
		seen[event.hostKey]++
	}
	for _, sector := range slab.Sectors[:egressReadServedShards] {
		if got := seen[sector.HostKey.String()]; got != rounds {
			t.Fatalf("host %s reported %d time(s), want %d", sector.HostKey, got, rounds)
		}
	}
}

// TestDownloadFailedReadsAreNotReported verifies failed reads never produce an
// event: an RPC error (the Go analogue of the Rust suite's ErrInvalidProof)
// and a cancellation that arrives mid-write, after partial bytes have already
// reached the caller's buffer.
func TestDownloadFailedReadsAreNotReported(t *testing.T) {
	cases := []struct {
		name string
		hook func(ctx context.Context, w io.Writer, sector []byte) error
	}{
		{
			name: "rpc error",
			hook: func(context.Context, io.Writer, []byte) error {
				return errors.New("sector proof invalid")
			},
		},
		{
			name: "cancelled mid-write",
			hook: func(ctx context.Context, w io.Writer, sector []byte) error {
				if _, err := w.Write(sector[:len(sector)/2]); err != nil {
					return err
				}
				<-ctx.Done()
				return context.Cause(ctx)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capture := &egressCapture{}
			sdk, hosts := newEgressReadSDK(t, capture)
			defer sdk.Close()

			obj, data := uploadEgressReadObject(t, sdk)
			slab := obj.Slabs()[0]
			failed := slab.Sectors[0].HostKey

			// make the failing read observable: it must be attempted, and
			// its bytes must never show up in an envelope
			var attempts atomic.Int64
			hosts.SetReadCompletion(failed, func(ctx context.Context, w io.Writer, sector []byte) error {
				attempts.Add(1)
				return tc.hook(ctx, w, sector)
			})

			got, err := readAll(sdk.Download(obj))
			if err != nil {
				t.Fatalf("download failed: %v", err)
			} else if !bytes.Equal(got, data) {
				t.Fatal("data mismatch")
			}
			if got := attempts.Load(); got != 1 {
				t.Fatalf("the failing host was read %d time(s), want 1", got)
			}

			sdk.egress.flushNow()
			if got := capture.count(); got != 1 {
				t.Fatalf("posted %d envelopes, want 1", got)
			}
			events := reportedShards(t, verifyEgressEnvelope(t, sdk.AppKey(), capture.bodies()[0]))
			if len(events) != egressReadServedShards-1 {
				t.Fatalf("envelope has %d events, want %d (the failed read must not be reported)",
					len(events), egressReadServedShards-1)
			}
			reported := make(map[string]bool, len(events))
			for _, event := range events {
				if event.hostKey == failed.String() {
					t.Fatalf("the failed read on %s was reported", failed)
				}
				if event.bytes != egressReadRegionBytes || event.shardIndex < 0 || event.shardIndex >= egressReadServedShards {
					t.Fatalf("unexpected event %+v", event)
				}
				reported[event.hostKey] = true
			}
			for _, sector := range slab.Sectors[:egressReadServedShards] {
				if sector.HostKey != failed && !reported[sector.HostKey.String()] {
					t.Fatalf("served shard on %s was not reported", sector.HostKey)
				}
			}
		})
	}
}

// TestDownloadSurvivesEgressFailures verifies a reporter that can neither
// reach its endpoint nor write its spool never affects a download, and that
// every served shard is still reported once the reporter recovers.
func TestDownloadSurvivesEgressFailures(t *testing.T) {
	spool := filepath.Join(t.TempDir(), "egress.spool")
	capture := &egressCapture{}
	sdk, _ := newEgressReadSDK(t, capture,
		WithEgressBatchMax(1),
		WithEgressSpoolPath(spool))
	defer sdk.Close()

	var spoolWrites atomic.Int64
	sdk.egress.writeSpoolFile = func(string, []byte) error {
		spoolWrites.Add(1)
		return errors.New("injected spool write failure")
	}

	obj, data := uploadEgressReadObject(t, sdk)

	// From the first served shard on, every send fails and every spool write
	// fails, so the reporter must retry from memory while the download
	// continues.
	capture.failAll(errors.New("egress endpoint offline"))

	rc, err := sdk.Download(obj)
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	waitForEgressAttempts(t, capture, 1)
	waitForCondition(t, func() bool { return spoolWrites.Load() > 0 }, "the reporter never attempted the failing spool write")

	got, err := io.ReadAll(rc)
	if err != nil {
		rc.Close()
		t.Fatalf("download failed mid-stream: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("failed to close download: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("data mismatch")
	}

	// The endpoint recovers: drain the reporter and check every served shard
	// arrived in a real envelope.
	capture.succeedAll()
	for i := 0; i < 100 && (sdk.egress.queueLen() > 0 || sdk.egress.hasPending() || sdk.egress.hasSpoolWork()); i++ {
		sdk.egress.flushNow()
	}
	if n := sdk.egress.queueLen(); n != 0 {
		t.Fatalf("%d event(s) left queued after the endpoint recovered", n)
	} else if sdk.egress.hasPending() {
		t.Fatal("an envelope is still pending after the endpoint recovered")
	}

	reported := make(map[string]bool)
	for _, body := range capture.bodies() {
		for _, event := range reportedShards(t, verifyEgressEnvelope(t, sdk.AppKey(), body)) {
			if event.bytes != egressReadRegionBytes {
				t.Fatalf("event bytes = %d, want %d", event.bytes, egressReadRegionBytes)
			}
			reported[fmt.Sprintf("%s|%d", event.hostKey, event.shardIndex)] = true
		}
	}
	for i, sector := range obj.Slabs()[0].Sectors[:egressReadServedShards] {
		key := fmt.Sprintf("%s|%d", sector.HostKey, i)
		if !reported[key] {
			t.Fatalf("served shard %s was never reported", key)
		}
		delete(reported, key)
	}
	if len(reported) != 0 {
		t.Fatalf("envelopes contain unexpected events: %v", reported)
	}
}
