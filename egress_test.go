package siastorage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// Golden literals from docs/egress-wire-golden.md (moneyd Task 1). They are
// the frozen cross-language contract; do not regenerate.
const (
	goldenEgressSeed       = "1111111111111111111111111111111111111111111111111111111111111111"
	goldenEgressPublicKey  = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
	goldenEgressIdentity   = "ed25519:d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
	goldenEgressBatchID    = "0123456789abcdef0123456789abcdef"
	goldenEgressSignature  = "ed25519:55430153c1313134096162667541e929208cde53967913157c3d0ce427811028278ce59ba7296b240b435cfb3b7cee18462e5d2c4a530d43bb77d76e89854c05"
	goldenEgressSHA256     = "30355f13ac6d508c8afd443e9a91719cddae20e3e18931eb35e80d452d6bc198"
	goldenEgressHostKeyOne = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	goldenEgressHostKeyTwo = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	goldenEgressSlabID     = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	goldenEgressBody = `{"batch_id":"0123456789abcdef0123456789abcdef","events":[{"bytes":4194304,"host_key":"ed25519:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","shard_index":0,"slab_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ts":1728345600000},{"bytes":1048576,"host_key":"ed25519:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100","shard_index":3,"slab_id":null,"ts":1728345600123}],"identity":"ed25519:d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737","seq":1,"totals":{"bytes":5242880,"shards":2}}`

	goldenEgressCanonical = `{"batch_id":"0123456789abcdef0123456789abcdef","events":[{"bytes":4194304,"host_key":"ed25519:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","shard_index":0,"slab_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","ts":1728345600000},{"bytes":1048576,"host_key":"ed25519:ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100","shard_index":3,"slab_id":null,"ts":1728345600123}],"identity":"ed25519:d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737","seq":1,"signature":"ed25519:55430153c1313134096162667541e929208cde53967913157c3d0ce427811028278ce59ba7296b240b435cfb3b7cee18462e5d2c4a530d43bb77d76e89854c05","totals":{"bytes":5242880,"shards":2}}`
)

func mustHex32(t testing.TB, text string) [32]byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", text, err)
	} else if len(decoded) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(decoded))
	}
	var out [32]byte
	copy(out[:], decoded)
	return out
}

func goldenEgressKey(t testing.TB) types.PrivateKey {
	t.Helper()
	seed := mustHex32(t, goldenEgressSeed)
	return types.NewPrivateKeyFromSeed(seed[:])
}

func goldenEgressBatchIDBytes(t testing.TB) (id [16]byte) {
	t.Helper()
	decoded, err := hex.DecodeString(goldenEgressBatchID)
	if err != nil {
		t.Fatalf("invalid batch id hex: %v", err)
	} else if len(decoded) != 16 {
		t.Fatalf("expected 16 batch id bytes, got %d", len(decoded))
	}
	copy(id[:], decoded)
	return
}

func goldenEgressEvents(t testing.TB) []egressEvent {
	t.Helper()
	slab := types.Hash256(mustHex32(t, goldenEgressSlabID))
	return []egressEvent{
		{
			hostKey:    types.PublicKey(mustHex32(t, goldenEgressHostKeyOne)),
			slabID:     &slab,
			shardIndex: 0,
			bytes:      4194304,
			ts:         1728345600000,
		},
		{
			hostKey:    types.PublicKey(mustHex32(t, goldenEgressHostKeyTwo)),
			slabID:     nil,
			shardIndex: 3,
			bytes:      1048576,
			ts:         1728345600123,
		},
	}
}

// verifyEgressEnvelope independently checks a canonical envelope against the
// wire contract: golden identity encoding and a raw stdlib Ed25519 signature
// over the domain-separated preimage. It returns the parsed envelope, kept
// intact with its signature, for further assertions.
func verifyEgressEnvelope(t testing.TB, appKey types.PrivateKey, envelope []byte) map[string]any {
	t.Helper()

	// UseNumber keeps every integer token exactly as received, so the
	// signature is verified over the envelope's own bytes rather than a
	// float64 round-trip that could mask numeric encoding drift.
	decoder := json.NewDecoder(bytes.NewReader(envelope))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("envelope is not JSON: %v\n%s", err, envelope)
	}
	if got := value["identity"]; got != goldenEgressIdentity && got != appKey.PublicKey().String() {
		t.Fatalf("identity = %v, want %s", got, appKey.PublicKey())
	}

	sigText, ok := value["signature"].(string)
	if !ok || !strings.HasPrefix(sigText, "ed25519:") {
		t.Fatalf("bad signature encoding: %v", value["signature"])
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(sigText, "ed25519:"))
	if err != nil {
		t.Fatalf("signature is not hex: %v", err)
	} else if len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	delete(value, "signature")
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("failed to remarshal body: %v", err)
	}
	preimage := append([]byte(egressPreimagePrefix), body...)
	pk := appKey.PublicKey()
	if !ed25519.Verify(pk[:], preimage, sig) {
		t.Fatalf("envelope signature does not verify with raw Ed25519")
	}
	value["signature"] = sigText
	return value
}

func waitForEgressAttempts(t testing.TB, capture *egressCapture, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for capture.count() < want {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d egress attempt(s), got %d", want, capture.count())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestEgressGoldenEnvelope pins the canonical bytes, the signed preimage, the
// identity and the signature to the Task 1 golden vector. Any drift is a wire
// break.
func TestEgressGoldenEnvelope(t *testing.T) {
	appKey := goldenEgressKey(t)
	events := goldenEgressEvents(t)

	body, envelope, err := buildEgressEnvelope(appKey, goldenEgressBatchIDBytes(t), 1, events)
	if err != nil {
		t.Fatalf("failed to build envelope: %v", err)
	}
	if string(body) != goldenEgressBody {
		t.Errorf("canonical body mismatch:\n got %s\nwant %s", body, goldenEgressBody)
	}
	if string(envelope) != goldenEgressCanonical {
		t.Errorf("canonical envelope mismatch:\n got %s\nwant %s", envelope, goldenEgressCanonical)
	}

	digest := sha256.Sum256(envelope)
	if got := hex.EncodeToString(digest[:]); got != goldenEgressSHA256 {
		t.Errorf("sha256(canonical bytes) = %s, want %s", got, goldenEgressSHA256)
	}

	if got := appKey.PublicKey().String(); got != goldenEgressIdentity {
		t.Fatalf("public identity = %s, want %s", got, goldenEgressIdentity)
	}

	// The literal golden signature must verify with raw stdlib Ed25519 over
	// the versioned preimage.
	sig, err := hex.DecodeString(strings.TrimPrefix(goldenEgressSignature, "ed25519:"))
	if err != nil {
		t.Fatal(err)
	}
	preimage := append([]byte(egressPreimagePrefix), []byte(goldenEgressBody)...)
	pk := appKey.PublicKey()
	if !ed25519.Verify(pk[:], preimage, sig) {
		t.Fatal("golden signature does not verify over the golden preimage")
	}
	if ed25519.Verify(pk[:], []byte("tessera-egress-v1:{}"), sig) {
		t.Fatal("golden signature verified over a tampered preimage")
	}
}

// TestEgressThresholdFlush verifies the batch threshold produces exactly one
// envelope and drains the queue.
func TestEgressThresholdFlush(t *testing.T) {
	sdk, capture := newEgressTestSDK(t, WithEgressInterval(time.Hour), WithEgressBatchMax(3))
	defer sdk.Close()

	slab := types.Hash256(mustHex32(t, goldenEgressSlabID))
	sdk.egress.record(types.PublicKey{1}, nil, 0, 100)
	sdk.egress.record(types.PublicKey{2}, &slab, 1, 200)
	time.Sleep(25 * time.Millisecond)
	if got := capture.count(); got != 0 {
		t.Fatalf("below the threshold %d envelope(s) were sent, want 0", got)
	}

	sdk.egress.record(types.PublicKey{3}, nil, 2, 300)
	waitForEgressAttempts(t, capture, 1)

	bodies := capture.bodies()
	if len(bodies) != 1 {
		t.Fatalf("threshold sent %d envelopes, want exactly 1", len(bodies))
	}
	value := verifyEgressEnvelope(t, sdk.AppKey(), bodies[0])
	events, ok := value["events"].([]any)
	if !ok || len(events) != 3 {
		t.Fatalf("events = %v, want 3", value["events"])
	}
	totals := value["totals"].(map[string]any)
	if totals["bytes"] != json.Number("600") || totals["shards"] != json.Number("3") {
		t.Fatalf("totals = %v, want bytes 600 shards 3", totals)
	}
	if value["seq"] != json.Number("1") {
		t.Fatalf("seq = %v, want 1", value["seq"])
	}

	// The threshold flush drained the queue: forcing a flush sends nothing.
	sdk.egress.flushNow()
	if got := capture.count(); got != 1 {
		t.Fatalf("flush after threshold sent %d envelopes, want 1", got)
	}
}

// TestEgressFlushNowDeterministic verifies flushNow does not depend on the
// interval timer.
func TestEgressFlushNowDeterministic(t *testing.T) {
	sdk, capture := newEgressTestSDK(t, WithEgressInterval(time.Hour), WithEgressBatchMax(500))
	defer sdk.Close()

	sdk.egress.record(types.PublicKey{7}, nil, 5, 8192)
	time.Sleep(25 * time.Millisecond)
	if got := capture.count(); got != 0 {
		t.Fatalf("the wall-clock interval fired: %d envelope(s)", got)
	}

	sdk.egress.flushNow()
	if got := capture.count(); got != 1 {
		t.Fatalf("flushNow sent %d envelopes, want 1", got)
	}
	value := verifyEgressEnvelope(t, sdk.AppKey(), capture.bodies()[0])
	events := value["events"].([]any)
	if len(events) != 1 {
		t.Fatalf("flushNow envelope has %d events, want 1", len(events))
	}
	if event := events[0].(map[string]any); event["bytes"] != json.Number("8192") || event["slab_id"] != nil {
		t.Fatalf("unexpected event: %v", event)
	}

	sdk.egress.flushNow()
	if got := capture.count(); got != 1 {
		t.Fatalf("a second flushNow around an empty queue sent %d envelopes, want 1", got)
	}
}

// TestEgressIntervalFlush verifies the interval alone flushes queued events.
func TestEgressIntervalFlush(t *testing.T) {
	sdk, capture := newEgressTestSDK(t, WithEgressInterval(20*time.Millisecond), WithEgressBatchMax(500))
	defer sdk.Close()

	sdk.egress.record(types.PublicKey{4}, nil, 2, 42)
	waitForEgressAttempts(t, capture, 1)
	value := verifyEgressEnvelope(t, sdk.AppKey(), capture.bodies()[0])
	if events := value["events"].([]any); len(events) != 1 {
		t.Fatalf("interval flush envelope has %d events, want 1", len(events))
	}
}

// TestEgressFailedSendRetriesIdenticalEnvelope verifies a retryable failure
// re-queues the identical signed envelope and never propagates.
func TestEgressFailedSendRetriesIdenticalEnvelope(t *testing.T) {
	sdk, capture := newEgressTestSDK(t, WithEgressInterval(time.Hour), WithEgressBatchMax(500))
	defer sdk.Close()

	capture.failNext(errors.New("network down"))
	sdk.egress.record(types.PublicKey{1}, nil, 0, 512)
	sdk.egress.flushNow()
	if got := capture.count(); got != 1 {
		t.Fatalf("first attempt count = %d, want 1", got)
	}
	if !sdk.egress.hasPending() {
		t.Fatal("a transport failure must re-queue the envelope")
	}

	sdk.egress.flushNow()
	bodies := capture.bodies()
	if len(bodies) != 2 {
		t.Fatalf("retry count = %d, want 2", len(bodies))
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatalf("retry must send the identical envelope:\nfirst  %s\nsecond %s", bodies[0], bodies[1])
	}
	first := verifyEgressEnvelope(t, sdk.AppKey(), bodies[0])
	second := verifyEgressEnvelope(t, sdk.AppKey(), bodies[1])
	if first["batch_id"] != second["batch_id"] || first["seq"] != second["seq"] || first["signature"] != second["signature"] {
		t.Fatalf("retry envelope changed: %v vs %v", first, second)
	}
	if sdk.egress.hasPending() {
		t.Fatal("pending must be cleared after a successful retry")
	}
}

// TestEgressRejectedEnvelopeDropped verifies a non-retryable 4xx drops the
// batch without poisoning the next one.
func TestEgressRejectedEnvelopeDropped(t *testing.T) {
	sdk, capture := newEgressTestSDK(t, WithEgressInterval(time.Hour), WithEgressBatchMax(500))
	defer sdk.Close()

	capture.failNext(&egressSendError{status: http.StatusBadRequest})
	sdk.egress.record(types.PublicKey{1}, nil, 0, 1)
	sdk.egress.flushNow()
	if got := capture.count(); got != 1 {
		t.Fatalf("attempt count = %d, want 1", got)
	}
	if sdk.egress.hasPending() {
		t.Fatal("a rejected envelope must be dropped, not re-queued")
	}

	sdk.egress.record(types.PublicKey{2}, nil, 0, 2)
	sdk.egress.flushNow()
	bodies := capture.bodies()
	if len(bodies) != 2 {
		t.Fatalf("the next batch was blocked: %d attempt(s)", len(bodies))
	}
	first := verifyEgressEnvelope(t, sdk.AppKey(), bodies[0])
	second := verifyEgressEnvelope(t, sdk.AppKey(), bodies[1])
	if first["batch_id"] == second["batch_id"] {
		t.Fatal("the second batch reused the rejected batch id")
	}
}

// TestEgressOverflowDropsOldest verifies the bounded queue drops the oldest
// event and never blocks.
func TestEgressOverflowDropsOldest(t *testing.T) {
	reporter := newEgressReporter(egressConfig{
		url:      "http://egress.test/api/v1/usage/egress",
		interval: time.Hour,
		batchMax: 500,
	}, types.GeneratePrivateKey(), zap.NewNop())

	for i := 0; i <= egressQueueCap; i++ {
		reporter.record(types.PublicKey{byte(i)}, nil, i, 1)
	}

	queued := reporter.snapshotQueue()
	if len(queued) != egressQueueCap {
		t.Fatalf("queue length = %d, want %d", len(queued), egressQueueCap)
	}
	if got := reporter.droppedCount(); got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
	if queued[0].shardIndex != 1 {
		t.Fatalf("front shard index = %d, want 1 (oldest dropped)", queued[0].shardIndex)
	}
	if last := queued[len(queued)-1]; last.shardIndex != egressQueueCap {
		t.Fatalf("back shard index = %d, want %d", last.shardIndex, egressQueueCap)
	}
}

// TestEgressBatchMaxClampedToServerLimit verifies WithEgressBatchMax clamps
// the configured batch size to the server's 1000-event limit.
func TestEgressBatchMaxClampedToServerLimit(t *testing.T) {
	sdk, _ := newEgressTestSDK(t, WithEgressBatchMax(5000))
	defer sdk.Close()

	if sdk.egressCfg.batchMax != egressBatchMaxEvents {
		t.Fatalf("configured batchMax = %d, want %d (clamped to the server limit)",
			sdk.egressCfg.batchMax, egressBatchMaxEvents)
	}
	if sdk.egress.batchMax != egressBatchMaxEvents {
		t.Fatalf("reporter batchMax = %d, want %d (clamped to the server limit)",
			sdk.egress.batchMax, egressBatchMaxEvents)
	}
}

// TestEgressBatchByteCap verifies a byte-heavy queue yields an envelope with
// at least one event whose cumulative bytes stay within the 512 MiB client
// obligation, satisfying the server's validate_batch bounds.
func TestEgressBatchByteCap(t *testing.T) {
	sdk, capture := newEgressTestSDK(t,
		WithEgressInterval(time.Hour),
		WithEgressBatchMax(5000)) // clamped to the 1000-event server limit
	defer sdk.Close()

	const eventBytes = egressBatchMaxBytes / 4 // 128 MiB
	for i := 0; i < 6; i++ {
		sdk.egress.record(types.PublicKey{byte(i)}, nil, i, eventBytes)
	}
	sdk.egress.flushNow()

	bodies := capture.bodies()
	if len(bodies) != 1 {
		t.Fatalf("flushNow sent %d envelopes, want 1", len(bodies))
	}
	value := verifyEgressEnvelope(t, sdk.AppKey(), bodies[0])
	events, ok := value["events"].([]any)
	if !ok || len(events) == 0 {
		t.Fatalf("events = %v, want at least one event", value["events"])
	}
	if len(events) > egressBatchMaxEvents {
		t.Fatalf("envelope has %d events, above the %d-event server limit",
			len(events), egressBatchMaxEvents)
	}
	if len(events) != 4 {
		t.Fatalf("envelope has %d events, want 4 (512 MiB / 128 MiB)", len(events))
	}
	var total int64
	for _, event := range events {
		bytes, err := event.(map[string]any)["bytes"].(json.Number).Int64()
		if err != nil {
			t.Fatalf("event bytes is not an integer: %v", err)
		}
		total += bytes
	}
	if total > egressBatchMaxBytes {
		t.Fatalf("cumulative event bytes = %d, above the client cap %d", total, egressBatchMaxBytes)
	}
	if total != egressBatchMaxBytes {
		t.Fatalf("cumulative event bytes = %d, want %d", total, egressBatchMaxBytes)
	}
	totals, ok := value["totals"].(map[string]any)
	if !ok || totals["bytes"] != json.Number(strconv.Itoa(egressBatchMaxBytes)) {
		t.Fatalf("totals = %v, want bytes %d", value["totals"], egressBatchMaxBytes)
	}
}

// TestEgressSpoolRoundTrip verifies a failed send is spooled and the spool is
// drained before newly queued events.
func TestEgressSpoolRoundTrip(t *testing.T) {
	spoolPath := filepath.Join(t.TempDir(), "egress.spool")
	sdk, capture := newEgressTestSDK(t,
		WithEgressInterval(time.Hour),
		WithEgressBatchMax(500),
		WithEgressSpoolPath(spoolPath))
	defer sdk.Close()

	capture.failNext(errors.New("offline"))
	sdk.egress.record(types.PublicKey{1}, nil, 0, 4096)
	sdk.egress.flushNow()
	bodies := capture.bodies()
	if len(bodies) != 1 {
		t.Fatalf("first attempt count = %d, want 1", len(bodies))
	}
	if sdk.egress.hasPending() {
		t.Fatal("a spooled envelope must not stay in memory")
	}

	spooled, err := os.ReadFile(spoolPath)
	if err != nil {
		t.Fatalf("failed to read spool: %v", err)
	}
	if !bytes.HasSuffix(spooled, []byte("\n")) {
		t.Fatal("spool is JSON lines")
	}
	lines := bytes.Split(bytes.TrimSuffix(spooled, []byte("\n")), []byte("\n"))
	if len(lines) != 1 || !bytes.Equal(lines[0], bodies[0]) {
		t.Fatalf("spooled line does not match the failed envelope:\n%q\n%q", lines, bodies[0])
	}

	// A new event arrives while the old batch is spooled; the spool drains
	// first, then a new envelope is built for the new event.
	sdk.egress.record(types.PublicKey{2}, nil, 0, 1)
	sdk.egress.flushNow()
	bodies = capture.bodies()
	if len(bodies) != 2 {
		t.Fatalf("spool drain attempts = %d, want 2", len(bodies))
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("the spooled envelope must be retried byte-for-byte")
	}

	sdk.egress.flushNow()
	bodies = capture.bodies()
	if len(bodies) != 3 {
		t.Fatalf("new batch attempts = %d, want 3", len(bodies))
	}
	if bytes.Equal(bodies[1], bodies[2]) {
		t.Fatal("the new event must form a new envelope")
	}
	drained, err := os.ReadFile(spoolPath)
	if err != nil {
		t.Fatalf("failed to read spool: %v", err)
	}
	if len(drained) != 0 {
		t.Fatalf("a drained spool must be empty, got %q", drained)
	}
}

// TestEgressSpoolBoundedDropsOldest verifies the spool stays under its 8 MiB
// bound by dropping the oldest envelopes, keeping the newest lineage.
func TestEgressSpoolBoundedDropsOldest(t *testing.T) {
	spoolPath := filepath.Join(t.TempDir(), "egress.spool")
	reporter := newEgressReporter(egressConfig{
		url:       "http://egress.test/api/v1/usage/egress",
		interval:  time.Hour,
		batchMax:  500,
		spoolPath: spoolPath,
	}, types.GeneratePrivateKey(), zap.NewNop())

	const envelopeSize = 1 << 20 // 1 MiB
	var envelopes [][]byte
	for i := 0; i < 9; i++ {
		envelope := bytes.Repeat([]byte{byte('a' + i)}, envelopeSize)
		if err := reporter.spoolAppend(envelope); err != nil {
			t.Fatalf("spoolAppend %d failed: %v", i, err)
		}
		envelopes = append(envelopes, envelope)
	}

	spooled, err := os.ReadFile(spoolPath)
	if err != nil {
		t.Fatalf("failed to read spool: %v", err)
	}
	lines := bytes.Split(bytes.TrimSuffix(spooled, []byte("\n")), []byte("\n"))
	if len(lines) >= len(envelopes) {
		t.Fatalf("spool kept all %d envelopes; the %d-byte bound did not drop the oldest", len(lines), egressSpoolMaxBytes)
	}
	total := 0
	for _, line := range lines {
		total += len(line) + 1
	}
	if total > egressSpoolMaxBytes {
		t.Fatalf("spool holds %d bytes (with newlines), above the %d-byte bound", total, egressSpoolMaxBytes)
	}
	want := envelopes[len(envelopes)-len(lines):]
	for i, line := range lines {
		if !bytes.Equal(line, want[i]) {
			t.Fatalf("spool line %d starts with %q, want the newest lineage %q", i, line[0], want[i][0])
		}
	}
}

// TestEgressSpoolRemovalFailureIsPaced verifies that when a delivered or
// 4xx-rejected envelope cannot be removed from the spool (disk failure), it
// stays recorded and the reporter arms the normal retry backoff instead of
// hot-looping: the flusher's next wait is positive and an immediate flusher
// pass does not re-post the same line. Once the disk recovers, the envelope
// drains normally.
//
// The failure is injected through the config's spool-writer seam because
// chmod cannot fail writes for root, and the test process may run as root.
func TestEgressSpoolRemovalFailureIsPaced(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reject bool
	}{
		{name: "delivered"},
		{name: "rejected-400", reject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spoolPath := filepath.Join(t.TempDir(), "egress.spool")
			capture := &egressCapture{}
			if tc.reject {
				capture.failNext(&egressSendError{status: http.StatusBadRequest})
				capture.failNext(&egressSendError{status: http.StatusBadRequest})
			}

			var failWrites bool
			var writes int
			reporter := newEgressReporter(egressConfig{
				url:       "http://egress.test/api/v1/usage/egress",
				interval:  time.Hour,
				batchMax:  500,
				spoolPath: spoolPath,
				post:      capture.post,
				writeSpoolFile: func(path string, data []byte) error {
					writes++
					if failWrites {
						return errors.New("injected spool write failure")
					}
					return os.WriteFile(path, data, 0o600)
				},
			}, types.GeneratePrivateKey(), zap.NewNop())

			envelope := []byte(`{"batch_id":"0123456789abcdef0123456789abcdef"}`)
			if err := reporter.spoolAppend(envelope); err != nil {
				t.Fatalf("failed to seed spool: %v", err)
			}

			// The seed append succeeds; the removal rewrite fails.
			failWrites = true
			reporter.send(envelope, egressSourceSpool)
			if got := capture.count(); got != 1 {
				t.Fatalf("post attempts = %d, want 1", got)
			}
			if writes != 2 {
				t.Fatalf("spool writes = %d, want 2 (seed + failed removal attempt)", writes)
			}
			if at := reporter.retryDeadline(); at.IsZero() || !at.After(time.Now()) {
				t.Fatalf("retry deadline = %v, want a future deadline after failed removal", at)
			}

			// An immediate flusher pass must honor the deadline and leave the
			// recorded envelope alone; a paced wait, not zero, prevents the
			// hot re-send loop.
			reporter.flushOnce(false)
			if got := capture.count(); got != 1 {
				t.Fatalf("the flusher re-sent during backoff: %d attempt(s)", got)
			}
			if wait := reporter.nextWait(time.Now()); wait < egressRetryBase/2 {
				t.Fatalf("next flusher wait = %v, want backoff-scale pacing", wait)
			}
			spooled, err := os.ReadFile(spoolPath)
			if err != nil {
				t.Fatalf("failed to read spool: %v", err)
			}
			if lines := bytes.Split(bytes.TrimSuffix(spooled, []byte("\n")), []byte("\n")); len(lines) != 1 || !bytes.Equal(lines[0], envelope) {
				t.Fatalf("spool = %q, want the unremoved envelope", spooled)
			}

			// Simulate the disk recovering and the deadline elapsing (rewind
			// it rather than sleeping through the whole backoff).
			failWrites = false
			reporter.mu.Lock()
			reporter.retryAt = time.Now().Add(-time.Millisecond)
			reporter.mu.Unlock()

			reporter.flushOnce(false)
			if got := capture.count(); got != 2 {
				t.Fatalf("post attempts after recovery = %d, want 2", got)
			}
			if writes != 3 {
				t.Fatalf("spool writes = %d, want 3 (recovery removal)", writes)
			}
			if at := reporter.retryDeadline(); !at.IsZero() {
				t.Fatalf("retry deadline = %v after successful removal, want cleared", at)
			}
			if spooled, err := os.ReadFile(spoolPath); err != nil {
				t.Fatalf("failed to read spool: %v", err)
			} else if len(spooled) != 0 {
				t.Fatalf("spool = %q after successful removal, want empty", spooled)
			}
		})
	}
}

// TestEgressCloseStopsFlusher verifies Close stops the reporter goroutine
// cleanly through the SDK's thread group.
func TestEgressCloseStopsFlusher(t *testing.T) {
	sdk, _ := newEgressTestSDK(t, WithEgressInterval(time.Hour), WithEgressBatchMax(500))
	sdk.egress.record(types.PublicKey{1}, nil, 0, 1)

	if err := sdk.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	select {
	case <-sdk.egress.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the egress flusher did not stop on Close")
	}
}

// TestEgressHTTPTransport exercises the default transport over loopback: a
// transient failure (503 or 429) is retried with the identical envelope, and
// the following 200 delivers it.
func TestEgressHTTPTransport(t *testing.T) {
	for _, retryStatus := range []int{http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		t.Run(http.StatusText(retryStatus), func(t *testing.T) {
			var mu sync.Mutex
			var requests [][]byte
			statuses := []int{retryStatus, http.StatusOK}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("failed to read request body: %v", err)
				}
				if r.Method != http.MethodPost || r.URL.Path != "/api/v1/usage/egress" {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if ct := r.Header.Get("Content-Type"); ct != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", ct)
				}
				mu.Lock()
				index := len(requests)
				requests = append(requests, body)
				mu.Unlock()
				w.WriteHeader(statuses[min(index, len(statuses)-1)])
			}))
			defer srv.Close()

			sdk := newMockEgressSDK(t,
				WithEgressURL(srv.URL+"/api/v1/usage/egress"),
				WithEgressInterval(time.Hour),
				WithEgressBatchMax(500))
			defer sdk.Close()

			sdk.egress.record(types.PublicKey{9}, nil, 7, 12345)
			sdk.egress.flushNow()
			if !sdk.egress.hasPending() {
				t.Fatalf("a %d must be retried, not dropped", retryStatus)
			}

			sdk.egress.flushNow()
			if sdk.egress.hasPending() {
				t.Fatal("the retried envelope must succeed on 200")
			}

			mu.Lock()
			defer mu.Unlock()
			if len(requests) != 2 {
				t.Fatalf("server received %d requests, want 2", len(requests))
			}
			if !bytes.Equal(requests[0], requests[1]) {
				t.Fatal("the retry must send the identical envelope")
			}
			value := verifyEgressEnvelope(t, sdk.AppKey(), requests[1])
			if value["seq"] != json.Number("1") {
				t.Fatalf("seq = %v, want 1", value["seq"])
			}
		})
	}
}

// TestEgressStatusClassification pins the retry policy: 429 and 5xx are
// transient, other statuses are rejections that drop the batch.
func TestEgressStatusClassification(t *testing.T) {
	cases := map[int]bool{
		http.StatusTooManyRequests:     true,
		http.StatusInternalServerError: true,
		http.StatusBadGateway:          true,
		http.StatusServiceUnavailable:  true,
		http.StatusBadRequest:          false,
		http.StatusNotFound:            false,
		http.StatusUnprocessableEntity: false,
	}
	for status, want := range cases {
		if got := (&egressSendError{status: status}).retryable(); got != want {
			t.Errorf("status %d retryable = %v, want %v", status, got, want)
		}
	}
}

// TestEgressDisabledWithoutURL verifies reporting is opt-in and record is a
// no-op without a reporter.
func TestEgressDisabledWithoutURL(t *testing.T) {
	sdk, _ := newTestSDK(t, 1, zaptest.NewLogger(t))
	defer sdk.Close()

	if sdk.egress != nil {
		t.Fatal("an egress reporter must not exist without a URL")
	}
	if sdk.egressCfg.interval != defaultEgressInterval || sdk.egressCfg.batchMax != defaultEgressBatchMax {
		t.Fatalf("unexpected egress defaults: %+v", sdk.egressCfg)
	}

	// A nil reporter accepts records so read paths never need a guard.
	var nilReporter *egressReporter
	nilReporter.record(types.PublicKey{}, nil, 0, 1)
}

// TestEgressOptionDefaults verifies the option surface and its defaults.
func TestEgressOptionDefaults(t *testing.T) {
	sdk, _ := newEgressTestSDK(t)
	defer sdk.Close()
	if sdk.egress.interval != defaultEgressInterval || sdk.egress.batchMax != defaultEgressBatchMax || sdk.egress.spoolPath != "" {
		t.Fatalf("unexpected defaults: interval=%v batchMax=%d spool=%q",
			sdk.egress.interval, sdk.egress.batchMax, sdk.egress.spoolPath)
	}

	spool := filepath.Join(t.TempDir(), "spool")
	sdk2, _ := newEgressTestSDK(t, WithEgressInterval(time.Minute), WithEgressBatchMax(7), WithEgressSpoolPath(spool))
	defer sdk2.Close()
	if sdk2.egress.interval != time.Minute || sdk2.egress.batchMax != 7 || sdk2.egress.spoolPath != spool {
		t.Fatalf("options not applied: interval=%v batchMax=%d spool=%q",
			sdk2.egress.interval, sdk2.egress.batchMax, sdk2.egress.spoolPath)
	}
}
