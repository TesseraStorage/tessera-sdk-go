package siastorage

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/threadgroup"
	"go.uber.org/zap"
	"lukechampine.com/frand"
)

// Egress reporting (P3b): the SDK reports successfully served shard reads to
// an indexer endpoint as signed JSON batches. The wire format is frozen in
// docs/egress-wire-golden.md and canonicalizes byte-for-byte across Python,
// Rust and Go:
//
//   - the envelope is a JSON object, UTF-8, compact (`,`/`:` separators),
//     keys sorted recursively, no whitespace. Values are lowercase hex
//     strings, integers and null.
//   - the signed preimage is b"tessera-egress-v1:" followed by the canonical
//     bytes of the envelope without its signature member.
//   - identity and signature encodings are ed25519:<lowercase hex>.
//
// Reporting is off unless WithEgressURL is set. Recording an event is a short
// in-memory append (bounded at egressQueueCap, oldest dropped) and can never
// block or fail a read; the flusher is fire-and-forget and every send error
// is swallowed (logged) and either retried or dropped.
const (
	// egressPreimagePrefix domain-separates the signed preimage.
	egressPreimagePrefix = "tessera-egress-v1:"

	// egressQueueCap bounds the in-memory event queue. The oldest events are
	// dropped beyond it.
	egressQueueCap = 4096

	// defaultEgressInterval and defaultEgressBatchMax are the flush cadence
	// defaults: at most one batch per interval, or immediately at the
	// threshold.
	defaultEgressInterval = 30 * time.Second
	defaultEgressBatchMax = 500

	// egressBatchMaxEvents and egressBatchMaxBytes are the client obligations
	// from the wire contract: at most 1000 events and 512 MiB of cumulative
	// event bytes per envelope (the server rejects batches above 1000 events
	// or 1 GiB). WithEgressBatchMax clamps to egressBatchMaxEvents and
	// takeEvents stops at egressBatchMaxBytes.
	egressBatchMaxEvents = 1000
	egressBatchMaxBytes  = 512 << 20 // 512 MiB

	// egressRetryBase and egressRetryMax bound the exponential retry backoff
	// (1s -> 60s cap).
	egressRetryBase = time.Second
	egressRetryMax  = 60 * time.Second

	// egressSpoolMaxBytes bounds the on-disk spool; the oldest envelopes are
	// dropped beyond it.
	egressSpoolMaxBytes = 8 << 20 // 8 MiB

	// egressHTTPTimeout bounds one POST to the egress endpoint.
	egressHTTPTimeout = 15 * time.Second
)

type (
	// egressConfig collects the egress options until initEgress builds the
	// reporter.
	egressConfig struct {
		url       string
		interval  time.Duration
		batchMax  int
		spoolPath string

		// post overrides the reporter's transport; tests install an offline
		// capture here (see withEgressCapture).
		post func(ctx context.Context, envelope []byte) error

		// writeSpoolFile overrides the spool writer; tests install a
		// filesystem error injector here.
		writeSpoolFile func(path string, data []byte) error
	}

	// egressEvent is one successfully served shard read.
	egressEvent struct {
		hostKey    types.PublicKey
		slabID     *types.Hash256
		shardIndex int
		bytes      int
		ts         int64 // Unix milliseconds
	}

	// egressSendError is returned by the default transport for a non-2xx
	// reply. 429 and 5xx are retryable; other statuses drop the batch.
	egressSendError struct {
		status int
	}

	// egressSource names where a posted envelope came from.
	egressSource int

	// egressReporter queues served-shard events and POSTs signed batches.
	// All state transitions are safe for concurrent record/flush calls.
	egressReporter struct {
		url       string
		interval  time.Duration
		batchMax  int
		spoolPath string
		appKey    types.PrivateKey
		log       *zap.Logger

		client *http.Client
		post   func(ctx context.Context, envelope []byte) error

		// writeSpoolFile overrides spool writes when set (test seam).
		writeSpoolFile func(path string, data []byte) error

		// ctx cancels in-flight sends when the SDK closes.
		ctx context.Context

		mu        sync.Mutex
		queue     []egressEvent
		dropped   uint64
		lastFlush time.Time
		pending   []byte // signed envelope awaiting retry, in memory
		retryAt   time.Time
		failures  int

		spoolMu sync.Mutex

		// flushMu serializes flush attempts between the background flusher
		// and flushNow.
		flushMu sync.Mutex
		wake    chan struct{}
		done    chan struct{}
		seq     atomic.Uint64
	}
)

const (
	egressSourceMemory egressSource = iota
	egressSourceSpool
)

func (e *egressSendError) Error() string {
	return fmt.Sprintf("egress endpoint returned HTTP %d", e.status)
}

// retryable reports whether the response warrants retrying the identical
// envelope: 429 and 5xx are transient, other statuses are rejections.
func (e *egressSendError) retryable() bool {
	return e.status == http.StatusTooManyRequests || e.status >= 500
}

// defaultEgressConfig returns the documented defaults.
func defaultEgressConfig() egressConfig {
	return egressConfig{
		interval: defaultEgressInterval,
		batchMax: defaultEgressBatchMax,
	}
}

// newEgressReporter builds a reporter. Non-positive interval or batchMax
// values fall back to the defaults; batchMax above the server's 1000-event
// limit is clamped to it.
func newEgressReporter(cfg egressConfig, appKey types.PrivateKey, log *zap.Logger) *egressReporter {
	if cfg.interval <= 0 {
		cfg.interval = defaultEgressInterval
	}
	if cfg.batchMax < 1 {
		cfg.batchMax = defaultEgressBatchMax
	} else if cfg.batchMax > egressBatchMaxEvents {
		cfg.batchMax = egressBatchMaxEvents
	}
	if log == nil {
		log = zap.NewNop()
	}
	r := &egressReporter{
		url:       cfg.url,
		interval:  cfg.interval,
		batchMax:  cfg.batchMax,
		spoolPath: cfg.spoolPath,
		appKey:    appKey,
		log:       log,
		client:    &http.Client{Timeout: egressHTTPTimeout},
		wake:      make(chan struct{}, 1),
		done:      make(chan struct{}),
		lastFlush: time.Now(),
	}
	if cfg.post != nil {
		r.post = cfg.post
	} else {
		r.post = r.postHTTP
	}
	r.writeSpoolFile = cfg.writeSpoolFile
	return r
}

// initEgress starts the egress reporter if an egress URL was configured. It
// must be called after every [Option] has been applied, because the options
// configure the reporter. Without a URL, s.egress stays nil and
// [egressReporter.record] becomes a no-op.
func (s *SDK) initEgress() {
	if s.egressCfg.url == "" {
		return
	}
	s.egress = newEgressReporter(s.egressCfg, s.appKey, s.log.Named("egress"))
	s.egress.start(s.tg)
}

// start spawns the flusher as a thread of tg, so stopping the thread group
// (SDK.Close) stops the reporter.
func (r *egressReporter) start(tg *threadgroup.ThreadGroup) {
	ctx, cancel, err := tg.AddContext(context.Background())
	if err != nil {
		// The thread group is already stopped; leave the reporter without a
		// flusher. record remains a no-op.
		return
	}
	r.ctx = ctx
	go func() {
		defer cancel()
		r.run(ctx)
	}()
}

// record appends one successfully served shard read to the bounded queue and
// wakes the flusher when the batch threshold is reached. It never blocks on
// the network and accepts a nil receiver, so a read path can record
// unconditionally even when reporting is disabled.
func (r *egressReporter) record(hostKey types.PublicKey, slabID *types.Hash256, shardIndex int, bytes int) {
	if r == nil {
		return
	}
	var slab *types.Hash256
	if slabID != nil {
		copied := *slabID
		slab = &copied
	}
	event := egressEvent{
		hostKey:    hostKey,
		slabID:     slab,
		shardIndex: shardIndex,
		bytes:      bytes,
		ts:         time.Now().UnixMilli(),
	}

	r.mu.Lock()
	if len(r.queue) >= egressQueueCap {
		copy(r.queue, r.queue[1:])
		r.queue[len(r.queue)-1] = event
		r.dropped++
	} else {
		r.queue = append(r.queue, event)
	}
	threshold := len(r.queue) >= r.batchMax
	r.mu.Unlock()

	if threshold {
		r.signal()
	}
}

// flushNow forces one flush attempt, bypassing the interval and the retry
// backoff. It is a test seam.
func (r *egressReporter) flushNow() {
	if r == nil {
		return
	}
	r.flushOnce(true)
}

// signal wakes the flusher without blocking.
func (r *egressReporter) signal() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// run is the flusher. It flushes when the interval elapses or the queue
// reaches the batch threshold, retries pending work at the backoff deadline,
// and exits when the SDK's thread group stops.
func (r *egressReporter) run(ctx context.Context) {
	defer close(r.done)
	timer := time.NewTimer(r.interval)
	defer timer.Stop()
	for {
		r.flushOnce(false)
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(r.nextWait(time.Now()))

		select {
		case <-ctx.Done():
			return
		case <-r.wake:
		case <-timer.C:
		}
	}
}

// nextWait returns how long the flusher should wait before its next check.
func (r *egressReporter) nextWait(now time.Time) time.Duration {
	if at := r.retryDeadline(); !at.IsZero() && now.Before(at) {
		return time.Until(at)
	}
	if r.hasPending() || r.hasSpoolWork() {
		return 0
	}
	if n := r.queueLen(); n >= r.batchMax {
		return 0
	} else if n > 0 {
		return max(r.interval-now.Sub(r.lastFlushTime()), 0)
	}
	return r.interval
}

// flushOnce attempts at most one delivery: the in-memory pending envelope
// first (a retried batch keeps its signed bytes), then the oldest spooled
// envelope, then a new batch built from the queue. A non-forced attempt is
// gated by the retry backoff, the batch threshold and the flush interval.
func (r *egressReporter) flushOnce(force bool) {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()

	now := time.Now()
	if !force {
		if at := r.retryDeadline(); !at.IsZero() && now.Before(at) {
			return
		}
	}

	if envelope := r.takePending(); envelope != nil {
		r.send(envelope, egressSourceMemory)
		return
	}
	if envelope := r.spoolFirst(); envelope != nil {
		r.send(envelope, egressSourceSpool)
		return
	}

	if !force {
		n := r.queueLen()
		if n == 0 || (n < r.batchMax && now.Sub(r.lastFlushTime()) < r.interval) {
			return
		}
	}

	events := r.takeEvents(r.batchMax)
	if len(events) == 0 {
		return
	}
	r.setLastFlush(now)

	_, envelope, err := buildEgressEnvelope(r.appKey, randomEgressBatchID(), r.seq.Add(1), events)
	if err != nil {
		r.log.Warn("egress reporter: failed to build envelope", zap.Error(err))
		return
	}
	r.send(envelope, egressSourceMemory)
}

// send posts one envelope and applies the retry/drop policy. It never
// propagates an error: a retryable failure keeps the identical envelope (in
// the spool when one is configured, otherwise in memory) for a later attempt,
// and a rejected batch is dropped with a log line so it cannot poison the
// queue. An envelope whose spool line cannot be removed after delivery or
// rejection stays recorded and is retried under the normal backoff.
func (r *egressReporter) send(envelope []byte, source egressSource) {
	defer r.signal()

	err := r.post(r.postContext(), envelope)
	if err == nil {
		r.settle(source)
		return
	}

	var rejected *egressSendError
	if errors.As(err, &rejected) && !rejected.retryable() {
		r.log.Warn("egress reporter: batch rejected, dropping", zap.Int("status", rejected.status))
		r.settle(source)
		return
	}

	r.log.Warn("egress reporter: failed to report batch, will retry", zap.Error(err))
	r.scheduleRetry()
	if source == egressSourceSpool {
		// Already spooled: it stays in place for the next attempt.
		return
	}
	if r.spoolPath != "" {
		if serr := r.spoolAppend(envelope); serr == nil {
			return // durably spooled; no in-memory retry needed
		} else {
			r.log.Warn("egress reporter: failed to spool envelope, falling back to memory", zap.Error(serr))
		}
	}
	r.setPending(envelope)
}

// settle finishes a delivered or rejected envelope. A spooled envelope must
// actually leave the spool before the reporter clears its retry state, because
// [egressReporter.nextWait] treats any spool work as immediately runnable.
// When the removal write fails, the envelope remains recorded and a retry is
// scheduled, pacing the next attempt through the normal backoff instead of
// re-reading and re-posting the same line in a hot loop.
func (r *egressReporter) settle(source egressSource) {
	if source == egressSourceSpool {
		if err := r.spoolRemoveFirst(); err != nil {
			r.scheduleRetry()
			return
		}
	}
	r.clearRetry()
}

// postContext returns the reporter's lifetime context, which is cancelled
// when the SDK closes.
func (r *egressReporter) postContext() context.Context {
	if r.ctx != nil {
		return r.ctx
	}
	return context.Background()
}

// postHTTP is the default transport: POST the canonical envelope to the
// configured URL with the client's timeout.
func (r *egressReporter) postHTTP(ctx context.Context, envelope []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(envelope))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &egressSendError{status: resp.StatusCode}
	}
	return nil
}

func (r *egressReporter) queueLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.queue)
}

// takeEvents removes and returns up to max of the oldest queued events,
// stopping before an event that would push the cumulative bytes past
// egressBatchMaxBytes (the 512 MiB client obligation). It always takes at
// least one event when the queue is non-empty: the server rejects empty
// batches.
func (r *egressReporter) takeEvents(max int) []egressEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := min(max, len(r.queue))
	if n == 0 {
		return nil
	}
	taken := 0
	var total int64
	for taken < n {
		eventBytes := int64(r.queue[taken].bytes)
		if taken > 0 && total+eventBytes > egressBatchMaxBytes {
			break
		}
		total += eventBytes
		taken++
	}
	events := make([]egressEvent, taken)
	copy(events, r.queue[:taken])
	r.queue = r.queue[taken:]
	if len(r.queue) == 0 {
		r.queue = nil
	}
	return events
}

func (r *egressReporter) lastFlushTime() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastFlush
}

func (r *egressReporter) setLastFlush(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastFlush = t
}

func (r *egressReporter) takePending() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	envelope := r.pending
	r.pending = nil
	return envelope
}

func (r *egressReporter) setPending(envelope []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending = envelope
}

func (r *egressReporter) hasPending() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending != nil
}

func (r *egressReporter) retryDeadline() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.retryAt
}

// scheduleRetry sets the next retry time with exponential backoff (1s -> 60s
// cap) and counts the failure.
func (r *egressReporter) scheduleRetry() {
	r.mu.Lock()
	defer r.mu.Unlock()
	backoff := min(egressRetryBase<<min(r.failures, 6), egressRetryMax)
	r.failures++
	r.retryAt = time.Now().Add(backoff)
}

func (r *egressReporter) clearRetry() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failures = 0
	r.retryAt = time.Time{}
}

// droppedCount returns the number of events dropped by the bounded queue.
// Test-only.
func (r *egressReporter) droppedCount() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dropped
}

// snapshotQueue returns a copy of the queued events. Test-only.
func (r *egressReporter) snapshotQueue() []egressEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]egressEvent, len(r.queue))
	copy(out, r.queue)
	return out
}

// hasSpoolWork reports whether the spool file holds at least one envelope.
func (r *egressReporter) hasSpoolWork() bool {
	if r.spoolPath == "" {
		return false
	}
	r.spoolMu.Lock()
	defer r.spoolMu.Unlock()
	lines, err := r.readSpool()
	return err == nil && len(lines) > 0
}

// spoolFirst returns the oldest spooled envelope, or nil when the spool is
// empty or unreadable.
func (r *egressReporter) spoolFirst() []byte {
	if r.spoolPath == "" {
		return nil
	}
	r.spoolMu.Lock()
	defer r.spoolMu.Unlock()
	lines, err := r.readSpool()
	if err != nil {
		r.log.Warn("egress reporter: failed to read spool", zap.String("path", r.spoolPath), zap.Error(err))
		return nil
	}
	if len(lines) == 0 {
		return nil
	}
	return lines[0]
}

// spoolAppend appends an envelope as a JSON line, dropping the oldest lines
// beyond egressSpoolMaxBytes.
func (r *egressReporter) spoolAppend(envelope []byte) error {
	r.spoolMu.Lock()
	defer r.spoolMu.Unlock()
	lines, err := r.readSpool()
	if err != nil {
		return err
	}
	lines = append(lines, bytes.Clone(envelope))

	total := 0
	for _, line := range lines {
		total += len(line) + 1 // count the newline
	}
	for total > egressSpoolMaxBytes && len(lines) > 1 {
		total -= len(lines[0]) + 1
		lines = lines[1:]
	}
	return r.writeSpool(lines)
}

// spoolRemoveFirst drops the oldest spooled envelope after it was delivered
// or rejected. It returns an error when the spool cannot be rewritten, in
// which case the envelope is still recorded on disk and the caller must keep
// it scheduled for a paced retry.
func (r *egressReporter) spoolRemoveFirst() error {
	if r.spoolPath == "" {
		return nil
	}
	r.spoolMu.Lock()
	defer r.spoolMu.Unlock()
	lines, err := r.readSpool()
	if err != nil {
		r.log.Warn("egress reporter: failed to read spool", zap.String("path", r.spoolPath), zap.Error(err))
		return err
	}
	if len(lines) == 0 {
		return nil
	}
	if err := r.writeSpool(lines[1:]); err != nil {
		r.log.Warn("egress reporter: failed to write spool", zap.String("path", r.spoolPath), zap.Error(err))
		return err
	}
	return nil
}

// readSpool returns one non-empty line per spooled envelope. A missing file
// is an empty spool.
func (r *egressReporter) readSpool() ([][]byte, error) {
	data, err := os.ReadFile(r.spoolPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	var lines [][]byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// writeSpool rewrites the spool as JSON lines. The writer is overridable via
// the config's test seam so tests can inject filesystem failures.
func (r *egressReporter) writeSpool(lines [][]byte) error {
	var buf bytes.Buffer
	for _, line := range lines {
		buf.Write(line)
		buf.WriteByte('\n')
	}
	if r.writeSpoolFile != nil {
		return r.writeSpoolFile(r.spoolPath, buf.Bytes())
	}
	return os.WriteFile(r.spoolPath, buf.Bytes(), 0o600)
}

// buildEgressEnvelope builds the canonical body and the signed canonical
// envelope for the given events. Keys are serialized from sorted maps (never
// struct order), the encoder does not escape HTML, and its trailing newline
// is trimmed before hashing/signing. The signature is a raw stdlib Ed25519
// signature over "tessera-egress-v1:" + canonical body; core/types has no
// message-signing helper (only SignHash), so the raw call is mandatory.
func buildEgressEnvelope(appKey types.PrivateKey, batchID [16]byte, seq uint64, events []egressEvent) (body, envelope []byte, err error) {
	if len(appKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("invalid egress app key length: %d", len(appKey))
	}

	values := make([]any, len(events))
	var totalBytes int64
	for i, event := range events {
		values[i] = egressEventValue(event)
		totalBytes += int64(event.bytes)
	}
	obj := map[string]any{
		"batch_id": hex.EncodeToString(batchID[:]),
		"events":   values,
		"identity": appKey.PublicKey().String(),
		"seq":      seq,
		"totals":   map[string]any{"bytes": totalBytes, "shards": len(events)},
	}

	if body, err = canonicalJSON(obj); err != nil {
		return nil, nil, err
	}
	preimage := make([]byte, 0, len(egressPreimagePrefix)+len(body))
	preimage = append(preimage, egressPreimagePrefix...)
	preimage = append(preimage, body...)
	signature := ed25519.Sign(ed25519.PrivateKey(appKey), preimage)

	obj["signature"] = "ed25519:" + hex.EncodeToString(signature)
	if envelope, err = canonicalJSON(obj); err != nil {
		return nil, nil, err
	}
	return body, envelope, nil
}

// egressEventValue serializes one event with sorted keys.
func egressEventValue(event egressEvent) map[string]any {
	var slab any
	if event.slabID != nil {
		slab = event.slabID.String()
	}
	return map[string]any{
		"bytes":       event.bytes,
		"host_key":    event.hostKey.String(),
		"shard_index": event.shardIndex,
		"slab_id":     slab,
		"ts":          event.ts,
	}
}

// canonicalJSON serializes v as compact UTF-8 JSON with recursively sorted
// keys. encoding/json sorts map keys; SetEscapeHTML(false) keeps the bytes
// stable for the wire contract, and the encoder's trailing newline is trimmed
// before hashing/signing. The value domain is restricted to integers,
// lowercase hex strings and null, so no escaping divergence exists.
func canonicalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// randomEgressBatchID returns 16 random bytes.
func randomEgressBatchID() (id [16]byte) {
	frand.Read(id[:])
	return
}
