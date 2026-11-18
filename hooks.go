package siastorage

import (
	"io"
	"sync"
	"sync/atomic"
	"time"

	"go.sia.tech/core/types"
	"go.uber.org/zap"
)

// AgentHooks are optional callbacks that report the outcome of transfers to
// the caller, for example an agent that needs to record what it stored. Set
// them with [WithAgentHooks]. Every field is optional; a nil field is never
// called.
//
// Hooks are fire-and-forget. Each call runs in its own goroutine, so a slow
// hook does not delay the transfer, and the SDK does not wait for a hook to
// return. A panic inside a hook is recovered and logged; it never changes
// the result of the transfer. Calls to different hooks are not ordered with
// respect to each other or to the return of the method that triggered them.
type AgentHooks struct {
	// OnUploadComplete is called after [SDK.Upload] returns nil. The data
	// is stored on hosts but is not tracked by the indexer until
	// [SDK.PinObject] succeeds.
	OnUploadComplete func(UploadCompleteEvent)

	// OnDownloadComplete is called when a reader returned by [SDK.Download]
	// has delivered its last byte (Read returned io.EOF, or WriteTo
	// returned without an error). A reader that is closed early or fails
	// does not call it.
	OnDownloadComplete func(DownloadCompleteEvent)

	// OnWriteFailed is called when [SDK.Upload] or [SDK.PinObject] returns
	// an error. [WriteFailedEvent.Stage] tells whether any data was sent.
	OnWriteFailed func(WriteFailedEvent)
}

// An UploadCompleteEvent describes a successful [SDK.Upload] call.
type UploadCompleteEvent struct {
	// ObjectID is the object's ID after this call. Appending data to an
	// object changes its ID.
	ObjectID types.Hash256
	// Size is the object's size in bytes after this call.
	Size uint64
	// Slabs is the number of slabs in the object after this call.
	Slabs int
	// ShardsAcknowledged is the number of shard writes that hosts
	// acknowledged during this call.
	ShardsAcknowledged int
	// Elapsed is the time from the start of the call to its return.
	Elapsed time.Duration
}

// A DownloadCompleteEvent describes a download that delivered every
// requested byte.
type DownloadCompleteEvent struct {
	// ObjectID is the ID of the downloaded object.
	ObjectID types.Hash256
	// Bytes is the number of bytes the reader delivered.
	Bytes uint64
	// Elapsed is the time from the [SDK.Download] call to the last byte.
	Elapsed time.Duration
}

// A WriteFailureStage tells how far a failed write got.
type WriteFailureStage int

const (
	// WriteNotSent means [SDK.Upload] failed before any shard write to a
	// host started. No object data left the process.
	WriteNotSent WriteFailureStage = iota + 1

	// WriteSentNotRegistered means [SDK.Upload] failed after at least one
	// shard write to a host started. Some shard data may be stored on
	// hosts. Nothing was pinned, so no object exists on the indexer and the
	// stored shards are not referenced by any object. Retrying with a new
	// [Object] is safe.
	WriteSentNotRegistered

	// WritePinFailed means the data was uploaded but [SDK.PinObject]
	// failed, so the object was not saved on the indexer.
	// [WriteFailedEvent.SlabsPinned] reports how many slabs the indexer
	// had confirmed as pinned before the failure. Pinned slabs without an
	// object stay on the account until the object is pinned or
	// [SDK.PruneSlabs] removes them. Calling PinObject again with the same
	// object is safe.
	WritePinFailed
)

// String returns the stage name.
func (s WriteFailureStage) String() string {
	switch s {
	case WriteNotSent:
		return "not_sent"
	case WriteSentNotRegistered:
		return "sent_not_registered"
	case WritePinFailed:
		return "pin_failed"
	default:
		return "unknown"
	}
}

// A WriteFailedEvent describes a failed [SDK.Upload] or [SDK.PinObject]
// call.
type WriteFailedEvent struct {
	// Stage tells how far the write got.
	Stage WriteFailureStage
	// Err is the error the method returned.
	Err error
	// ObjectID is the ID of the object that failed to pin. It is set only
	// for [WritePinFailed]; an upload that did not finish has no stable ID.
	ObjectID types.Hash256
	// WriteAttemptsStarted is the number of shard writes to hosts that
	// started during the upload, including retries and racing attempts.
	// Zero for [WritePinFailed].
	WriteAttemptsStarted int
	// ShardsAcknowledged is the number of shard writes that hosts
	// acknowledged during the upload. Zero for [WritePinFailed].
	ShardsAcknowledged int
	// SlabsPinned is the number of slabs the indexer confirmed as pinned
	// before the failure. Set only for [WritePinFailed].
	SlabsPinned int
	// Elapsed is the time from the start of the call to its return.
	Elapsed time.Duration
}

// WithAgentHooks sets callbacks that report completed uploads and
// downloads and failed writes. See [AgentHooks]. Without this option the
// SDK behaves exactly as before.
func WithAgentHooks(h AgentHooks) Option {
	return func(s *SDK) {
		s.hooks = h
	}
}

// fireHook runs fn in its own goroutine and recovers a panic so a caller's
// hook can never fail or block a transfer.
func (s *SDK) fireHook(name string, fn func()) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.log.Warn("agent hook panicked; the transfer result is unaffected", zap.String("hook", name), zap.Any("panic", r))
			}
		}()
		fn()
	}()
}

// uploadCounters observes one Upload call for the agent hooks.
type uploadCounters struct {
	attempts atomic.Int64
	acks     atomic.Int64
}

// option wraps the caller's progress callback so the counters see every
// acknowledged shard and every write attempt. It is applied after the
// caller's options.
func (c *uploadCounters) option() UploadOption {
	return func(uo *uploadOption) {
		user := uo.onProgress
		uo.onProgress = func(p ShardProgress) {
			c.acks.Add(1)
			if user != nil {
				user(p)
			}
		}
		uo.onWriteAttempt = func() { c.attempts.Add(1) }
	}
}

// completionReader wraps a download reader and calls done once with the
// number of bytes delivered when the stream reaches its end.
type completionReader struct {
	rc   io.ReadCloser
	n    uint64
	once sync.Once
	done func(n uint64)
}

func (c *completionReader) finish() {
	c.once.Do(func() { c.done(c.n) })
}

func (c *completionReader) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	c.n += uint64(n)
	if err == io.EOF {
		c.finish()
	}
	return n, err
}

func (c *completionReader) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := c.rc.(io.WriterTo); ok {
		n, err := wt.WriteTo(w)
		c.n += uint64(n)
		if err == nil {
			c.finish()
		}
		return n, err
	}
	n, err := io.Copy(w, struct{ io.Reader }{c})
	return n, err
}

func (c *completionReader) Close() error {
	return c.rc.Close()
}
