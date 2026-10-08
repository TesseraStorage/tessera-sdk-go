package siastorage

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
	proto4 "go.sia.tech/core/rhp/v4"
	"go.sia.tech/core/types"
	"go.sia.tech/coreutils/rhp/v4"
	"go.sia.tech/coreutils/threadgroup"
	"go.sia.tech/indexd/api"
	"go.sia.tech/indexd/api/app"
	"go.sia.tech/indexd/client/v2"
	"go.sia.tech/indexd/hosts"
	"go.sia.tech/indexd/slabs"
	"go.uber.org/zap"
	"golang.org/x/crypto/chacha20"
)

// pinBatchSize is the maximum number of slabs sent to the indexer in a
// single PinSlabs request.
const pinBatchSize = 50

type (
	// A HostClient is an interface for interacting with hosts.
	//
	// EXPORTED (Tessera fork). The stock SDK keeps this unexported with no public setter, so an
	// integrator cannot observe the host transport. Two events that exist inside this interface
	// are unavailable anywhere else in the public API:
	//
	//	PickWrite     -- a host has been selected and a shard write is ABOUT TO START on it
	//	AddFailedRPC  -- a host's RPC FAILED
	//
	// WithUploadProgress cannot substitute for either: ShardProgress "reports the result of a
	// successfully completed shard upload" (sdk.go), fires once per shard, and names only the
	// winner. A host that was picked, failed, and was swapped out by pool.swap() leaves NO trace
	// in the public API at all -- so per-host failure attribution and any "write in flight"
	// indication are both impossible without this seam.
	HostClient interface {
		Prices(ctx context.Context, hostKey types.PublicKey) (prices proto4.HostPrices, err error)
		ReadSector(ctx context.Context, accountKey types.PrivateKey, hostKey types.PublicKey, root types.Hash256, w io.Writer, offset, length uint64) (rhp.RPCReadSectorResult, error)
		WriteSector(ctx context.Context, accountKey types.PrivateKey, hostKey types.PublicKey, data []byte) (rhp.RPCWriteSectorResult, error)

		AddFailedRPC(hostKey types.PublicKey)
		Prioritize(hosts []types.PublicKey) []types.PublicKey
		ReadEstimate(bytes uint64) time.Duration
		WriteEstimate(bytes uint64) time.Duration
		PickWrite(candidates []types.PublicKey) (host types.PublicKey, release func(), remaining []types.PublicKey, ok bool)
		TrackInflightRead(hostKey types.PublicKey) func()
		UploadQueue() (*client.HostQueue, error)
		Close() error
	}

	// hostClient is retained as an alias so every existing use inside the package -- including
	// connect.go's mockHost field and the test suite -- compiles unchanged. Renaming call sites
	// would turn an additive change into a sweeping one, which is exactly what makes a fork hard
	// to rebase and hard to propose upstream.
	hostClient = HostClient

	// An appClient is an interface for the application API of the indexer.
	appClient interface {
		Account(ctx context.Context, appKey types.PrivateKey) (resp app.AccountResponse, err error)

		Hosts(context.Context, types.PrivateKey, ...api.URLQueryParameterOption) ([]hosts.HostInfo, error)

		// ObjectHosts returns the current, post-repair set of hosts storing
		// the given object's shards -- indexd's `GET /objects/:key/hosts`.
		//
		// TESSERA FORK: backs
		// [SDK.Download]'s job-scoped, read-start-only host map. Product
		// law: downloads never call the write-path Hosts/GET /hosts.
		ObjectHosts(ctx context.Context, appKey types.PrivateKey, key types.Hash256) ([]hosts.HostInfo, error)

		CreateSharedObjectURL(ctx context.Context, appKey types.PrivateKey, objectID types.Hash256, encryptionKey []byte, validUntil time.Time) (string, error)
		SharedObject(ctx context.Context, sharedURL string) (slabs.SharedObject, []byte, error)

		ListObjects(ctx context.Context, appKey types.PrivateKey, cursor slabs.Cursor, limit int) ([]slabs.ObjectEvent, error)
		Object(ctx context.Context, appKey types.PrivateKey, key types.Hash256) (slabs.SealedObject, error)
		PinObject(ctx context.Context, appKey types.PrivateKey, obj slabs.SealedObject) error
		DeleteObject(ctx context.Context, appKey types.PrivateKey, key types.Hash256) error

		Slab(context.Context, types.PrivateKey, slabs.SlabID) (slabs.PinnedSlab, error)
		PinSlabs(context.Context, types.PrivateKey, ...slabs.SlabPinParams) ([]slabs.SlabID, error)
		UnpinSlab(context.Context, types.PrivateKey, slabs.SlabID) error
		PruneSlabs(context.Context, types.PrivateKey, ...api.URLQueryParameterOption) error
	}

	downloadOption struct {
		hostTimeout time.Duration
		// maxBufferedChunks is the memory ceiling for the download, in chunks.
		// Zero derives it from the memory budget.
		maxBufferedChunks int
		offset            uint64
		length            uint64
		onProgress        func(ShardProgress)
	}

	// A ShardProgress reports the result of a successfully completed
	// shard upload or download.
	ShardProgress struct {
		HostKey    types.PublicKey
		SlabIndex  int
		ShardIndex int
		ShardSize  uint64
		Elapsed    time.Duration
	}

	// An UploadOption configures the upload behavior
	UploadOption func(*uploadOption)

	// A DownloadOption configures the download behavior
	DownloadOption func(*downloadOption)

	// An SDK is a client for the indexd service.
	SDK struct {
		app   appClient
		hosts hostClient
		// wrapHosts, when set by WithHostClient, decorates `hosts` once the real client exists.
		wrapHosts  func(HostClient) HostClient
		hostsCache *hostCache

		// newHosts builds a hostClient over a given host store. Production
		// code always builds a real client.New(client.NewProvider(store), ...);
		// mocked SDKs override this to hand back the same mock client
		// regardless of store, so a download's job-scoped map still exercises
		// the mock's recorded RPC behavior.
		//
		// TESSERA FORK: lets
		// [SDK.Download] build a fresh, job-scoped hostClient over a
		// download-only host store, isolated from the shared write-path
		// hostsCache.
		newHosts func(*hostCache) hostClient

		appKey types.PrivateKey

		// egress reports successfully served shard reads to the configured
		// endpoint; nil when no egress URL is configured (reporting off).
		egress *egressReporter
		// egressCfg collects the egress options until initEgress builds the
		// reporter.
		egressCfg egressConfig

		tg  *threadgroup.ThreadGroup
		log *zap.Logger
	}
)

var (
	// ErrNotEnoughShards is returned when not enough shards were
	// uploaded or downloaded to satisfy the minimum required shards.
	ErrNotEnoughShards = errors.New("not enough shards")

	// ErrNoMoreHosts is returned when there are no more hosts
	// available to attempt to upload a shard
	ErrNoMoreHosts = errors.New("no more hosts available")
)

type sectorDownload struct {
	index  int
	sector slabs.PinnedSector
}

func (s *SDK) downloadSlab(ctx context.Context, hc hostClient, slab slabs.SlabSlice, slabIndex, seq int, popped *changeCounter, limiter *inflightLimiter, timeout time.Duration, onProgress func(ShardProgress)) ([][]byte, error) {
	if slab.MinShards == 0 {
		return nil, errors.New("invalid slab: min shards cannot be 0")
	} else if int(slab.MinShards) > len(slab.Sectors) {
		return nil, fmt.Errorf("invalid slab: min shards %d exceeds sector count %d", slab.MinShards, len(slab.Sectors))
	}

	slabSectors := make(map[types.PublicKey]sectorDownload)
	slabHosts := make([]types.PublicKey, 0, len(slab.Sectors))
	for i, sector := range slab.Sectors {
		if _, ok := slabSectors[sector.HostKey]; ok {
			// a host should never hold two sectors of the same slab; the
			// indexer rejects such a slab at pin time. Skipping keeps
			// slabHosts and slabSectors the same length, so the usable-host
			// check below and the initial batch agree on how many sectors
			// are actually reachable.
			continue
		}
		slabSectors[sector.HostKey] = sectorDownload{
			index:  i,
			sector: sector,
		}
		slabHosts = append(slabHosts, sector.HostKey)
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer func() {
		cancel()
		wg.Wait()
	}()

	// calculate offset and length that's required from each sector to recover
	// the data referenced by the slab slice
	offset, length := sectorRegion(slab)

	// prioritize hosts, dropping any that are no longer usable
	slabHosts = hc.Prioritize(slabHosts)
	// check after prioritizing since it removes unusable hosts, leaving
	// potentially fewer than the initial batch below consumes
	if len(slabHosts) < int(slab.MinShards) {
		return nil, fmt.Errorf("slab has %d usable hosts, minimum required: %d: %w", len(slabHosts), slab.MinShards, ErrNotEnoughShards)
	}

	// helper to launch download
	type result struct {
		index   int
		buf     []byte
		err     error
		hostKey types.PublicKey
		elapsed time.Duration
	}
	responseCh := make(chan result, len(slab.Sectors))
	var outstanding int
	tryDownloadSector := func(d sectorDownload) {
		outstanding++
		release := hc.TrackInflightRead(d.sector.HostKey)
		wg.Go(func() {
			defer release()
			permit := limiter.sample()
			timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			buf := bytes.NewBuffer(make([]byte, 0, length))
			start := time.Now()
			_, err := hc.ReadSector(timeoutCtx, s.appKey, d.sector.HostKey, d.sector.Root, buf, offset, length)
			// report the served shard immediately, before the result can be
			// dropped by the cancellation race below: the host did the work,
			// so an overprovisioned success that loses the race still counts.
			// Failed, cancelled and partially written reads are not reported,
			// and slabs.SlabSlice carries no id, so slab_id is null on the
			// wire. record never blocks or fails the read.
			if err == nil {
				s.egress.record(d.sector.HostKey, nil, d.index, buf.Len())
			}
			elapsed := time.Since(start)
			// a read aborted because the chunk already had enough shards
			// measured the cancellation, not the network, so it is not a
			// congestion signal
			if ctx.Err() == nil {
				limiter.record(permit, elapsed, err == nil)
			}
			select {
			case <-ctx.Done():
			case responseCh <- result{
				index:   d.index,
				buf:     buf.Bytes(),
				err:     err,
				hostKey: d.sector.HostKey,
				elapsed: elapsed,
			}:
			}
			// a host only gets demoted when it hits the shard timeout. reads
			// cancelled because the chunk completed without them are expected
			// with overprovisioning and do not count against the host
			if timeoutCtx.Err() != nil && ctx.Err() == nil {
				hc.AddFailedRPC(d.sector.HostKey)
			}
		})
	}

	// overprovision the initial reads to avoid waiting on the slowest of
	// exactly minShards hosts; the chunk completes on the first minShards
	// successes and the leftover reads are cancelled
	initial := min(int(slab.MinShards)*3/2, len(slabHosts))
	for range initial {
		tryDownloadSector(slabSectors[slabHosts[0]])
		slabHosts = slabHosts[1:]
	}

	// only race a host once it is clearly slower than normal. before we have
	// timing data the estimate is large, so racing stays off until it warms up.
	raceTimeout := time.Duration(float64(hc.ReadEstimate(length)) * raceFactor)
	lastEvent := time.Now()

	var successful int
	shards := make([][]byte, len(slab.Sectors))
	for {
		// snapshot the read head once so the eligibility test and the wakeup
		// channel stay consistent. only race while this chunk is near the read
		// head and a spare host is free. the spare check stops a tiny estimate
		// from spinning the timer.
		head, windowCh := popped.snapshot()
		eligible := len(slabHosts) > 0 && seq < head+raceWindow
		var raceCh <-chan time.Time
		if eligible {
			// Go cleans up this timer even if we never read the channel
			raceCh = time.After(time.Until(lastEvent.Add(raceTimeout)))
			// while racing we wait on the timer, not read-head moves
			windowCh = nil
		}

		select {
		case res := <-responseCh:
			lastEvent = time.Now()
			outstanding--
			if res.err == nil {
				// successful download
				shards[res.index] = res.buf
				successful++
				if successful <= int(slab.MinShards) && onProgress != nil {
					onProgress(ShardProgress{
						HostKey:    res.hostKey,
						SlabIndex:  slabIndex,
						ShardIndex: res.index,
						ShardSize:  uint64(len(res.buf)),
						Elapsed:    res.elapsed,
					})
				}
				if successful >= int(slab.MinShards) {
					// enough shards downloaded
					return shards, nil
				}
			}
			// check if enough potential successes remain
			rem := int(slab.MinShards) - successful
			if outstanding+len(slabHosts) < rem {
				return nil, ErrNotEnoughShards
			}
			if res.err != nil && len(slabHosts) > 0 {
				tryDownloadSector(slabSectors[slabHosts[0]])
				slabHosts = slabHosts[1:]
			}

		case <-raceCh:
			lastEvent = time.Now()
			// periodically launch an extra download to race slow hosts
			if len(slabHosts) > 0 {
				tryDownloadSector(slabSectors[slabHosts[0]])
				slabHosts = slabHosts[1:]
			}

		case <-windowCh:
			// the read head moved, loop around and check again

		case <-ctx.Done():
			// download got interrupted before it could finish
			return nil, ctx.Err()
		}
	}
}

// AppKey returns the app key used by the SDK.
//
// It should be kept secret. Applications
// should store it securely to authenticate with
// the indexer.
func (s *SDK) AppKey() types.PrivateKey {
	return s.appKey
}

// Account retrieves account information for the current app key.
func (s *SDK) Account(ctx context.Context) (app.AccountResponse, error) {
	return s.app.Account(ctx, s.appKey)
}

// PruneSlabs removes all slabs on the account that are not associated with
// an object.
//
// The indexer only considers slabs that were pinned more than
// [api.DefaultSlabPruneCutoff] ago. Pass [api.WithBefore] to override that
// cutoff.
func (s *SDK) PruneSlabs(ctx context.Context, opts ...api.URLQueryParameterOption) error {
	return s.app.PruneSlabs(ctx, s.appKey, opts...)
}

// DeleteObject deletes the object with the given key from the indexer.
func (s *SDK) DeleteObject(ctx context.Context, key types.Hash256) error {
	return s.app.DeleteObject(ctx, s.appKey, key)
}

// Upload uploads the data to hosts.
//
// Appends the metadata of the slabs that were uploaded to the given object.
// After uploading the object, the caller must call PinObject to pin the
// slabs and save the object metadata to the indexer.
//
// TESSERA FORK: fetches the write-path
// host plate (GET /hosts, paginated) once, here, at write-job start. connect
// no longer does this -- see initSDK -- and there is no periodic background
// refresh; a long-lived SDK's write-path list is only as fresh as its last
// Upload/UploadPacked call.
func (s *SDK) Upload(ctx context.Context, obj *Object, r io.Reader, opts ...UploadOption) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if err := s.refreshHosts(ctx, true); err != nil {
		return fmt.Errorf("failed to refresh hosts at write start: %w", err)
	}

	// create upload options
	uo, enc, err := newUploadOption(opts...)
	if err != nil {
		return err
	}

	if len(obj.dataKey) != 32 {
		return fmt.Errorf("invalid data key length: %d", len(obj.dataKey))
	}

	// the object data is encrypted with a distinct nonce for each slab; the same
	// slab key is then used to encrypt the individual shards
	slabKeys := &slabKeySource{}

	// start uploading slabs; the workers encrypt each slab in place
	slabsCh := make(chan slabUpload, uo.maxBufferedSlabs)
	go func() {
		defer close(slabsCh)
		s.uploadPlaintextSlabs(ctx, slabsCh, r, obj.UnsafeDataKey(), slabKeys, enc, uo)
	}()

	// collect uploaded slabs
	uploaded, err := collectSlabs(ctx, slabsCh, uo)
	if err != nil {
		return err
	}

	obj.slabs = append(obj.slabs, uploaded...)
	return nil
}

// Download returns an [io.ReadCloser] streaming the object's data. Closing the
// reader cancels the underlying download. Callers must always Close the
// returned reader to release resources.
//
// TESSERA FORK: read start fetches THIS
// object's map -- GET /objects/:key/hosts, via [appClient.ObjectHosts] --
// once, into a fresh, job-scoped hostClient that shares no state with the
// write-path SDK.hosts/hostsCache Upload populates. It is used for this
// download only and closed when the returned reader is closed. Product law:
// never call GET /hosts to help a download, never reuse the write-path plate.
func (s *SDK) Download(obj Object, opts ...DownloadOption) (io.ReadCloser, error) {
	do, err := newDownloadOption(obj.Size(), opts...)
	if err != nil {
		return nil, err
	}

	if !do.normalizeRange(obj.Size()) {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}

	if len(obj.dataKey) != 32 {
		return nil, fmt.Errorf("invalid data key length: %d", len(obj.dataKey))
	} else if err := validateSlabVersions((*[32]byte)(obj.dataKey), obj.slabs); err != nil {
		return nil, err
	}

	mapHosts, err := s.app.ObjectHosts(context.Background(), s.appKey, obj.ID())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch object host map: %w", err)
	}
	scoped := newHostCache()
	scoped.updateHosts(mapHosts)
	hc := s.newHosts(scoped)

	return s.downloadReader(hc, (*[32]byte)(obj.dataKey), obj.slabs, do)
}

// DownloadSharedObject returns an [io.ReadCloser] streaming a shared object's
// data. Closing the reader cancels the underlying download. Callers must always
// Close the returned reader to release resources.
//
// KNOWN GAP (TESSERA FORK): a shared object
// belongs to a DIFFERENT account than s.appKey, so indexd's authenticated
// GET /objects/:key/hosts (scoped to the caller's own account) cannot be used
// here -- unlike [SDK.Download], this path still reads from the shared,
// write-path s.hosts/hostsCache, which Upload/UploadPacked populate and
// nothing else does since connect-time/periodic refresh were removed. A
// process that only ever calls DownloadSharedObject (never Upload) now starts
// with an EMPTY host cache. Out of scope for this packet (four laws are
// specified for object()/download() of an app's own objects); flagged here
// rather than silently left broken.
func (s *SDK) DownloadSharedObject(ctx context.Context, sharedURL string, opts ...DownloadOption) (io.ReadCloser, error) {
	obj, encryptionKey, err := s.app.SharedObject(ctx, sharedURL)
	if err != nil {
		return nil, err
	}

	do, err := newDownloadOption(obj.Size(), opts...)
	if err != nil {
		return nil, err
	}

	if !do.normalizeRange(obj.Size()) {
		return io.NopCloser(bytes.NewReader(nil)), nil
	}

	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("invalid encryption key length: %d", len(encryptionKey))
	}
	if err := validateSlabVersions((*[32]byte)(encryptionKey), obj.Slabs); err != nil {
		return nil, err
	}

	return s.downloadReader(s.hosts, (*[32]byte)(encryptionKey), obj.Slabs, do)
}

// downloadReader starts recovering chunks immediately and streams them to the
// reader, so the first bytes are ready as early as possible. Closing the
// returned reader cancels any chunk downloads in flight.
func (s *SDK) downloadReader(hc hostClient, key *[32]byte, ss []slabs.SlabSlice, do downloadOption) (io.ReadCloser, error) {
	ctx, cancel := context.WithCancelCause(context.Background())
	chunks := newChunkDownloader(ctx, cancel, s, hc, key, ss, do)
	chunks.start()
	return &downloadStream{chunks: chunks}, nil
}

// downloadStream is an [io.ReadCloser] over the recovered, decrypted plaintext
// produced by a [chunkDownloader]; it only tracks its position within the
// current chunk.
type downloadStream struct {
	chunks *chunkDownloader

	closed atomic.Bool // set by Close, possibly on a different goroutine than Read

	cur []byte // current chunk's plaintext (pooled), nil if drained
	off int    // bytes of cur already consumed
}

// release returns cur to the pool once it is fully consumed.
func (d *downloadStream) release() {
	d.chunks.bufs.put(d.cur)
	d.cur = nil
	d.off = 0
}

// fill ensures d.cur holds an unconsumed chunk, fetching the next one only once
// the current is drained so a large read gets whatever is available rather than
// blocking until it is full. It reports io.ErrClosedPipe if the stream was
// closed, io.EOF once every chunk has been yielded, or any download error.
func (d *downloadStream) fill() error {
	if d.closed.Load() {
		return io.ErrClosedPipe
	}
	if d.cur != nil {
		return nil
	}
	buf, err := d.chunks.nextChunk()
	if d.closed.Load() {
		if err == nil {
			d.chunks.bufs.put(buf)
		}
		return io.ErrClosedPipe
	}
	if err != nil {
		return err
	}
	d.cur, d.off = buf, 0
	return nil
}

func (d *downloadStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if err := d.fill(); err != nil {
		return 0, err
	}
	n := copy(p, d.cur[d.off:])
	d.off += n
	if d.off == len(d.cur) {
		d.release()
	}
	return n, nil
}

func (d *downloadStream) WriteTo(w io.Writer) (int64, error) {
	var total int64
	for {
		if err := d.fill(); err != nil {
			if errors.Is(err, io.EOF) {
				return total, nil
			}
			return total, err
		}
		for d.off < len(d.cur) {
			p := d.cur[d.off:]
			n, err := w.Write(p)
			if n < 0 || n > len(p) {
				return total, fmt.Errorf("invalid Write count %d", n)
			}

			d.off += n
			total += int64(n)
			if d.off == len(d.cur) {
				d.release()
			}
			if err != nil {
				return total, err
			} else if n == 0 {
				return total, io.ErrShortWrite
			}
		}
	}
}

func (d *downloadStream) Close() error {
	if d.closed.Swap(true) {
		return nil // already closed
	}
	d.chunks.close()
	return nil
}

// newDownloadOption creates a downloadOption for an object of the given size
// with defaults, applies the given options, and validates them.
func newDownloadOption(objectSize uint64, opts ...DownloadOption) (downloadOption, error) {
	do := downloadOption{
		hostTimeout: 60 * time.Second, // long to handle slow hosts; racing routes around stragglers
		length:      objectSize,
	}
	for _, opt := range opts {
		opt(&do)
	}

	if do.maxBufferedChunks < 0 {
		return do, fmt.Errorf("max buffered chunks must not be negative, got %d", do.maxBufferedChunks)
	} else if do.maxBufferedChunks == 0 {
		do.maxBufferedChunks = defaultChunksInMemory()
	}
	// a chunk holds a single permit, so the budget is already a capacity
	do.maxBufferedChunks = clampBufferBudget(do.maxBufferedChunks, 1)

	return do, nil
}

// normalizeRange clamps the download range to the object size. Returns
// false if the range is empty (nothing to download).
func (do *downloadOption) normalizeRange(maxLength uint64) bool {
	if do.offset >= maxLength || do.length == 0 {
		return false
	}
	do.length = min(do.length, maxLength-do.offset)
	return true
}

// Close closes the SDK and releases all resources.
func (s *SDK) Close() error {
	s.tg.Stop()
	return s.hosts.Close()
}

// PinObject pins the object's slabs and saves the object metadata to the
// indexer.
func (s *SDK) PinObject(ctx context.Context, obj Object) error {
	params := make([]slabs.SlabPinParams, len(obj.slabs))
	for i, slab := range obj.slabs {
		params[i] = slabs.SlabPinParams{
			Version:       slab.Version,
			EncryptionKey: slab.EncryptionKey,
			MinShards:     slab.MinShards,
			Sectors:       slab.Sectors,
		}
		if err := params[i].Validate(); err != nil {
			return fmt.Errorf("slab %d invalid: %w", i, err)
		}
	}

	for i := 0; i < len(params); i += pinBatchSize {
		end := min(i+pinBatchSize, len(params))

		slabIDs, err := s.app.PinSlabs(ctx, s.appKey, params[i:end]...)
		if err != nil {
			return fmt.Errorf("failed to pin slabs: %w", err)
		}

		for j, slab := range obj.slabs[i:end] {
			if expected := slab.Digest(); slabIDs[j] != expected {
				return fmt.Errorf("slab %d: pinned id %s does not match expected id %s", i+j, slabIDs[j], expected)
			}
		}
	}

	return s.app.PinObject(ctx, s.appKey, obj.Seal(s.appKey).SealedObject)
}

const (
	// initialDownloadInflight is the number of chunk recoveries allowed in
	// flight before the controller has measured anything, and
	// minDownloadInflight is the floor it may back off to.
	initialDownloadInflight = 8
	minDownloadInflight     = 1

	// initialChunkSize is the size of a download's first chunk. Starting
	// small keeps the time to first byte low, since the first chunk only
	// needs a tiny read from each host.
	initialChunkSize = 1 << 15 // 32 KiB

	// maxChunkSize caps the per-chunk doubling. Larger chunks amortize the
	// fixed cost of a read RPC over more bytes.
	maxChunkSize = 1 << 20 // 1 MiB
)

// chunkIter splits slabs into chunks for parallel recovery. Chunks start at
// initialChunkSize for a fast first byte and double per chunk up to
// maxChunkSize. It handles byte-range selection internally: offset is a byte
// offset into the logical stream of all slabs and length limits total output.
type chunkIter struct {
	slabs        []slabs.SlabSlice
	slabIdx      int
	offset       uint64 // position within current slab
	objectOffset uint64 // position within the object's logical stream
	remaining    uint64 // total bytes left to yield
	chunkSize    uint64 // doubles per chunk up to maxChunkSize
}

type chunkSlab struct {
	slab         slabs.SlabSlice
	slabIdx      int
	objectOffset uint64
}

func newChunkIter(ss []slabs.SlabSlice, offset, length uint64) *chunkIter {
	ci := &chunkIter{
		slabs:        ss,
		objectOffset: offset,
		remaining:    length,
		chunkSize:    initialChunkSize,
	}
	for ci.slabIdx < len(ci.slabs) {
		slabLength := uint64(ci.slabs[ci.slabIdx].Length)
		if offset < slabLength {
			break
		}
		offset -= slabLength
		ci.slabIdx++
	}
	ci.offset = offset
	return ci
}

func (ci *chunkIter) next() (chunkSlab, bool) {
	for ci.remaining > 0 && ci.slabIdx < len(ci.slabs) {
		slab := ci.slabs[ci.slabIdx]
		available := uint64(slab.Length) - ci.offset
		if available == 0 {
			ci.slabIdx++
			ci.offset = 0
			continue
		}
		chunkLen := min(available, ci.remaining, ci.chunkSize)
		chunk := slab
		chunk.Offset = slab.Offset + uint32(ci.offset)
		chunk.Length = uint32(chunkLen)
		result := chunkSlab{
			slab:         chunk,
			slabIdx:      ci.slabIdx,
			objectOffset: ci.objectOffset,
		}
		ci.offset += chunkLen
		ci.objectOffset += chunkLen
		if ci.offset >= uint64(slab.Length) {
			ci.offset = 0
			ci.slabIdx++
		}
		ci.remaining -= chunkLen
		ci.chunkSize = min(ci.chunkSize*2, maxChunkSize)
		return result, true
	}
	return chunkSlab{}, false
}

type recoveredChunk struct {
	shards   [][]byte
	skip     int
	writeLen int
}

func (s *SDK) recoverChunk(ctx context.Context, hc hostClient, chunk slabs.SlabSlice, slabIndex, seq int, popped *changeCounter, limiter *inflightLimiter, hostTimeout time.Duration, onProgress func(ShardProgress)) (recoveredChunk, error) {
	shards, err := s.downloadSlab(ctx, hc, chunk, slabIndex, seq, popped, limiter, hostTimeout, onProgress)
	if err != nil {
		return recoveredChunk{}, fmt.Errorf("failed to download slab: %w", err)
	}

	// decrypt shards
	counter := chunk.Offset / (proto4.LeafSize * uint32(chunk.MinShards))
	var nonce [24]byte
	for i, shard := range shards {
		if shard == nil {
			continue
		}
		nonce[0] = byte(i)
		c, _ := chacha20.NewUnauthenticatedCipher(chunk.EncryptionKey[:], nonce[:])
		c.SetCounter(counter)
		c.XORKeyStream(shard, shard)
	}

	// reconstruct data shards
	enc, err := reedsolomon.New(int(chunk.MinShards), len(shards)-int(chunk.MinShards))
	if err != nil {
		return recoveredChunk{}, fmt.Errorf("failed to create reedsolomon coder: %w", err)
	}
	if err := enc.ReconstructData(shards); err != nil {
		return recoveredChunk{}, fmt.Errorf("failed to reconstruct data shards: %w", err)
	}

	return recoveredChunk{
		shards:   shards[:int(chunk.MinShards)],
		skip:     int(chunk.Offset) % (proto4.LeafSize * int(chunk.MinShards)),
		writeLen: int(chunk.Length),
	}, nil
}

// slabCipherStream returns the cipher stream that decrypts the given chunk's
// data, returning ErrUnsupportedSlabVersion for versions this SDK cannot
// decrypt. It is the single source of truth for which slab versions are
// supported.
func slabCipherStream(dataKey *[32]byte, chunk chunkSlab) (cipher.Stream, error) {
	switch chunk.slab.Version {
	case 0:
		return newV0CipherStream(dataKey, chunk.objectOffset), nil
	case 1:
		return newV1CipherStream(dataKey, (*[32]byte)(&chunk.slab.EncryptionKey), uint64(chunk.slab.Offset)), nil
	default:
		return nil, fmt.Errorf("%w: %d", slabs.ErrUnsupportedSlabVersion, chunk.slab.Version)
	}
}

// validateSlabVersions rejects slabs this SDK cannot decrypt so downloads fail
// fast, before any sectors are fetched.
func validateSlabVersions(dataKey *[32]byte, ss []slabs.SlabSlice) error {
	for i, slab := range ss {
		if _, err := slabCipherStream(dataKey, chunkSlab{slab: slab}); err != nil {
			return fmt.Errorf("slab %d: %w", i, err)
		}
	}
	return nil
}

// chunkResult is the decrypted plaintext of a chunk, or the error that
// prevented recovery.
type chunkResult struct {
	index   int
	data    []byte // pooled; returned via bufs.put once consumed
	err     error
	release func() // frees the chunk's limiter permit once consumed
}

// chunkDownloader recovers and decrypts chunks concurrently and yields their
// plaintext in order via nextChunk. Each chunk recovers in its own goroutine
// (chacha20 is seekable, so decryption parallelizes); nextChunk reorders the
// results, buffering ready chunks so a straggler never idles the other slots.
// A recovery error cancels the context but is reported as context.Cause, not a
// bare context.Canceled.
type chunkDownloader struct {
	s           *SDK
	ctx         context.Context
	cancel      context.CancelCauseFunc
	key         *[32]byte
	hc          hostClient // job-scoped host client for this download only (TESSERA FORK)
	hostTimeout time.Duration
	onProgress  func(ShardProgress)
	bufs        *chunkBufPool
	chunks      *chunkIter

	// popped counts how many chunks the reader has taken. each chunk task uses
	// it to tell how close it is to the read head.
	popped *changeCounter

	limiter *inflightLimiter // adapts the number of concurrent chunk recoveries
	results chan chunkResult // recovered chunks, in completion order

	once sync.Once
	done chan struct{} // closed once the dispatcher and all chunk goroutines exit

	// consumer state, owned by the nextChunk caller
	next      int                 // index of the next chunk to yield
	completed map[int]chunkResult // out-of-order results awaiting their turn
	err       error               // terminal error, cached for repeat nextChunk calls
}

// chunkBufPool pools full-size plaintext buffers reused across chunk downloads,
// hiding the [maxChunkSize]byte-array/slice conversion behind get and put.
type chunkBufPool struct {
	pool sync.Pool
}

func newChunkBufPool() *chunkBufPool {
	return &chunkBufPool{pool: sync.Pool{New: func() any { return new([maxChunkSize]byte) }}}
}

// get returns a buffer of length n backed by a full [maxChunkSize]byte array.
func (p *chunkBufPool) get(n int) []byte {
	return p.pool.Get().(*[maxChunkSize]byte)[:n]
}

// put returns a buffer previously obtained from get to the pool.
func (p *chunkBufPool) put(buf []byte) {
	p.pool.Put((*[maxChunkSize]byte)(buf[:maxChunkSize]))
}

// newChunkDownloader builds a chunkDownloader; the caller launches its
// dispatcher via start.
func newChunkDownloader(ctx context.Context, cancel context.CancelCauseFunc, s *SDK, hc hostClient, key *[32]byte, ss []slabs.SlabSlice, do downloadOption) *chunkDownloader {
	// the controller samples sector reads but limits chunk recoveries, and each
	// recovery issues about MinShards reads, so scale its window accordingly
	scale := 1
	if len(ss) > 0 {
		scale = int(ss[0].MinShards)
	}
	return &chunkDownloader{
		s:           s,
		ctx:         ctx,
		cancel:      cancel,
		key:         key,
		hc:          hc,
		hostTimeout: do.hostTimeout,
		onProgress:  do.onProgress,
		bufs:        newChunkBufPool(),
		chunks:      newChunkIter(ss, do.offset, do.length),
		popped:      newChangeCounter(0),
		limiter:     newInflightLimiter(initialDownloadInflight, minDownloadInflight, do.maxBufferedChunks, scale, s.log),
		results:     make(chan chunkResult, do.maxBufferedChunks),
		done:        make(chan struct{}),
		completed:   make(map[int]chunkResult),
	}
}

func (c *chunkDownloader) start() {
	c.once.Do(func() { go c.run() })
}

// run walks chunks in order and admits each at the controller's current limit.
// The permit is held until the reader consumes the result, bounding buffered
// memory as well as active recovery. The first chunk is recovered synchronously
// for fast TTFB, so its host reads never queue behind later chunks.
func (c *chunkDownloader) run() {
	var wg sync.WaitGroup
	defer close(c.done)
	defer close(c.results)
	defer wg.Wait()
	for index := 0; ; index++ {
		// bail out promptly if the download was cancelled
		if c.ctx.Err() != nil {
			return
		}
		chunk, ok := c.chunks.next()
		if !ok {
			return
		}
		release, ok := c.limiter.acquire(c.ctx)
		if !ok {
			return
		}
		if index == 0 {
			c.deliverChunk(index, chunk, release)
			continue
		}
		wg.Go(func() {
			c.deliverChunk(index, chunk, release)
		})
	}
}

// deliverChunk recovers and decrypts one chunk and hands its result off along
// with the permit the reader releases once it consumes it. If the download was
// cancelled first, the permit and the pooled buffer are released here instead.
func (c *chunkDownloader) deliverChunk(index int, chunk chunkSlab, release func()) {
	data, err := c.recoverAndDecrypt(index, chunk)
	if err != nil {
		// surface the error promptly via the cause instead of
		// waiting behind slower in-order chunks; first cause wins.
		c.cancel(err)
	}
	select {
	case c.results <- chunkResult{index: index, data: data, err: err, release: release}:
	case <-c.ctx.Done():
		release()
		if data != nil {
			c.bufs.put(data)
		}
	}
}

// recoverAndDecrypt recovers a chunk into a pooled buffer and decrypts it in
// place with the cipher stream for its slab version, so chunks decrypt
// independently.
func (c *chunkDownloader) recoverAndDecrypt(seq int, chunk chunkSlab) ([]byte, error) {
	stream, err := slabCipherStream(c.key, chunk)
	if err != nil {
		return nil, err
	}
	rc, err := c.s.recoverChunk(c.ctx, c.hc, chunk.slab, chunk.slabIdx, seq, c.popped, c.limiter, c.hostTimeout, c.onProgress)
	if err != nil {
		return nil, err
	}
	out := c.bufs.get(rc.writeLen)
	if err := stripedJoin(out, rc.shards, rc.skip); err != nil {
		c.bufs.put(out)
		return nil, err
	}
	stream.XORKeyStream(out, out)
	return out, nil
}

// nextChunk blocks until the next chunk's plaintext is ready and returns it in
// order, io.EOF once all chunks are yielded. Hand the buffer to c.bufs.put when done.
func (c *chunkDownloader) nextChunk() ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	c.start()
	c.popped.add(1) // the chunk being awaited is now the read head
	for {
		if r, ok := c.completed[c.next]; ok {
			delete(c.completed, c.next)
			r.release()
			if r.err != nil {
				return nil, c.fail(r.err)
			}
			c.next++
			return r.data, nil
		}
		r, ok := <-c.results
		if !ok {
			// dispatcher exited: nil cause means it finished cleanly, else cancelled
			if c.err = context.Cause(c.ctx); c.err == nil {
				c.err = io.EOF
				c.cancel(nil)
			}
			return nil, c.err
		}
		c.completed[r.index] = r
	}
}

// fail records the download's terminal error, preferring the cancellation
// cause over a bare context.Canceled, and reaps the download goroutines.
func (c *chunkDownloader) fail(err error) error {
	c.err = err
	if errors.Is(err, context.Canceled) {
		if cause := context.Cause(c.ctx); cause != nil {
			c.err = cause
		}
	}
	c.close()
	return c.err
}

// close cancels the download and waits for its goroutines to exit. Outstanding
// result buffers and limiter permits become unreachable with the downloader.
func (c *chunkDownloader) close() {
	c.cancel(nil)
	// ensure the dispatcher was launched so done is guaranteed to close; if it
	// never ran, run observes the cancelled context and exits immediately.
	c.start()
	<-c.done
}

func (s *SDK) fetchHosts(ctx context.Context) (all []hosts.HostInfo, _ error) {
	const batchSize = 100

	var exhausted bool
	for offset := 0; !exhausted; offset += batchSize {
		batch, err := s.app.Hosts(ctx, s.appKey, api.WithOffset(offset), api.WithLimit(batchSize))
		if err != nil {
			return nil, fmt.Errorf("failed to fetch hosts from indexer: %w", err)
		} else if len(batch) < batchSize {
			exhausted = true
		}
		all = append(all, batch...)
	}

	return all, nil
}

func (s *SDK) refreshHosts(ctx context.Context, forceWarmup bool) error {
	// fetch all hosts
	allHosts, err := s.fetchHosts(ctx)
	if err != nil {
		return err
	}

	// count GFU hosts for logging
	var gfuCount int
	for _, host := range allHosts {
		if host.GoodForUpload {
			gfuCount++
		}
	}

	// update the hosts cache
	added := s.hostsCache.updateHosts(allHosts)
	s.log.Debug("hosts refreshed", zap.Int("hosts", len(allHosts)), zap.Int("new", len(added)), zap.Int("goodForUpload", gfuCount))

	// warmup all hosts if force is set
	if forceWarmup {
		hks := make([]types.PublicKey, len(allHosts))
		for i, host := range allHosts {
			hks[i] = host.PublicKey
		}
		return s.warmConnections(ctx, hks)
	}

	// otherwise warm up newly added GFU hosts if there are any
	if len(added) > 0 {
		gfu := make([]types.PublicKey, 0, len(added))
		for _, host := range added {
			if host.GoodForUpload {
				gfu = append(gfu, host.PublicKey)
			}
		}
		if len(gfu) > 0 {
			return s.warmConnections(ctx, gfu)
		}
	}

	return nil
}

func (s *SDK) warmConnections(ctx context.Context, hks []types.PublicKey) error {
	var warmed atomic.Uint64

	var wg sync.WaitGroup
	sema := make(chan struct{}, 15)
	for _, hk := range hks {
		select {
		case <-ctx.Done():
			return nil
		case sema <- struct{}{}:
		}

		tCtx, tCancel, err := s.tg.AddContext(ctx)
		if err != nil {
			return err
		}

		wg.Add(1)
		go func(ctx context.Context, hk types.PublicKey) {
			defer func() {
				tCancel()
				wg.Done()
				<-sema
			}()
			pCtx, pCancel := context.WithTimeout(ctx, time.Second)
			_, err := s.hosts.Prices(pCtx, hk)
			pCancel()

			if err == nil {
				warmed.Add(1)
			}
		}(tCtx, hk)
	}

	// wait for all warmups to complete
	wg.Wait()

	s.log.Debug("warmed up hosts", zap.Uint64("n", warmed.Load()))
	return nil
}

// sectorRegion returns the offset and length of the sector region that must be
// downloaded in order to recover the data referenced by the slice.
func sectorRegion(ss slabs.SlabSlice) (offset, length uint64) {
	minChunkSize := proto4.LeafSize * uint32(ss.MinShards)
	start := (ss.Offset / minChunkSize) * proto4.LeafSize
	end := ((ss.Offset + ss.Length) / minChunkSize) * proto4.LeafSize
	if (ss.Offset+ss.Length)%minChunkSize != 0 {
		end += proto4.LeafSize
	}
	return uint64(start), uint64(end - start)
}

// writeSector uploads a single sector to a host with the given timeout.
func writeSector(ctx context.Context, client hostClient, accountKey types.PrivateKey, hostKey types.PublicKey, data []byte, timeout time.Duration) (types.Hash256, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := client.WriteSector(ctx, accountKey, hostKey, data)
	return result.Root, err
}

// WithRedundancy sets the number of data and parity shards for the upload.
// The number of shards must be at least 2x redundancy:
// `(dataShards + parityShards) / dataShards >= 2`.
func WithRedundancy(dataShards, parityShards uint8) UploadOption {
	return func(uo *uploadOption) {
		uo.dataShards = dataShards
		uo.parityShards = parityShards
	}
}

// WithUploadMaxBufferedSlabs sets the maximum number of fully encoded slabs
// held in memory. Upload concurrency adapts to network conditions up to that
// ceiling. Each slab uses (dataShards+parityShards) * 4 MiB; zero uses the
// default, roughly 10% of the memory available to the process.
func WithUploadMaxBufferedSlabs(maxBufferedSlabs int) UploadOption {
	return func(uo *uploadOption) {
		uo.maxBufferedSlabs = maxBufferedSlabs
	}
}

// WithUploadProgress sets a callback that is invoked for each shard that
// completes uploading successfully. Callers should keep the callback short or
// hand off work to a goroutine. The callback may be called concurrently.
func WithUploadProgress(fn func(ShardProgress)) UploadOption {
	return func(uo *uploadOption) {
		uo.onProgress = fn
	}
}

// WithDownloadHostTimeout sets the timeout for reading sectors
// from individual hosts. The default is 60 seconds.
func WithDownloadHostTimeout(timeout time.Duration) DownloadOption {
	return func(do *downloadOption) {
		do.hostTimeout = timeout
	}
}

// WithDownloadMaxBufferedChunks sets the maximum number of chunks held in
// memory. Download concurrency adapts to network conditions up to that ceiling.
// Each chunk uses up to 1 MiB; zero uses the default, roughly 10% of the memory
// available to the process.
func WithDownloadMaxBufferedChunks(maxBufferedChunks int) DownloadOption {
	return func(do *downloadOption) {
		do.maxBufferedChunks = maxBufferedChunks
	}
}

// WithDownloadProgress sets a callback that is invoked for shard downloads
// that complete successfully before the chunk download finishes, i.e. for up
// to MinShards successful shard downloads per chunk. Callers should keep the
// callback short or hand off work to a goroutine. The callback may be called
// concurrently.
func WithDownloadProgress(fn func(ShardProgress)) DownloadOption {
	return func(do *downloadOption) {
		do.onProgress = fn
	}
}

// WithDownloadRange sets the byte range to download from the object. The range
// is clamped to the object size: if offset+length exceeds the object size, only
// the available bytes are returned. If offset is at or beyond the end, or
// length is zero, the returned reader yields no data.
func WithDownloadRange(offset, length uint64) DownloadOption {
	return func(do *downloadOption) {
		do.offset = offset
		do.length = length
	}
}

// An Option configures the SDK.
type Option func(*SDK)

// WithLogger sets the logger for the SDK. The default behavior is to not log
// anything.
// WithHostClient wraps the SDK's host transport, allowing an integrator to observe host-level
// events that are otherwise invisible: a write starting on a specific host (PickWrite), a host RPC
// failing (AddFailedRPC), and the release of a write slot.
//
// The function receives the SDK's own fully-configured HostClient and must return a value that
// delegates to it. Returning the argument unchanged is a no-op. It is applied after construction,
// so a wrapper can observe how writes proceed but cannot change how hosts are reached.
//
// TESSERA FORK ADDITION. Rationale, for the upstream proposal:
//
//	WithUploadProgress reports only SUCCESSFUL, COMPLETED shard transfers and names only the host
//	that won. upload.go's pool.swap() silently substitutes a failed host and reports the
//	substitute's success, so from the public API a slow or failing host is INDISTINGUISHABLE FROM
//	A HOST THAT WAS NEVER ASKED. That makes two legitimate integrator needs impossible:
//	per-host reliability measurement, and any live "write in flight" indication.
//
//	The seam already exists internally (connect.go's mockHost field is this same interface), so
//	this exposes an existing abstraction rather than introducing one.
func WithHostClient(fn func(HostClient) HostClient) Option {
	return func(s *SDK) {
		if fn == nil {
			return
		}
		s.wrapHosts = fn
	}
}

func WithLogger(log *zap.Logger) Option {
	return func(s *SDK) {
		s.log = log
	}
}

// WithEgressURL enables signed egress reporting to the given endpoint, e.g.
// "http://indexer/api/v1/usage/egress". Reporting is disabled by default;
// without a URL no reporter is started and serving a shard does not record
// anything.
func WithEgressURL(url string) Option {
	return func(s *SDK) {
		s.egressCfg.url = url
	}
}

// WithEgressInterval sets how long queued egress events may wait before they
// are reported. The default is 30 seconds.
func WithEgressInterval(interval time.Duration) Option {
	return func(s *SDK) {
		s.egressCfg.interval = interval
	}
}

// WithEgressBatchMax sets the number of queued egress events that triggers an
// immediate flush. The default is 500.
func WithEgressBatchMax(max int) Option {
	return func(s *SDK) {
		s.egressCfg.batchMax = max
	}
}

// WithEgressSpoolPath sets a file used to spool signed egress envelopes that
// could not be delivered, so they survive process restarts. The spool holds
// one canonical envelope per line and is bounded at 8 MiB, oldest dropped.
// Empty (the default) disables the spool.
func WithEgressSpoolPath(path string) Option {
	return func(s *SDK) {
		s.egressCfg.spoolPath = path
	}
}

func initSDK(appKey types.PrivateKey, app appClient, opts ...Option) (*SDK, error) {
	sdk := &SDK{
		appKey:     appKey,
		app:        app,
		hostsCache: newHostCache(),
		egressCfg:  defaultEgressConfig(),

		tg:  threadgroup.New(),
		log: zap.NewNop(), // no logging by default
	}
	for _, opt := range opts {
		opt(sdk)
	}

	// create the host client
	sdk.hosts = client.New(client.NewProvider(sdk.hostsCache), sdk.log.Named("client"))
	// Apply the WithHostClient decorator AFTER the real transport exists, so a wrapper always
	// receives a fully-configured client and can only observe -- never replace -- how hosts are
	// reached. (Tessera fork addition.)
	if sdk.wrapHosts != nil {
		if wrapped := sdk.wrapHosts(sdk.hosts); wrapped != nil {
			sdk.hosts = wrapped
		}
	}

	// newHosts builds the job-scoped hostClient a Download call uses over its
	// own per-object map. Defaults to a real client.New over the given store,
	// decorated the same way as the write-path client above. (Tessera fork,
	// Tessera fork)
	if sdk.newHosts == nil {
		sdk.newHosts = func(store *hostCache) hostClient {
			hc := hostClient(client.New(client.NewProvider(store), sdk.log.Named("client")))
			if sdk.wrapHosts != nil {
				if wrapped := sdk.wrapHosts(hc); wrapped != nil {
					hc = wrapped
				}
			}
			return hc
		}
	}

	// TESSERA FORK: connect/init must NOT
	// call GET /hosts, and there is no periodic background refresh anymore.
	// The old code called sdk.refreshHosts(..., true) here and then spawned a
	// 10-minute-ticker background refresh loop -- both removed. hostsCache
	// starts empty; SDK.Upload/UploadPacked populate it at their own job
	// start, and SDK.Download never touches it at all (job-scoped map
	// instead). See SDK.Upload and SDK.Download for where each half of this
	// law now lives.

	// start egress reporting if WithEgressURL configured it (this must run
	// after every Option has been applied)
	sdk.initEgress()
	return sdk, nil
}
