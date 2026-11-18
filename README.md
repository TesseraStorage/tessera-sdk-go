# Tessera Go SDK

Tessera Go SDK (fork of the Sia Foundation's [siastorage](https://github.com/SiaFoundation/sia-storage-go)).

Guides live at [tessera.storage/docs](https://tessera.storage/docs). Package documentation is on [pkg.go.dev](https://pkg.go.dev/github.com/TesseraStorage/tessera-sdk-go).

```
go get github.com/TesseraStorage/tessera-sdk-go
```

The Go package name is `siastorage`.

Download usage is metered by the server. This SDK does not report download bytes.

## Connecting to the indexer

Before uploading or downloading data, your application connects to the Tessera indexer. Create a `Builder` with your application metadata, then walk the user through the approval flow:

```go
builder := siastorage.NewBuilder("https://index.tessera.storage", siastorage.AppMetadata{
	ID:          appID,                          // a persistent, randomly-generated 32-byte app ID
	Name:        "MyApp",                        // display name
	Description: "My first Tessera application", // short description
	LogoURL:     "https://my.app/logo.png",      // logo shown in the indexer UI
	ServiceURL:  "https://my.app",               // your application's homepage
})

// request a connection — the user must visit the returned URL to approve
responseURL, err := builder.RequestConnection(ctx)
if err != nil {
	log.Fatal("failed to request connection:", err)
}
fmt.Println("Approve the connection:", responseURL)

// block until the user approves or rejects
if err := builder.WaitForApproval(ctx); errors.Is(err, siastorage.ErrUserRejected) {
	log.Fatal("user denied the connection")
} else if err != nil {
	log.Fatal("failed to wait for approval:", err)
}

// derive an app key from a BIP-39 seed phrase and register it
mnemonic := siastorage.NewSeedPhrase() // generate once — store securely
client, err := builder.Register(ctx, mnemonic)
if err != nil {
	log.Fatal("failed to register:", err)
}
defer client.Close()
```

On subsequent launches, skip the approval flow and create the SDK directly with the previously derived app key:

```go
builder := siastorage.NewBuilder("https://index.tessera.storage", siastorage.AppMetadata{ID: appID})
client, err := builder.SDK(appKey)
if err != nil {
	log.Fatal("failed to create SDK:", err)
}
defer client.Close()
```

## Uploading and downloading data

Once connected, you can upload and download files using the SDK:

```go
// upload
obj := siastorage.NewEmptyObject()
f, _ := os.Open("path/to/src.dat")
defer f.Close()

if err := client.Upload(ctx, &obj, f); err != nil {
	log.Fatal("upload failed:", err)
}

// pin the object so the indexer tracks it
if err := client.PinObject(ctx, obj); err != nil {
	log.Fatal("pin failed:", err)
}

// download
out, _ := os.Create("path/to/dst.dat")
defer out.Close()

rc, err := client.Download(obj)
if err != nil {
	log.Fatal("download failed:", err)
}
defer rc.Close()

if _, err := io.Copy(out, rc); err != nil {
	log.Fatal("download failed:", err)
}
```

The `Object` returned by `Upload` contains the encryption key and slab metadata required to download the data later. After uploading, call `PinObject` to persist the object on the indexer. Applications should store the sealed object (via `obj.Seal(appKey)`) so it can be reopened later.

`Upload` and `UploadPacked` fetch the write host list (`GET /hosts`) once at the start of the call. `Download` fetches the hosts storing that object (`GET /objects/:key/hosts`) into a client used only for that download. Downloads do not call `GET /hosts`.

## Agent hooks

Agents and other unattended callers often need to record what they stored and to know when a write did not land. `WithAgentHooks` sets optional callbacks for that. Without it the SDK behaves exactly as before.

```go
client, err := builder.SDK(appKey, siastorage.WithAgentHooks(siastorage.AgentHooks{
	OnUploadComplete: func(ev siastorage.UploadCompleteEvent) {
		log.Printf("uploaded %s: %d bytes in %s", ev.ObjectID, ev.Size, ev.Elapsed)
	},
	OnDownloadComplete: func(ev siastorage.DownloadCompleteEvent) {
		log.Printf("downloaded %s: %d bytes", ev.ObjectID, ev.Bytes)
	},
	OnWriteFailed: func(ev siastorage.WriteFailedEvent) {
		switch ev.Stage {
		case siastorage.WriteNotSent:
			// no object data left the process; retry when ready
		case siastorage.WriteSentNotRegistered:
			// shards may be on hosts, but no object exists; retry with a new Object
		case siastorage.WritePinFailed:
			// data uploaded but the object was not saved; call PinObject again
		}
		log.Printf("write failed (%s): %v", ev.Stage, ev.Err)
	},
}))
```

- `OnUploadComplete` runs after `Upload` returns nil. The object is not tracked by the indexer until `PinObject` succeeds.
- `OnDownloadComplete` runs when a reader returned by `Download` has delivered its last byte. A reader closed early or ending in an error does not call it.
- `OnWriteFailed` runs when `Upload` or `PinObject` returns an error. `Stage` tells a write that never left the process (`WriteNotSent`, no shard write started) from one that sent data but was not registered (`WriteSentNotRegistered`), and from a failed pin (`WritePinFailed`). `WriteAttemptsStarted`, `ShardsAcknowledged` and `SlabsPinned` give the counts behind the stage.

Hooks are fire-and-forget. Each call runs in its own goroutine, the SDK does not wait for it, and a panic inside a hook is recovered and logged without changing the result of the transfer. `UploadPacked` and `DownloadSharedObject` do not call the hooks; packed objects still report pin failures through `PinObject`.

### Agent metadata

`SetAgentMetadata` records which agent wrote an object, under the `agent` key of the object's metadata. The metadata is encrypted with the rest of the object metadata when the object is sealed, so the indexer never sees it in plaintext. Other metadata keys are kept unchanged.

```go
obj := siastorage.NewEmptyObject()
if err := client.Upload(ctx, &obj, f); err != nil {
	log.Fatal(err)
}
if err := obj.SetAgentMetadata(siastorage.AgentMetadata{
	Name:   "nightly-exporter",
	Run:    runID,
	Task:   "export orders table",
	Labels: map[string]string{"env": "prod"},
}); err != nil {
	log.Fatal(err)
}
if err := client.PinObject(ctx, obj); err != nil { // saves the metadata
	log.Fatal(err)
}

// later
meta, ok, err := obj.AgentMetadata()
```

`SetAgentMetadata` returns `ErrMetadataNotObject` and leaves the metadata unchanged if the existing metadata is not a JSON object.

## Indexer application client

`NewAppClient` is the indexer application client. It embeds the public `go.sia.tech/indexd/api/app` client and adds `ObjectHosts`.

```go
api := siastorage.NewAppClient("https://index.tessera.storage")
hosts, err := api.ObjectHosts(ctx, appKey, objectID) // GET /objects/:key/hosts
```

`Account`, `Hosts`, and the other application methods are the embedded public client. A non-2xx response from `ObjectHosts` is a `*app.HTTPError` from `go.sia.tech/indexd/api/app`.

Shared indexer types come from public `go.sia.tech/indexd` `v0.4.3-0.20260811102619-b064dc9575d1`.

## Packed uploads

When uploading many small objects, `UploadPacked` combines them into shared slabs to reduce overhead:

```go
packed, err := client.UploadPacked()
if err != nil {
	log.Fatal("failed to create packed upload:", err)
}
defer packed.Close()

for _, data := range smallObjects {
	if _, err := packed.Add(ctx, bytes.NewReader(data)); err != nil {
		log.Fatal("failed to add object:", err)
	}
}

objects, err := packed.Finalize(ctx)
if err != nil {
	log.Fatal("failed to finalize:", err)
}

// pin and download each object individually
for _, obj := range objects {
	client.PinObject(ctx, obj)
}
```

### Optimizing packed uploads

Use `Remaining()` and `Length()` to monitor padding and decide when to finalize:

```go
const paddingTarget = 0.05

for len(uploads) > 0 {
	packed, err := client.UploadPacked()
	if err != nil {
		log.Fatal(err)
	}

	for len(uploads) > 0 {
		if _, err := packed.Add(ctx, bytes.NewReader(uploads[0])); err != nil {
			log.Fatal(err)
		}
		uploads = uploads[1:]

		if packed.Length() == 0 {
			continue
		}
		if float64(packed.Remaining())/float64(packed.Length()) <= paddingTarget {
			break
		}
	}

	objects, err := packed.Finalize(ctx)
	if err != nil {
		log.Fatal(err)
	}

	for _, obj := range objects {
		client.PinObject(ctx, obj)
	}
	packed.Close()
}
```

### Limitations

- `PackedUpload` is not thread-safe; do not call `Add` concurrently
- Empty objects are not supported and will return `ErrEmptyObject`
- Once `Finalize` is called, subsequent `Add` calls return `ErrUploadFinalized`

## Sharing objects

Objects can be shared via time-limited URLs:

```go
url, err := client.CreateSharedObjectURL(ctx, obj.ID(), time.Now().Add(24*time.Hour))
if err != nil {
	log.Fatal("failed to create shared URL:", err)
}

// anyone with the URL can download the object
var buf bytes.Buffer
rc, err := client.DownloadSharedObject(ctx, url)
if err != nil {
	log.Fatal("failed to download shared object:", err)
}
defer rc.Close()

if _, err := io.Copy(&buf, rc); err != nil {
	log.Fatal("failed to download shared object:", err)
}
```
