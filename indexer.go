package siastorage

import (
	"context"
	"errors"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/indexd/api/app"
	"go.sia.tech/indexd/hosts"

	"github.com/TesseraStorage/tessera-sdk-go/internal/objecthosts"
)

// appRequestValidity is how long a signed application request stays valid.
// It matches the default used by go.sia.tech/indexd/api/app.
const appRequestValidity = 10 * time.Minute

// AppClient is an HTTP client for the Tessera indexer application API.
//
// It embeds the public [app.Client] and adds [AppClient.ObjectHosts],
// GET /objects/:key/hosts. That call is not part of the public indexd client.
// The embedded methods (Account, Hosts, and the connection flow) are unchanged.
type AppClient struct {
	*app.Client

	baseURL  string
	validity time.Duration
}

// NewAppClient returns a client for indexerURL, for example
// "https://index.tessera.storage".
func NewAppClient(indexerURL string) *AppClient {
	return &AppClient{
		Client:   app.NewClient(indexerURL),
		baseURL:  indexerURL,
		validity: appRequestValidity,
	}
}

// ObjectHosts returns the hosts currently storing the object's shards
// (GET /objects/:key/hosts). The list includes hosts that are not marked
// usable for new uploads. A non-2xx response is an [*app.HTTPError].
func (c *AppClient) ObjectHosts(ctx context.Context, appKey types.PrivateKey, objectID types.Hash256) ([]hosts.HostInfo, error) {
	if c == nil {
		return nil, errors.New("nil app client")
	}
	list, err := objecthosts.Fetch(ctx, c.baseURL, appKey, objectID, c.validity)
	var se *objecthosts.StatusError
	if errors.As(err, &se) {
		return nil, &app.HTTPError{StatusCode: se.StatusCode, Body: se.Body}
	}
	return list, err
}
