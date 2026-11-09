// Package objecthosts fetches the hosts storing an object.
//
// Upstream go.sia.tech/indexd/api/app does not call GET /objects/:key/hosts.
// The request is signed the same way as the other application API calls:
// query parameters sc, ss, and sv over a hash of the method, host, path, and
// expiration.
package objecthosts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/indexd/hosts"
)

const applicationJSON = "application/json"

// StatusError is a non-2xx response from the indexer.
type StatusError struct {
	StatusCode int
	Body       string
}

func (e *StatusError) Error() string {
	msg := e.Body
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	if msg == "" {
		return fmt.Sprintf("HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, msg)
}

// Fetch calls GET /objects/:key/hosts and decodes the host list.
// validity is how long the signed URL remains acceptable to the indexer.
func Fetch(ctx context.Context, baseURL string, appKey types.PrivateKey, objectID types.Hash256, validity time.Duration) ([]hosts.HostInfo, error) {
	if validity <= 0 {
		return nil, errors.New("object host request validity must be positive")
	}
	route := fmt.Sprintf("/objects/%s/hosts", objectID)
	signed, body, err := sign(appKey, time.Now().Add(validity), http.MethodGet, baseURL+route, nil)
	if err != nil {
		return nil, err
	}
	rc, err := doRequest(ctx, http.MethodGet, signed, body, applicationJSON)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	var resp []hosts.HostInfo
	if err := json.NewDecoder(rc).Decode(&resp); err != nil {
		return nil, fmt.Errorf("failed to decode object hosts: %w", err)
	}
	return resp, nil
}

func sign(appKey types.PrivateKey, validUntil time.Time, method, endpointURL string, requestBuf []byte) (*url.URL, io.Reader, error) {
	u, err := url.Parse(endpointURL)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	sigHash := requestHash(method, u.Host, u.Path, validUntil, requestBuf)

	val := url.Values{}
	val.Set("sv", fmt.Sprint(validUntil.Unix()))
	pk := appKey.PublicKey()
	val.Set("sc", base64.URLEncoding.EncodeToString(pk[:]))
	sig := appKey.SignHash(sigHash)
	val.Set("ss", base64.URLEncoding.EncodeToString(sig[:]))

	q := u.Query()
	for k, v := range val {
		for _, s := range v {
			q.Add(k, s)
		}
	}
	u.RawQuery = q.Encode()

	var body io.Reader = http.NoBody
	if requestBuf != nil {
		body = bytes.NewReader(requestBuf)
	}
	return u, body, nil
}

func requestHash(method, hostname, path string, validUntil time.Time, body []byte) types.Hash256 {
	h := types.NewHasher()
	h.E.Write([]byte(method))
	h.E.Write([]byte(hostname))
	h.E.Write([]byte(path))
	h.E.WriteUint64(uint64(validUntil.Unix()))
	if body != nil {
		h.E.Write(body)
	}
	return h.Sum()
}

func doRequest(ctx context.Context, method string, u *url.URL, body io.Reader, accept string) (io.ReadCloser, error) {
	if u == nil {
		return nil, errors.New("nil URL")
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", accept)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, &StatusError{StatusCode: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if contentType := resp.Header.Get("Content-Type"); resp.StatusCode != http.StatusNoContent && accept != contentType {
		defer resp.Body.Close()
		return nil, fmt.Errorf("expected content type %s, got %s", accept, contentType)
	}
	return resp.Body, nil
}
