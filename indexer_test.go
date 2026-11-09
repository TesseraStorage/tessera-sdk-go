package siastorage

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.sia.tech/core/types"
	"go.sia.tech/indexd/api/app"
	"go.sia.tech/indexd/hosts"
)

func TestAppClientObjectHosts(t *testing.T) {
	appKey := types.GeneratePrivateKey()
	objectID := types.Hash256{4, 5, 6}
	want := types.GeneratePrivateKey().PublicKey()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/objects/"+objectID.String()+"/hosts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("sc") == "" || r.URL.Query().Get("ss") == "" || r.URL.Query().Get("sv") == "" {
			t.Errorf("missing signature query: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]hosts.HostInfo{{PublicKey: want}})
	}))
	defer srv.Close()

	got, err := NewAppClient(srv.URL).ObjectHosts(context.Background(), appKey, objectID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].PublicKey != want {
		t.Fatalf("hosts = %+v", got)
	}
}

func TestAppClientObjectHostsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "insufficient balance", http.StatusPaymentRequired)
	}))
	defer srv.Close()

	_, err := NewAppClient(srv.URL).ObjectHosts(context.Background(), types.GeneratePrivateKey(), types.Hash256{1})
	var he *app.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("err = %T %v, want *app.HTTPError", err, err)
	}
	if he.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status = %d", he.StatusCode)
	}
	if he.Body == "" {
		t.Fatal("empty body")
	}
}
