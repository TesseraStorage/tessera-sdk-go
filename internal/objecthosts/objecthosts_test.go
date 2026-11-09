package objecthosts

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"go.sia.tech/core/types"
	"go.sia.tech/indexd/hosts"
)

func TestFetchSignsObjectHosts(t *testing.T) {
	appKey := types.GeneratePrivateKey()
	objectID := types.Hash256{9, 8, 7}
	wantKey := types.GeneratePrivateKey().PublicKey()

	var gotPath, gotAccept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAccept = r.Header.Get("Accept")
		if r.Method != http.MethodGet {
			t.Errorf("method = %s", r.Method)
		}
		q := r.URL.Query()
		var pk types.PublicKey
		if _, err := base64.URLEncoding.Decode(pk[:], []byte(q.Get("sc"))); err != nil {
			t.Errorf("credential: %v", err)
		} else if pk != appKey.PublicKey() {
			t.Errorf("credential = %v, want app key", pk)
		}
		var sig types.Signature
		if _, err := base64.URLEncoding.Decode(sig[:], []byte(q.Get("ss"))); err != nil {
			t.Errorf("signature: %v", err)
		}
		unix, err := strconv.ParseInt(q.Get("sv"), 10, 64)
		if err != nil {
			t.Errorf("expiry: %v", err)
		}
		hash := requestHash(r.Method, r.Host, r.URL.Path, time.Unix(unix, 0), nil)
		if !pk.VerifyHash(hash, sig) {
			t.Error("signature did not verify")
		}
		if unix < time.Now().Unix() {
			t.Error("signed URL is already expired")
		}

		w.Header().Set("Content-Type", applicationJSON)
		_ = json.NewEncoder(w).Encode([]hosts.HostInfo{{
			PublicKey:     wantKey,
			GoodForUpload: false,
		}})
	}))
	defer srv.Close()

	got, err := Fetch(context.Background(), srv.URL, appKey, objectID, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/objects/"+objectID.String()+"/hosts" {
		t.Fatalf("path = %s", gotPath)
	}
	if gotAccept != applicationJSON {
		t.Fatalf("Accept = %s", gotAccept)
	}
	if len(got) != 1 || got[0].PublicKey != wantKey || got[0].GoodForUpload {
		t.Fatalf("hosts = %+v", got)
	}
}

func TestFetchStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		http.Error(w, "insufficient balance", http.StatusPaymentRequired)
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), srv.URL, types.GeneratePrivateKey(), types.Hash256{1}, time.Minute)
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want StatusError", err)
	}
	if se.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status = %d", se.StatusCode)
	}
	if se.Body == "" {
		t.Fatal("empty body")
	}
}
