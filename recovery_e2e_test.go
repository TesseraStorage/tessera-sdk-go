package siastorage_test

// SDK-level recovery end-to-end: the same (phrase, app id, connect key)
// re-registration must yield the same app key AND the same pinned file, with
// a real indexd test cluster (real app API, real slab/contract machinery,
// in-memory hosts).
//
// This is the storage-identity core of the seed-phrase recovery fix: the
// recovery phrase alone cannot rebuild the key (it also needs the server-side
// app id and shared secret), so a recovered client must re-run the connect
// approval with the account's original app id and its connect key. The
// moneyd endpoint that hands those values to an authenticated session is
// covered by dataplane/moneyd/tests/test_recovery.py; this test proves the
// client side of that contract produces the same identity and sees the same
// file.

import (
	"bytes"
	"io"
	"testing"

	"github.com/TesseraStorage/tessera-sdk-go"
	proto "go.sia.tech/core/rhp/v4"
	"go.sia.tech/indexd/accounts"
	"go.sia.tech/indexd/slabs"
	"go.sia.tech/indexd/testutils"
	"go.uber.org/zap/zaptest"
)

func TestRecoveryRestoresSameIdentityAndFile(t *testing.T) {
	log := zaptest.NewLogger(t)
	ms := testutils.MaintenanceSettings
	ms.WantedContracts = 15
	cluster := testutils.NewCluster(t,
		testutils.WithHosts(15),
		testutils.WithLogger(log.Named("cluster")),
		testutils.WithIndexer(testutils.WithMaintenanceSettings(ms)),
	)
	cluster.WaitForContracts(t)

	connectKey, err := cluster.Indexer.Admin.AddAppConnectKey(t.Context(), accounts.AppConnectKeyRequest{
		Description: "recovery e2e",
		Quota:       "default",
	})
	if err != nil {
		t.Fatal("failed to add app connect key:", err)
	}

	// ── PC 1: first registration + upload + pin ──
	appID := siastorage.GenerateAppID()
	phrase := siastorage.NewSeedPhrase()

	builder := siastorage.NewBuilder(cluster.Indexer.AppURL, siastorage.AppMetadata{
		ID:          appID,
		Name:        "Tessera",
		Description: "Tessera storage client",
		ServiceURL:  cluster.Indexer.AppURL,
	})
	responseURL, err := builder.RequestConnection(t.Context())
	if err != nil {
		t.Fatal("request connection:", err)
	}
	respondToAppConnection(t, responseURL, connectKey.Key, true)
	if err := builder.WaitForApproval(t.Context()); err != nil {
		t.Fatal("wait for approval:", err)
	}
	client, err := builder.Register(t.Context(), phrase)
	if err != nil {
		t.Fatal("register:", err)
	}
	defer client.Close()
	appKey1 := client.AppKey()

	// host writes require the account to be funded (and, on pool-capable
	// hosts, its pool attached) first
	cluster.WaitForAccountFunding(t, proto.Account(appKey1.PublicKey()))

	data := []byte("recovery e2e file contents")
	obj := siastorage.NewEmptyObject()
	obj.UpdateMetadata([]byte(`{"name":"proof.txt"}`))
	if err := client.Upload(t.Context(), &obj, bytes.NewReader(data), siastorage.WithRedundancy(4, 10)); err != nil {
		t.Fatal("upload:", err)
	}
	if err := client.PinObject(t.Context(), obj); err != nil {
		t.Fatal("pin:", err)
	}

	// ── PC 2: recovery from the phrase + the account's original app id and
	// connect key (exactly what moneyd's recovery endpoint returns) ──
	builder2 := siastorage.NewBuilder(cluster.Indexer.AppURL, siastorage.AppMetadata{
		ID:          appID,
		Name:        "Tessera",
		Description: "Tessera storage client",
		ServiceURL:  cluster.Indexer.AppURL,
	})
	responseURL, err = builder2.RequestConnection(t.Context())
	if err != nil {
		t.Fatal("request connection:", err)
	}
	respondToAppConnection(t, responseURL, connectKey.Key, true)
	if err := builder2.WaitForApproval(t.Context()); err != nil {
		t.Fatal("wait for approval:", err)
	}
	client2, err := builder2.Register(t.Context(), phrase)
	if err != nil {
		t.Fatal("re-register:", err)
	}
	defer client2.Close()
	appKey2 := client2.AppKey()

	if !bytes.Equal(appKey1, appKey2) {
		t.Fatal("recovered app key does not match the original")
	}

	// The recovered identity must see the pinned file.
	events, err := client2.ObjectEvents(t.Context(), slabs.Cursor{}, 10)
	if err != nil {
		t.Fatal("object events:", err)
	}
	if len(events) == 0 {
		t.Fatal("recovered identity sees no objects")
	}
	found := false
	for _, ev := range events {
		if ev.Object == nil {
			continue
		}
		rc, err := client2.Download(*ev.Object)
		if err != nil {
			t.Fatal("download:", err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal("read download:", err)
		}
		if bytes.Equal(got, data) {
			found = true
		}
	}
	if !found {
		t.Fatal("recovered identity could not download the uploaded file")
	}

	// A wrong phrase must NOT produce the account key: it derives a different
	// app key, which the CLI refuses before persisting.
	wrongPhrase := siastorage.NewSeedPhrase()
	if wrongPhrase == phrase {
		t.Fatal("generated identical wrong phrase") // astronomically unlikely
	}
	builder3 := siastorage.NewBuilder(cluster.Indexer.AppURL, siastorage.AppMetadata{
		ID:          appID,
		Name:        "Tessera",
		Description: "Tessera storage client",
		ServiceURL:  cluster.Indexer.AppURL,
	})
	responseURL, err = builder3.RequestConnection(t.Context())
	if err != nil {
		t.Fatal("request connection:", err)
	}
	respondToAppConnection(t, responseURL, connectKey.Key, true)
	if err := builder3.WaitForApproval(t.Context()); err != nil {
		t.Fatal("wait for approval:", err)
	}
	client3, err := builder3.Register(t.Context(), wrongPhrase)
	if err != nil {
		t.Fatal("re-register with wrong phrase:", err)
	}
	defer client3.Close()
	if bytes.Equal(client3.AppKey(), appKey1) {
		t.Fatal("a different phrase derived the same app key")
	}
	events3, err := client3.ObjectEvents(t.Context(), slabs.Cursor{}, 10)
	if err != nil {
		t.Fatal("object events for wrong-phrase identity:", err)
	}
	if len(events3) != 0 {
		t.Fatal("wrong-phrase identity sees the account's objects")
	}
}
