package siastorage_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/TesseraStorage/tessera-sdk-go"
	proto "go.sia.tech/core/rhp/v4"
	"go.sia.tech/indexd/accounts"
	"go.sia.tech/indexd/testutils"
	"go.uber.org/zap/zaptest"
)

// TestAgentHooksEndToEnd runs the upload and write-failed hooks and agent
// metadata against a real indexd test cluster with in-memory hosts.
func TestAgentHooksEndToEnd(t *testing.T) {
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
		Description: "agent hooks e2e",
		Quota:       "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	meta := siastorage.AppMetadata{
		ID:          siastorage.GenerateAppID(),
		Name:        "Tessera",
		Description: "Tessera storage client",
		ServiceURL:  cluster.Indexer.AppURL,
	}
	builder := siastorage.NewBuilder(cluster.Indexer.AppURL, meta)
	responseURL, err := builder.RequestConnection(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	respondToAppConnection(t, responseURL, connectKey.Key, true)
	if err := builder.WaitForApproval(t.Context()); err != nil {
		t.Fatal(err)
	}
	registered, err := builder.Register(t.Context(), siastorage.NewSeedPhrase())
	if err != nil {
		t.Fatal(err)
	}
	appKey := registered.AppKey()
	registered.Close()
	cluster.WaitForAccountFunding(t, proto.Account(appKey.PublicKey()))

	uploads := make(chan siastorage.UploadCompleteEvent, 1)
	failures := make(chan siastorage.WriteFailedEvent, 1)
	client, err := siastorage.NewBuilder(cluster.Indexer.AppURL, meta).SDK(appKey, siastorage.WithAgentHooks(siastorage.AgentHooks{
		OnUploadComplete: func(ev siastorage.UploadCompleteEvent) { uploads <- ev },
		OnWriteFailed:    func(ev siastorage.WriteFailedEvent) { failures <- ev },
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	data := []byte("agent hooks e2e file contents")
	obj := siastorage.NewEmptyObject()
	obj.UpdateMetadata([]byte(`{"name":"agent.txt"}`))
	if err := client.Upload(t.Context(), &obj, bytes.NewReader(data), siastorage.WithRedundancy(4, 10)); err != nil {
		t.Fatal("upload:", err)
	}
	select {
	case ev := <-uploads:
		if ev.ObjectID != obj.ID() || ev.Size != uint64(len(data)) || ev.ShardsAcknowledged != 14 {
			t.Fatalf("unexpected upload event %+v", ev)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OnUploadComplete was not called")
	}

	if err := obj.SetAgentMetadata(siastorage.AgentMetadata{Name: "e2e-agent", Run: "run-1", Task: "store proof"}); err != nil {
		t.Fatal(err)
	}
	if err := client.PinObject(t.Context(), obj); err != nil {
		t.Fatal("pin:", err)
	}

	// the indexer returns the object with the encrypted metadata intact
	fetched, err := client.Object(t.Context(), obj.ID())
	if err != nil {
		t.Fatal(err)
	}
	agent, ok, err := fetched.AgentMetadata()
	if err != nil || !ok || agent.Name != "e2e-agent" || agent.Run != "run-1" || agent.Task != "store proof" {
		t.Fatalf("unexpected agent metadata %+v %v %v", agent, ok, err)
	}
	if !bytes.Contains(fetched.Metadata(), []byte(`"name":"agent.txt"`)) {
		t.Fatalf("existing metadata lost: %s", fetched.Metadata())
	}

	// Download is not exercised here: the public indexd test cluster does
	// not serve GET /objects/:key/hosts, which Download needs. The download
	// hook is covered by the mock tests in hooks_test.go.

	select {
	case ev := <-failures:
		t.Fatalf("unexpected failure event %+v", ev)
	case <-time.After(200 * time.Millisecond):
	}
}
