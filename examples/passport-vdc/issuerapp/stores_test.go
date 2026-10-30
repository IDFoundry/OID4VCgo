package issuerapp_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// openTestDatabase opens the database in dir, its key beside it, and
// returns the option setting it as Config.Database.
func openTestDatabase(t *testing.T, dir string) func(*issuerapp.Config) {
	t.Helper()
	db, sealer, err := issuerapp.OpenDatabase(filepath.Join(dir, "stores.db"), filepath.Join(dir, "stores.key"))
	if err != nil {
		t.Fatalf("OpenDatabase: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return func(cfg *issuerapp.Config) { cfg.Database, cfg.DatabaseSealer = db, sealer }
}

// countRows are the queries rows runs.
var countRows = map[string]string{
	"fapigo_authorization_codes": "SELECT COUNT(*) FROM fapigo_authorization_codes",
	"fapigo_replay":              "SELECT COUNT(*) FROM fapigo_replay",
	"fapigo_rs_dpop_nonces":      "SELECT COUNT(*) FROM fapigo_rs_dpop_nonces",
}

// rows counts table's rows in the SQLite database in dir.
func rows(t *testing.T, dir, table string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "stores.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var n int
	if err := db.QueryRowContext(context.Background(), countRows[table]).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// With Config.Database, the Authorization Server's stores
// (fapigo/sqlstore) and the Credential Issuer's (oid4vcgo/sqlstore)
// share one SQLite database, sealed under one key: a whole issuance
// runs over them, and an issuer started again on the same database and
// key starts.
func TestEndToEnd_DatabaseStores(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	env := demotest.New(t, nil, openTestDatabase(t, dir))

	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if len(received) != 2 {
		t.Fatalf("received %d credentials, want one per format", len(received))
	}
	// The redeemed code, the proofs seen and the Credential Endpoint's
	// DPoP nonce are kept until they expire.
	for table := range countRows {
		if rows(t, dir, table) == 0 {
			t.Errorf("%s is empty", table)
		}
	}
	env.Issuer.Sweep()

	info, err := os.Stat(filepath.Join(dir, "stores.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("stores.key mode = %v, want 0600", info.Mode().Perm())
	}
	demotest.New(t, nil, openTestDatabase(t, dir)) // the same key, read back
}

func TestNew_DatabaseRequiresSealer(t *testing.T) {
	db, _, err := issuerapp.OpenDatabase(filepath.Join(t.TempDir(), "stores.db"), filepath.Join(t.TempDir(), "stores.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := issuerapp.New(issuerapp.Config{
		IssuerURL: "https://127.0.0.1:8543", CSCAPool: &cms.GenericCertPool{},
		Wallet: issuerapp.WalletClient{
			ClientID: demotest.WalletClientID, RedirectURIs: []string{demotest.RedirectURI},
			ProviderIssuer: demotest.ProviderIssuer, ProviderCA: []byte("unused"),
		},
		Database: db,
	}); err == nil {
		t.Fatal("New accepted a Database without a DatabaseSealer")
	}
}
