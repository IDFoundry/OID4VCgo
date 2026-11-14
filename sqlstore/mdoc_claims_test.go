package sqlstore_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// walletflow stores an mdoc's claims as its CBOR decoded them: an
// element whose value is a map (an EUDI PID's place_of_birth, an mDL's
// driving_privileges entries) is a map[interface{}]interface{}, which
// encoding/json refused before Go 1.27. The CredentialStore keeps such a
// credential, with its maps keyed by text.
func TestCredentialStoreKeepsMdocMapClaims(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		c := walletflow.StoredCredential{
			ID: "mdoc", CredentialIssuer: "https://issuer.example", ConfigurationID: "pid", Format: "mso_mdoc",
			DocType: "eu.europa.ec.eudi.pid.1", Credential: "AA", HolderKeyID: "k", ReceivedAt: time.Now().UTC(),
			Claims: map[string]any{"eu.europa.ec.eudi.pid.1": map[string]any{
				"place_of_birth":     map[any]any{"country": "FR", "locality": "Paris"},
				"driving_privileges": []any{map[any]any{"vehicle_category_code": "B", uint64(7): "x"}},
			}},
		}
		store := e.db().Credentials()
		if err := store.Put(ctx, c); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := store.Get(ctx, "mdoc")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		ns, _ := got.Claims["eu.europa.ec.eudi.pid.1"].(map[string]any)
		place, _ := ns["place_of_birth"].(map[string]any)
		if place["country"] != "FR" || place["locality"] != "Paris" {
			t.Errorf("place_of_birth = %v, want country FR, locality Paris", ns["place_of_birth"])
		}
		privileges, _ := ns["driving_privileges"].([]any)
		if len(privileges) != 1 {
			t.Fatalf("driving_privileges = %v, want one entry", ns["driving_privileges"])
		}
		if p, _ := privileges[0].(map[string]any); p["vehicle_category_code"] != "B" || p["7"] != "x" {
			t.Errorf("driving_privileges[0] = %v, want vehicle_category_code B, 7 x", privileges[0])
		}
		// The caller's claims are left as they were.
		if _, ok := c.Claims["eu.europa.ec.eudi.pid.1"].(map[string]any)["place_of_birth"].(map[any]any); !ok {
			t.Error("Put changed the caller's claims")
		}
	})
}
