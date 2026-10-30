package registration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/registration"
)

// Registrars.Revocation refuses a registration whose registrar
// certificate is revoked, and is required: nil isn't "no check".
func TestRegistrars_Revocation(t *testing.T) {
	reg := newRegistrar(t)
	token, err := registration.Issue(shop(), reg.key, reg.chain)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range testcert.RevocationCases(t, reg.ca, reg.caKey, reg.chain[0]) {
		t.Run(c.Name, func(t *testing.T) {
			_, err := registration.Registrars{Roots: reg.roots, Revocation: c.Checker}.Verify(context.Background(), token, clientID, time.Now())
			if c.Checker == nil {
				if err == nil || !strings.Contains(err.Error(), "Revocation is required") {
					t.Fatalf("no Revocation: %v, want it refused", err)
				}
				return
			}
			c.Check(t, err)
		})
	}
	if _, err := (registration.Registrars{Roots: reg.roots, Revocation: certrevocation.CRLs{}}).Verify(context.Background(), token, clientID, time.Now()); err == nil {
		t.Error("CRLs without Lists accepted")
	}
	if _, err := (registration.Registrars{Roots: reg.roots, Revocation: certrevocation.NoCheck{}}).Verify(context.Background(), token, clientID, time.Now()); err != nil {
		t.Errorf("certrevocation.NoCheck{}: %v", err)
	}
}
