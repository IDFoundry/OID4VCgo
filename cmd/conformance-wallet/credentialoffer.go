package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/conformancesuite"
)

// credentialOfferPath is appended to -credential-offer-endpoint to
// build this run's own vci.credential_offer_endpoint config value.
// Arbitrary — see that flag's own doc comment for why this endpoint
// never actually needs to be reachable at all.
const credentialOfferPath = "/credential_offer" //nolint:gosec // an OID4VCI wire path name, not a credential

// waitForCredentialOfferRedirectURL polls GET /api/log/{moduleID}
// until a "Created credential offer redirect url" log entry appears
// (VCICreateCredentialOfferRedirectUrl.java), returning its own
// credential_offer_redirect_url field — the exact URL the suite's
// AbstractVCIWalletTest.prepareCredentialOffer built and (for a
// domain with no matching "browser" automation entry in this run's
// own plan config, which this binary doesn't supply) merely queued
// for a browser to visit, never blocking on it.
//
// That queuing turns out to be exactly why no inbound HTTP listener
// is needed at all, despite this flow variant's own name suggesting
// the suite must call back into this binary: prepareCredentialOffer()
// returns immediately after queuing (BrowserControl.goToUrl's own
// "no match" branch never blocks), so the module reaches WAITING
// right away regardless of whether vci.credential_offer_endpoint is
// ever actually visited — confirmed live by creating a module with a
// syntactically-valid but entirely unreachable credential_offer_endpoint
// and observing it reach WAITING immediately, with the fully-resolved
// offer (including issuer_state) already sitting in its own log. This
// binary only needs the *string value* of that URL — decodeable
// directly by wallet.Wallet.ResolveCredentialOffer without ever
// dereferencing it — not an actual round trip through it.
func waitForCredentialOfferRedirectURL(httpClient *http.Client, apiBase, moduleID string, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for {
		req, err := http.NewRequest(http.MethodGet, apiBase+"api/log/"+moduleID, nil)
		if err != nil {
			return "", err
		}
		body, status, err := conformancesuite.Do(httpClient, req)
		if err != nil {
			return "", err
		}
		if status == http.StatusOK {
			var entries []map[string]json.RawMessage
			if err := json.Unmarshal(body, &entries); err == nil {
				for _, e := range entries {
					raw, ok := e["credential_offer_redirect_url"]
					if !ok {
						continue
					}
					var url string
					if err := json.Unmarshal(raw, &url); err == nil && url != "" {
						return url, nil
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("module %s did not log a credential offer redirect url within %s", moduleID, timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
