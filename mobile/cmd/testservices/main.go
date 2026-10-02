// Command testservices runs walletflowtest's HAIP issuer and Verifier,
// and a Wallet Provider with the passport-vdc demo's HTTP API, for
// driving the iOS demo wallet app end to end on the Simulator (see
// mobile/ios/DemoWallet). A control endpoint on -addr serves the app's
// configuration and fresh Credential Offers:
//
//	GET  /config                 → {"wallet": NewWallet config, "provider_url"}
//	POST /offer?pin=<digits>     → {"offer"}  (no pin: the authorization code grant)
//
// Every service is HTTPS with one self-signed certificate, written to
// -cert for the Simulator to trust (xcrun simctl keychain booted
// add-root-cert). It is test infrastructure: it attests anything, and its
// issuer approves every request at once.
package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"syscall"

	"github.com/idfoundry/oid4vcgo/mobile/internal/devjwk"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8600", "control endpoint address")
	redirect := flag.String("redirect", "org.idfoundry.oid4vcgo.demowallet:/callback", "the app's redirect URI, registered with the issuer")
	certOut := flag.String("cert", "", "write the services' TLS certificate here, as PEM")
	flag.Parse()
	if err := run(*addr, *redirect, *certOut); err != nil {
		log.Fatal(err)
	}
}

func run(addr, redirect, certOut string) error {
	env, err := walletflowtest.New(walletflowtest.Options{RedirectURIs: []string{redirect}})
	if err != nil {
		return err
	}
	defer env.Close()
	v, err := env.StartVerifier()
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.TLSCertificate.Raw})
	if certOut != "" {
		if err := os.WriteFile(certOut, certPEM, 0o600); err != nil {
			return err
		}
	}

	provider := httptest.NewTLSServer(providerHandler(env.Provider))
	defer provider.Close()

	config := map[string]any{
		"wallet": map[string]any{
			"client_id": walletflowtest.ClientID, "redirect_uri": redirect, "development": true,
			"issuer_roots":   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: env.IssuerCA.Raw})),
			"verifier_roots": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: v.CA.Raw})),
		},
		"provider_url": provider.URL,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /config", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, config) })
	mux.HandleFunc("POST /offer", func(w http.ResponseWriter, r *http.Request) {
		var offer string
		var err error
		if pin := r.URL.Query().Get("pin"); pin != "" {
			offer, err = env.PreAuthorizedOffer(pin, walletflowtest.SDJWTConfigurationID)
		} else {
			offer, err = env.AuthorizationCodeOffer(walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"offer": offer})
	})
	control := httptest.NewUnstartedServer(mux)
	if err := control.Listener.Close(); err != nil {
		return err
	}
	if control.Listener, err = netListen(addr); err != nil {
		return err
	}
	control.StartTLS()
	defer control.Close()

	fmt.Printf("test services: control %s, issuer %s, provider %s\n", control.URL, env.IssuerURL, provider.URL)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}

// providerHandler serves walletflowtest's Wallet Provider with the
// passport-vdc demo Wallet Provider's API (examples/passport-vdc/
// walletprovider): POST a JSON request, get {"attestation"}.
func providerHandler(p *walletflowtest.Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /wallet-attestation", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ClientID    string          `json:"client_id"`
			InstanceKey json.RawMessage `json:"instance_key"`
		}
		if !decode(w, r, &req) {
			return
		}
		key, err := devjwk.ParseP256(req.InstanceKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jwt, err := p.WalletAttestation(r.Context(), req.ClientID, key)
		writeAttestation(w, jwt, err)
	})
	mux.HandleFunc("POST /key-attestation", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Keys  json.RawMessage `json:"keys"`
			Nonce string          `json:"nonce"`
		}
		if !decode(w, r, &req) {
			return
		}
		keys, err := devjwk.ParseP256Set(req.Keys)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		jwt, err := p.KeyAttestation(r.Context(), keys, req.Nonce)
		writeAttestation(w, jwt, err)
	})
	return mux
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(v); err != nil {
		http.Error(w, "malformed request", http.StatusBadRequest)
		return false
	}
	return true
}

func writeAttestation(w http.ResponseWriter, jwt string, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"attestation": jwt})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func netListen(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }
