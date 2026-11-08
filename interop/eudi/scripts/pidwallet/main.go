// Command pidwallet obtains a credential from the EUDI reference PID
// Issuer for interop/eudi/run-pid-issuer.sh, with OID4VCgo's wallet
// package and fapigo/client (engine "core") or with walletflow
// (engine "walletflow"), and checks what it receives with the wallet's
// own verification: the credential's signature under the issuer's
// IACA, its holder binding, and its Token Status List entry.
//
// The core engine runs the authorization code flow — PAR with PKCE,
// DPoP, a Wallet Attestation with a challenged PoP at the PAR and token
// endpoints, the holder's sign-in on Keycloak's login page — then asks
// the Nonce Endpoint for a c_nonce and the Credential Endpoint for the
// credential, encrypted both ways as the issuer requires, with the
// proof -proof names:
//
//	attestation  a Key Attestation, as the attestation proof type (Appendix F.3)
//	jwt          a jwt proof whose key_attestation header carries one, its key named by kid "0",
//	             the index of its key among attested_keys, as ETSI TS 119 472-3 has it
//	jwk          the same, its key in jwk, as wallet.Wallet.GenerateProofWithKeyAttestation and
//	             walletflow make it
//	jwt-each     one jwt proof (kid "0") per key, each with a Key Attestation of its key alone
//
// -batch keys are attested, so the issuer issues one credential per
// key; a deferred credential is polled at the Deferred Credential
// Endpoint; a credential with a notification_id is acknowledged at the
// Notification Endpoint. With -revoke-api-key, the first credential's
// status list entry is then revoked at the status list service, and
// checked again.
//
// The result, written to -out as JSON, says how far the run got and
// what it saw; the script decides whether that's what the case
// expects. Usage: see run-pid-issuer.sh.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

// options are the command line.
type options struct {
	work, out               string
	engine                  string
	issuer, configID, offer string
	proof                   string
	batch                   int
	clientID, redirectURI   string
	user, password          string
	metadataRoots           string
	issuerRoots             string
	walletStatusIdx         int
	keyStorageStatusIdx     int
	revokeAPIKey            string
}

// result is what the run reports.
type result struct {
	Engine        string `json:"engine"`
	Configuration string `json:"configuration"`
	Proof         string `json:"proof,omitempty"`
	// OK is set when every step succeeded; otherwise Step is the one
	// that failed and Error why.
	OK    bool   `json:"ok"`
	Step  string `json:"step,omitempty"`
	Error string `json:"error,omitempty"`

	SignedMetadata bool `json:"signed_metadata"`
	IssuerState    bool `json:"issuer_state"`
	// OfferAuthorizationServer is the authorization_server the offer's
	// authorization_code grant names, and AuthorizationServers how many
	// the metadata lists.
	OfferAuthorizationServer string `json:"offer_authorization_server,omitempty"`
	AuthorizationServers     int    `json:"authorization_servers"`
	TokenType                string `json:"token_type,omitempty"`
	// Challenges counts the Attestation Challenges fetched; DPoPNonces
	// the responses that handed out a DPoP-Nonce, and DPoPNonceRetries
	// those that refused a request for want of one (use_dpop_nonce).
	Challenges        int  `json:"attestation_challenges"`
	DPoPNonces        int  `json:"dpop_nonces"`
	DPoPNonceRetries  int  `json:"dpop_nonce_retries"`
	EncryptedRequest  bool `json:"encrypted_request"`
	EncryptedResponse bool `json:"encrypted_response"`
	Deferred          bool `json:"deferred"`
	DeferredPolls     int  `json:"deferred_polls,omitempty"`
	Notified          bool `json:"notified"`

	Credentials []credentialReport `json:"credentials,omitempty"`
	// StatusAfterRevoke is the first credential's status once revoked.
	StatusAfterRevoke string `json:"status_after_revoke,omitempty"`

	Exchanges []exchange `json:"exchanges"`
}

// credentialReport is what the wallet's checks found of one credential.
type credentialReport struct {
	Format string `json:"format"`
	// Verified is set once the credential passed the wallet's checks;
	// otherwise VerifyError says why it didn't.
	Verified    bool     `json:"verified"`
	VerifyError string   `json:"verify_error,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	Signer      string   `json:"signer,omitempty"`
	Claims      []string `json:"claims,omitempty"`
	ValidUntil  string   `json:"valid_until,omitempty"`
	StatusURI   string   `json:"status_uri,omitempty"`
	StatusIdx   uint64   `json:"status_idx,omitempty"`
	Status      string   `json:"status,omitempty"`
	StatusError string   `json:"status_error,omitempty"`
}

func main() {
	var o options
	flag.StringVar(&o.work, "work", "", "the directory pidsetup wrote")
	flag.StringVar(&o.out, "out", "", "the file to write the result to")
	flag.StringVar(&o.engine, "engine", "core", "core (wallet and fapigo/client) or walletflow")
	flag.StringVar(&o.issuer, "issuer", "", "the Credential Issuer Identifier, for a wallet-initiated issuance")
	flag.StringVar(&o.configID, "config", "", "the credential configuration to request, for a wallet-initiated issuance")
	flag.StringVar(&o.offer, "offer", "", "a Credential Offer link, for an issuer-initiated issuance")
	flag.StringVar(&o.proof, "proof", "jwt", "attestation, jwt (kid 0), jwk or jwt-each")
	flag.IntVar(&o.batch, "batch", 1, "how many keys to attest, so how many credentials to ask for")
	flag.StringVar(&o.clientID, "client-id", "eudiw-abca", "the wallet's client_id")
	flag.StringVar(&o.redirectURI, "redirect-uri", "", "the wallet's redirect URI")
	flag.StringVar(&o.user, "user", "tneal", "the holder's username at the Authorization Server")
	flag.StringVar(&o.password, "password", "password", "the holder's password")
	flag.StringVar(&o.metadataRoots, "metadata-roots", "metadata-ca.pem", "the CA the wallet trusts for signed metadata, in -work")
	flag.StringVar(&o.issuerRoots, "issuer-roots", "iaca.pem", "the CA the wallet trusts for credentials, in -work")
	flag.IntVar(&o.walletStatusIdx, "wallet-status-idx", 0, "the Wallet Attestation's client_status index (1 is revoked)")
	flag.IntVar(&o.keyStorageStatusIdx, "key-storage-status-idx", 0, "the Key Attestation's key_storage_status index (1 is revoked)")
	flag.StringVar(&o.revokeAPIKey, "revoke-api-key", "", "the status list service's API key: revoke the first credential, and check it again")
	flag.Parse()
	if o.work == "" || o.out == "" || o.redirectURI == "" || (o.offer == "") == (o.issuer == "" || o.configID == "") {
		fmt.Fprintln(os.Stderr, "pidwallet: -work, -out, -redirect-uri, and either -offer or -issuer and -config are required")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	res := run(ctx, o)
	raw, err := json.MarshalIndent(res, "", "  ")
	if err == nil {
		err = os.WriteFile(o.out, raw, 0o644) // #nosec G306 -- holds no key or credential
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pidwallet:", err)
		os.Exit(2)
	}
	if !res.OK {
		os.Exit(1)
	}
}

// run runs the engine o names.
func run(ctx context.Context, o options) result {
	res := result{Engine: o.engine, Configuration: o.configID, Proof: o.proof}
	env, err := newEnvironment(o)
	if err != nil {
		res.Step, res.Error = "setup", err.Error()
		return res
	}
	switch o.engine {
	case "core":
		runCore(ctx, env, &res)
	case "walletflow":
		runWalletflow(ctx, env, &res)
	default:
		res.Step, res.Error = "setup", "unknown -engine "+o.engine
	}
	env.summarize(&res)
	res.Exchanges = env.rec.recorded()
	return res
}

// fail records the step that failed, and why.
func (r *result) fail(step string, err error) {
	r.Step, r.Error = step, err.Error()
}
