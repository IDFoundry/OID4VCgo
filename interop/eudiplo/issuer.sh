# Sourced by run.sh, after the Verifier's cases: EUDIPLO's Credential
# Issuer, to OID4VCgo's wallet (walletflow), attested by the second
# instance of OID4VCgo's Wallet Provider ($EWP_PORT), which EUDIPLO's
# trust list names as a wallet provider. EUDIPLO's built-in
# authorization server redeems pre-authorized codes, with a tx_code;
# Wallet Attestations and DPoP are required, and the attestations'
# status checked strictly on the provider's status lists, which EUDIPLO
# fetches through serve's second tap. Then controls, each refused for
# its reason: EUDIPLO's, or the wallet's own. See README.md.

echo "### EUDIPLO's issuer → OID4VCgo's wallet"
# The tenants (setup): the Verifier's, which issues too, and the one
# requiring encryption.
TENANT_ID="$(jq -r '.id | rtrimstr("-run")' client.json)" ENC_TENANT_ID="$(jq -r '.id | rtrimstr("-run")' enc-client.json)"
ENC_TOKEN="$(api -X POST "$E/api/oauth2/token" -d grant_type=client_credentials \
  --data-urlencode client_id="$(jq -r .id enc-client.json)" --data-urlencode client_secret="$(jq -r .secret enc-client.json)" | jq -r .access_token)"
TX=493536
REDIRECT=https://wallet.oid4vcgo.example/callback

# eoffer has the tenant whose token is $1 offer configuration $2, its
# pre-authorized code with the tx_code $3 or, with $3
# "authorization_code", for the authorization code flow; its answer
# ({uri, session}) is in $4-offer.json.
eoffer() {  # $1 token, $2 configuration, $3 tx_code or authorization_code, $4 name
  local token="$1" config="$2" code="$3" name="$4"
  api -X POST -H "Authorization: Bearer $token" -H "$JSON" --data "$(jq -cn --arg c "$config" --arg t "$code" '
    {response_type: "uri", credentialConfigurationIds: [$c]}
    + if $t == "authorization_code" then {flow: $t} else {flow: "pre_authorized_code", tx_code: $t} end')" \
    "$E/api/issuer/offer" > "$name-offer.json"
}
# ereceive has the tenant whose token is $1 offer configuration $3 (as
# eoffer, $4 its tx_code), and OID4VCgo's wallet redeem it, attested by
# the Wallet Provider EUDIPLO trusts, checking each credential's chain
# to EUDIPLO's CAs; the rest are the wallet's options (a later
# -wallet-provider replaces EUDIPLO's, a later -tx-code the offer's).
# Its outcome is in $2-wallet.json, its log in wallet-$2.log, the
# issuance session's state in $2-session.json.
EWP=(-wallet-provider "https://localhost:$EWP_PORT" -wallet-provider-tls wallet-provider-eudiplo/tls-cert.pem -client-id "$CLIENT_ID")
ereceive() {  # $1 token, $2 name, $3 configuration, $4 tx_code or authorization_code; then wallet flags
  local token="$1" name="$2" config="$3" code="$4" grant=(-tx-code "$4")
  shift 4
  eoffer "$token" "$config" "$code" "$name"
  if [[ "$code" = authorization_code ]]; then grant=(-redirect-uri "$REDIRECT"); fi
  eredeem "$name" "${grant[@]}" "$@"
  api -H "Authorization: Bearer $token" "$E/api/session/$(jq -r .session "$name-offer.json")" \
    | jq '{status, failureCode, errorReason}' > "$name-session.json"
}
# eredeem has the wallet redeem $1-offer.json's offer, as ereceive
# says; the rest are its options.
eredeem() {  # $1 name; then wallet flags
  local name="$1"
  shift
  ./wallet -tls-ca ca.pem -issuer-ca eudiplo-issuer-ca.pem -mdoc-issuer-ca eudiplo-iaca.pem -verifier-ca ca.pem -crl-set none \
    "${EWP[@]}" -offer "$(jq -r .uri "$name-offer.json")" -out "$name-wallet.json" "$@" >> "wallet-$name.log" 2>&1 \
    || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name-wallet.json"
}
ewhy() {  # $1 name: the wallet's stage and error, and EUDIPLO's session
  local name="$1"
  echo "wallet $(jq -c '{stage, error, failed} | with_entries(select(.value != null))' "$name-wallet.json" 2>/dev/null | cut -c1-400)," \
    "session $(jq -c . "$name-session.json" 2>/dev/null | cut -c1-200)"
}
# issued checks case $1 received one credential of format $2, as $3
# copies (a batch), holding the PID's claims, its session completed (the
# wallet's notification, credential_accepted).
issued() {  # $1 name, $2 format, $3 copies
  local name="$1" format="$2" copies="$3"
  jq -e --arg f "$format" --argjson n "$copies" '.stage == "done" and (.received | length == 1) and .received[0].format == $f
      and (.received[0].status_lists | length == $n)
      and (if $f == "dc+sd-jwt" then (.received[0].claims | contains(["family_name", "given_name", "birth_date", "cnf", "status"]))
           else .received[0].claims == ["eu.europa.ec.eudi.pid.1"] end)' "$name-wallet.json" >/dev/null 2>&1 \
    && jq -e '.status == "completed"' "$name-session.json" >/dev/null 2>&1
}
# observed is what the wallet's transport saw: the token type, and each
# Credential Response's media type (application/jwt: encrypted).
observed() {  # $1 name
  local name="$1"
  jq -r '.observed | "token_type \(.token_types | join(",")), Credential Responses \(.credential_responses | map(split(";")[0]) | join(","))"' "$name-wallet.json"
}
encrypted() {  # $1 name: a DPoP token, every Credential Response encrypted
  local name="$1"
  jq -e '.observed.token_types == ["DPoP"] and (.observed.credential_responses | length >= 1 and all(startswith("application/jwt")))' "$name-wallet.json" >/dev/null 2>&1
}
fetched() {  # the times EUDIPLO fetched the Wallet Provider's status lists
  grep -c ' tap: GET "/statuslists/[0-9]*/[0-9]*" 200' ewp-serve.log || true
}

# Pre-authorized code, with a tx_code, the Wallet Attestation and DPoP
# required: an SD-JWT VC and an mdoc PID, each a batch of 2 (EUDIPLO's
# batchSize), checked by walletflow on receipt (its chain to EUDIPLO's
# CA or IACA, its holder binding to the keys the wallet proved). Every
# Credential Request and Response is encrypted: EUDIPLO always offers
# it (credential_request_encryption, credential_response_encryption)
# and walletflow takes what is offered.
for c in "issue-sdjwt pid-sdjwt dc+sd-jwt" "issue-mdoc pid-mdoc mso_mdoc"; do
  read -r name config format <<< "$c"
  ereceive "$TOKEN" "$name" "$config" "$TX"
  if issued "$name" "$format" 2 && encrypted "$name"; then
    ok "$name: issued, pre-authorized with a tx_code, the Wallet Attestation EUDIPLO checked, DPoP; $(observed "$name"); a batch of $(jq '.received[0].status_lists | length' "$name-wallet.json"), claims $(jq -c '.received[0].claims' "$name-wallet.json")"
  else bad "$name: $(ewhy "$name")"; fi
done
# EUDIPLO checked the Wallet Attestation's status: it fetched the
# provider's status list (once, then cached, for its ttl).
if [[ "$(fetched)" -ge 1 ]]; then ok "EUDIPLO fetched the Wallet Provider's status list, for the Wallet Attestation's status"
else bad "EUDIPLO didn't fetch the Wallet Provider's status list: $(tail -3 ewp-serve.log | tr '\n' ';')"; fi

# The same under walletflow's HAIP profile: a Wallet Attestation at
# every Token Request, and a jwt proof carrying a Key Attestation, its
# key named in its jwk header (README finding 3); one proof, so one
# credential.
ereceive "$TOKEN" issue-haip pid-sdjwt "$TX" -haip -proof-key-by-jwk
if issued issue-haip dc+sd-jwt 1 && encrypted issue-haip; then
  ok "issue-haip: issued under walletflow.ProfileHAIP, its jwt proof carrying a Key Attestation; $(observed issue-haip)"
else bad "issue-haip: $(ewhy issue-haip)"; fi

# The second tenant requires Credential Request and Response encryption
# (encryption_required in its metadata, which EUDIPLO enforces).
if curl -s --cacert ca.pem "$E/.well-known/openid-credential-issuer/issuers/$ENC_TENANT_ID" \
    | jq -e '.credential_request_encryption.encryption_required == true and .credential_response_encryption.encryption_required == true' >/dev/null; then
  ereceive "$ENC_TOKEN" issue-enc pid-sdjwt "$TX"
  if issued issue-enc dc+sd-jwt 2 && encrypted issue-enc; then
    ok "issue-enc: issued by the tenant requiring Credential Request and Response encryption; $(observed issue-enc)"
  else bad "issue-enc: $(ewhy issue-enc)"; fi
else bad "issue-enc: the second tenant's metadata doesn't require encryption"; fi

# Key Attestations, required (key_attestations_required, key storage
# iso_18045_moderate, which the provider attests) and checked by
# EUDIPLO against the same trust list, their status too: in a jwt
# proof's key_attestation header (one proof, so one credential), and as
# an attestation proof, for which EUDIPLO issues one credential per
# attested key (a batch of 2).
ka_before="$(grep -c ' served POST "/v1/key-attestation" 200' wallet-provider-eudiplo/wallet-provider.log || true)"
ereceive "$TOKEN" issue-ka pid-sdjwt-ka "$TX" -proof-key-by-jwk
ereceive "$TOKEN" issue-kap pid-sdjwt-kap "$TX"
ka_after="$(grep -c ' served POST "/v1/key-attestation" 200' wallet-provider-eudiplo/wallet-provider.log || true)"
if issued issue-ka dc+sd-jwt 1 && issued issue-kap dc+sd-jwt 2 && [[ "$ka_after" -ge $((ka_before + 2)) ]]; then
  ok "issue-ka, issue-kap: issued, a Key Attestation from OID4VCgo's Wallet Provider required, in a jwt proof and as an attestation proof (a batch of 2); Key Attestations served $ka_before → $ka_after"
else bad "issue-ka: $(ewhy issue-ka); issue-kap: $(ewhy issue-kap); Key Attestations served $ka_before → $ka_after"; fi

# Token Status List: the wallet checks each credential's entry on
# EUDIPLO's list (Wallet.CheckStatus): VALID; then, EUDIPLO revoking the
# session's credentials (POST /api/session/revoke, the wallet's
# -revoke-call) before the check, INVALID. Each pair differs in the
# revocation alone. EUDIPLO signs the mdocs' list under its IACA, and
# the SD-JWT VCs' as a Status Issuer: its iss EUDIPLO's PUBLIC_URL,
# not the tenant's credential issuer, its certificate under EUDIPLO's
# CA naming that (setup), which the wallet is told (-status-issuer,
# walletflow.Config.StatusIssuers; README, "What EUDIPLO sends").
STATUS_ISSUER=(-status-issuer "$E/issuers/$TENANT_ID=$E")
for c in "sdjwt pid-sdjwt" "mdoc pid-mdoc"; do
  read -r format config <<< "$c"
  ereceive "$TOKEN" "status-$format" "$config" "$TX" -check-status "${STATUS_ISSUER[@]}"
  if jq -e '.stage == "done" and (.received[0].status.value == "valid")' "status-$format-wallet.json" >/dev/null 2>&1; then
    ok "status-$format: the wallet checked its entry on EUDIPLO's status list: $(jq -c '.received[0].status' "status-$format-wallet.json")"
  else bad "status-$format: $(ewhy "status-$format") $(jq -c '.received[0].status' "status-$format-wallet.json" 2>/dev/null)"; fi
  # The revocation names the offer's session, so the offer comes first.
  eoffer "$TOKEN" "$config" "$TX" "revoked-$format"
  jq -n --arg u "$E/api/session/revoke" --arg t "$TOKEN" --arg s "$(jq -r .session "revoked-$format-offer.json")" \
    '{url: $u, token: $t, body: {sessionId: $s, status: 1}}' > "revoked-$format-call.json"
  eredeem "revoked-$format" -tx-code "$TX" -revoke-call "revoked-$format-call.json" -check-status "${STATUS_ISSUER[@]}"
  if jq -e '.stage == "done" and (.revoked | length == 1) and (.received[0].status.value == "invalid")' "revoked-$format-wallet.json" >/dev/null 2>&1; then
    ok "control: the $format revoked by EUDIPLO after issuance: the wallet reads it on EUDIPLO's status list as $(jq -c '.received[0].status' "revoked-$format-wallet.json")"
  else bad "control: the $format revoked by EUDIPLO: $(jq -c '{stage, error, revoked, status: .received[0].status}' "revoked-$format-wallet.json" 2>/dev/null | cut -c1-400)"; fi
done

# What EUDIPLO's SD-JWT VC status list names as its iss: its PUBLIC_URL
# (README, "What EUDIPLO sends").
iss="$(api "$(jq -r '.received[0].status_lists[0] | split("#")[0]' status-sdjwt-wallet.json)" | jq -rR 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson | .iss')"
echo "        observed: the SD-JWT VC's status list token's iss $iss, the credential's $E/issuers/$TENANT_ID"
if [[ "$iss" = "$E" ]]; then ok "observed: EUDIPLO's status list token names its PUBLIC_URL as iss, not the tenant's credential issuer"
else bad "observed: EUDIPLO's status list token's iss changed: $iss"; fi
# The wallet not told EUDIPLO is the Status Issuer: it refuses the
# SD-JWT VC's status list, whose signer is neither the credential's key
# nor a certificate naming its iss. The case differs from status-sdjwt
# in that alone.
ereceive "$TOKEN" status-issuer-unknown pid-sdjwt "$TX" -check-status
if jq -e --arg want "token signer isn't the referenced token's issuer: neither its key nor a name its certificate carries: certchain: iss \"$E/issuers/$TENANT_ID\" isn't a URI of the signing certificate" \
    '.stage == "done" and (.received[0].status.error | contains($want))' status-issuer-unknown-wallet.json >/dev/null 2>&1; then
  ok "control: the wallet not told EUDIPLO signs as a Status Issuer: it refuses the SD-JWT VC's status list, for its signer"
else bad "control: a status list from an unknown Status Issuer: $(ewhy status-issuer-unknown) $(jq -c '.received[0].status' status-issuer-unknown-wallet.json 2>/dev/null)"; fi

# Controls, each differing from issue-sdjwt (or issue-ka) in one thing.
# refused_at checks case $1 stopped at the wallet's stage $2 with an
# error containing $3, the refusing side's reason, its session still
# active: EUDIPLO issued nothing.
refused_at() {  # $1 name, $2 stage, $3 in the error, $4 what the control is
  local name="$1" stage="$2" reason="$3" what="$4"
  if jq -e --arg s "$stage" --arg r "$reason" '.stage == $s and (.received | length == 0) and (.error | contains($r))' "$name-wallet.json" >/dev/null 2>&1 \
      && jq -e '.status == "active"' "$name-session.json" >/dev/null 2>&1; then
    ok "control: $what: refused ($(jq -r '.error | split("error response: ")[-1] | .[:200]' "$name-wallet.json"))"
  else bad "control: $what: $(ewhy "$name")"; fi
}
ereceive "$TOKEN" wrong-tx-code pid-sdjwt "$TX" -tx-code 493537
refused_at wrong-tx-code token "invalid_grant: Invalid 'tx_code' provided" "a wrong tx_code, by EUDIPLO's token endpoint"
# A Wallet Attestation from OID4VCgo's other Wallet Provider instance
# (the Verifier cases'), whose CA EUDIPLO's trust list doesn't name.
ereceive "$TOKEN" untrusted-attester pid-sdjwt "$TX" \
  -wallet-provider "https://localhost:$WP_PORT" -wallet-provider-tls wallet-provider/tls-cert.pem
refused_at untrusted-attester token "invalid_client: Wallet provider certificate is not trusted - no matching entity in trust list" \
  "a Wallet Attestation from a provider EUDIPLO's trust list doesn't name"
# The Wallet Attestation's instance revoked by the provider once it's
# attested (the wallet's -revoke-instance): its status list entry reads
# INVALID. EUDIPLO caches the provider's status list, so the run clears
# the tenant's cache first and checks EUDIPLO fetched the list again.
before="$(fetched)"
api -o /dev/null -X DELETE -H "$AUTH" "$E/api/cache/status-list"
ereceive "$TOKEN" revoked-attestation pid-sdjwt "$TX" -revoke-instance "http://127.0.0.1:$EWP_ADMIN_PORT/revoke"
if [[ "$(fetched)" -le "$before" ]]; then bad "control: a revoked Wallet Attestation: EUDIPLO didn't fetch the provider's status list again"; fi
refused_at revoked-attestation token "invalid_client: Wallet attestation is not valid: Invalid/Revoked" \
  "a Wallet Attestation whose instance the provider revoked, by its status"
# A Key Attestation below the key storage level the configuration
# requires (iso_18045_high); the case differs from issue-ka in that
# alone.
ereceive "$TOKEN" ka-level pid-sdjwt-ka-high "$TX" -proof-key-by-jwk
refused_at ka-level credential "invalid_proof: The key attestation does not state an accepted key_storage value (accepted: iso_18045_high)" \
  "a Key Attestation below the required key storage level"
# Every Credential Request's DPoP proof signed again by the wallet's
# DPoP key, its htu the Notification Endpoint's (the wallet's
# -tamper-dpop).
ereceive "$TOKEN" dpop-htu pid-sdjwt "$TX" -tamper-dpop
refused_at dpop-htu credential "Dpop jwt contains htu value '$E/issuers/$TENANT_ID/vci/notification', but expected htu value '$E/issuers/$TENANT_ID/vci/credential'" \
  "a DPoP proof for another endpoint (htu), by EUDIPLO's Credential Endpoint"
# The wallet's own refusal: it trusts another CA for issuers, so the
# credential's chain doesn't verify; its notification
# (credential_failure) fails EUDIPLO's session.
ereceive "$TOKEN" untrusted-issuer pid-sdjwt "$TX" -issuer-ca other-ca.pem
if jq -e '.stage == "credential" and (.received | length == 0)
    and (.error | contains("is invalid: wallet: verify issued credential: issuer certificate: certchain: certificate chain does not verify against a trusted root"))' \
    untrusted-issuer-wallet.json >/dev/null 2>&1 \
    && jq -e '.status == "failed" and .failureCode == "credential_failure"' untrusted-issuer-session.json >/dev/null 2>&1; then
  ok "control: the wallet trusts another issuer CA: it refuses the credential, for its chain, and tells EUDIPLO (session failed, credential_failure)"
else bad "control: an untrusted issuer: $(ewhy untrusted-issuer)"; fi

# Known gaps of EUDIPLO's, noted rather than failed; the run fails once
# either changes (README.md).
# Finding 2: EUDIPLO's PAR refuses a request parameter it doesn't know,
# and fapigo's client, under walletflow, sends nonce: the authorization
# code flow stops there. Shown by elimination too: the same PAR without
# nonce gets past its validation, to its client authentication.
ereceive "$TOKEN" authorization-code pid-sdjwt authorization_code
par() {  # then extra form fields: EUDIPLO's answer to a PAR without attestation
  api -X POST --data-urlencode client_id="$CLIENT_ID" --data-urlencode response_type=code --data-urlencode redirect_uri="$REDIRECT" \
    --data-urlencode scope=pid-sdjwt --data-urlencode code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM \
    --data-urlencode code_challenge_method=S256 "$@" "$E/issuers/$TENANT_ID/authorize/par"
}
par --data-urlencode nonce=n > par-nonce.json
par > par-plain.json
if jq -e '.stage == "authorization" and (.error | contains("pushed authorization request: client: invalid_response: authorization server returned an error: HTTP 400"))' \
    authorization-code-wallet.json >/dev/null 2>&1 \
    && jq -e 'any(.errors[]?; .message == "Unrecognized key: \"nonce\"")' par-nonce.json >/dev/null 2>&1 \
    && jq -e '.error == "invalid_client"' par-plain.json >/dev/null 2>&1; then
  echo "  note  EUDIPLO's PAR refuses the authorization request's nonce, a parameter it doesn't know (README finding 2): $(jq -c '.errors[0].message' par-nonce.json); without it, $(jq -r '"\(.error): \(.error_description)"' par-plain.json)"
else bad "README finding 2 has changed: the authorization code flow: $(ewhy authorization-code); PAR with nonce $(head -c 200 par-nonce.json); without $(head -c 200 par-plain.json)"; fi
# Finding 3: a key-attested jwt proof naming its key by its index in
# the Key Attestation's attested_keys (kid "0", walletflow's default)
# isn't verified, as Credo's issuer, on the same library, doesn't
# verify it either. The case differs from issue-ka in that alone.
ereceive "$TOKEN" ka-index pid-sdjwt-ka "$TX"
if jq -e '.stage == "credential" and (.error | contains("invalid_proof: Error verifying credential request proof jwt"))' ka-index-wallet.json >/dev/null 2>&1; then
  echo "  note  EUDIPLO refuses a key-attested jwt proof naming its key by its index (README finding 3): $(jq -r '.error | split("error response: ")[-1] | .[:120]' ka-index-wallet.json)"
else bad "README finding 3 has changed: a key-attested jwt proof naming its key by index: $(ewhy ka-index)"; fi
