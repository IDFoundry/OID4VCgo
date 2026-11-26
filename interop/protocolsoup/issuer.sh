# Sourced by run.sh, after the Verifier's cases: ProtocolSoup's
# Credential Issuer, to OID4VCgo's wallet (walletflow), attested by
# OID4VCgo's Wallet Provider, whose CA ProtocolSoup trusts for Wallet
# Attestations and Key Attestations. Its HAIP configurations take a
# Wallet Attestation at the Token Endpoint, a DPoP-bound token and a
# Key Attestation in the jwt proof; its others none of them. Then
# controls, each refused for its reason: ProtocolSoup's, or the
# wallet's own. See README.md.

echo "### ProtocolSoup's issuer → OID4VCgo's wallet"
# poffer has ProtocolSoup's issuer offer configuration $2 by
# pre-authorized code, by reference, from its endpoint $3
# (pre-authorized, or pre-authorized/deferred), with a tx_code unless
# $4 is false; its answer is in $1-offer.json, and it prints the
# openid-credential-offer:// link.
poffer() {  # $1 name, $2 configuration, $3 endpoint, $4 tx_code
  local name="$1" config="$2" endpoint="$3" tx="$4"
  api -X POST -H "$JSON" --data "$(jq -cn --arg c "$config" --argjson t "$tx" '{credential_configuration_ids: [$c], tx_code_required: $t}')" \
    "$PS/oid4vci/offers/$endpoint" > "$name-offer.json"
  jq -e '.credential_offer_uri' "$name-offer.json" >/dev/null 2>&1 || { echo "ProtocolSoup made no offer: $(head -c 200 "$name-offer.json")" >&2; exit 2; }
  jq -r '"openid-credential-offer://?credential_offer_uri=\(.credential_offer_uri | @uri)"' "$name-offer.json"
}
# preceive has OID4VCgo's wallet redeem an offer of configuration $2
# (as poffer, $3 and $4), attested by the Wallet Provider ProtocolSoup
# trusts, the offer's tx_code given, checking each credential's chain
# to ProtocolSoup's IACA (which certifies its SD-JWT VC signer too);
# the rest are the wallet's options (a later -wallet-provider replaces
# the trusted one, a later -tx-code the offer's). Its outcome is in
# $1-wallet.json.
preceive() {  # $1 name, $2 configuration, $3 endpoint, $4 tx_code; then the wallet's options
  local name="$1" config="$2" endpoint="$3" tx="$4" link
  shift 4
  pace
  link="$(poffer "$name" "$config" "$endpoint" "$tx")"
  local grant=()
  if [[ "$tx" = true ]]; then grant=(-tx-code "$(jq -r .tx_code_oob_value "$name-offer.json")"); fi
  ./wallet -tls-ca ca.pem -issuer-ca protocolsoup-iaca.pem -mdoc-issuer-ca protocolsoup-iaca.pem -verifier-ca ca.pem -crl-set none \
    -wallet-provider "https://localhost:$WP_PORT" -wallet-provider-tls wallet-provider/tls-cert.pem -client-id "$CLIENT_ID" \
    -offer "$link" -out "$name-wallet.json" ${grant[@]+"${grant[@]}"} "$@" >> "wallet-$name.log" 2>&1 \
    || echo '{"stage": "wallet", "error": "the wallet failed; see its log"}' > "$name-wallet.json"
}
pwhy() {  # $1 name: the wallet's stage and error
  local name="$1"
  jq -c '{stage, error, failed} | with_entries(select(.value != null))' "$name-wallet.json" 2>/dev/null | cut -c1-400
}
# pissued checks case $1 received one credential of format $2 and
# configuration $3, as $4 copies (a batch), its token of type $5, and
# the Credential Response that issued it encrypted (application/jwt):
# the one before it, if any, is ProtocolSoup's use_dpop_nonce
# challenge, an error response (application/json).
pissued() {  # $1 name, $2 format, $3 configuration, $4 copies, $5 token type
  local name="$1" format="$2" config="$3" copies="$4" token_type="$5"
  jq -e --arg f "$format" --arg c "$config" --argjson n "$copies" --arg t "$token_type" '.stage == "done" and (.received | length == 1)
      and .received[0].format == $f and .received[0].configuration_id == $c and .received[0].copies == $n
      and .observed.token_types == [$t] and (.observed.credential_responses[-1] | startswith("application/jwt"))' "$name-wallet.json" >/dev/null 2>&1
}
# pobserved is what the wallet's transport saw: the token type, and each
# Credential Response's media type (application/jwt: encrypted).
pobserved() {  # $1 name
  local name="$1"
  jq -r '"copies \(.received[0].copies // 0), " + (.observed | "token_type \(.token_types | join(",")), Credential Responses \(.credential_responses | map(split(";")[0]) | join(","))")' "$name-wallet.json"
}
HAIP_SDJWT=UniversityDegreeCredentialSDJWTHAIP HAIP_MDOC=MobileDrivingLicenceMsoMdocHAIP
PLAIN_SDJWT=UniversityDegreeCredentialSDJWT PLAIN_MDOC=MobileDrivingLicenceMsoMdoc

# HAIP: pre-authorized code with a tx_code; the Wallet Attestation
# from OID4VCgo's Wallet Provider at the Token Endpoint, a DPoP-bound
# token (ProtocolSoup requires both of a HAIP configuration), and a jwt
# proof carrying a Key Attestation from the provider, naming its key in
# its jwk header (README finding 3); one proof, so one credential.
# ProtocolSoup offers credential request and response encryption,
# which walletflow takes.
ka_before="$(grep -c ' served POST "/v1/key-attestation" 200' wallet-provider/wallet-provider.log || true)"
preceive issue-haip "$HAIP_SDJWT" pre-authorized true -haip -proof-key-by-jwk
ka_after="$(grep -c ' served POST "/v1/key-attestation" 200' wallet-provider/wallet-provider.log || true)"
if pissued issue-haip dc+sd-jwt "$HAIP_SDJWT" 1 DPoP && [[ "$ka_after" -gt "$ka_before" ]]; then
  ok "issue-haip: issued, pre-authorized with a tx_code, the Wallet Attestation and Key Attestation from OID4VCgo's Wallet Provider, which ProtocolSoup checked, DPoP; $(pobserved issue-haip); claims $(jq -c '.received[0].claims' issue-haip-wallet.json)"
else bad "issue-haip: $(pwhy issue-haip), Key Attestations served $ka_before → $ka_after"; fi

# Its other SD-JWT VC configuration, under walletflow's default
# profile: no Wallet Attestation asked of a pre-authorized code, no Key
# Attestation; DPoP all the same, and a batch.
preceive issue-sdjwt "$PLAIN_SDJWT" pre-authorized false
if pissued issue-sdjwt dc+sd-jwt "$PLAIN_SDJWT" "$(jq '.received[0].copies // 0' issue-sdjwt-wallet.json)" DPoP \
    && jq -e '.received[0].copies > 1' issue-sdjwt-wallet.json >/dev/null; then
  ok "issue-sdjwt: issued, pre-authorized, as a batch; $(pobserved issue-sdjwt)"
else bad "issue-sdjwt: $(pwhy issue-sdjwt)"; fi

# Deferred: the Credential Endpoint answers 202 with a transaction_id,
# and the wallet gets the credential from the Deferred Credential
# Endpoint (the wallet's deferred count).
preceive deferred "$PLAIN_SDJWT" pre-authorized/deferred false
if jq -e '.stage == "done" and .deferred == 1 and (.received | length == 1)' deferred-wallet.json >/dev/null 2>&1; then
  ok "deferred: deferred, then issued from the Deferred Credential Endpoint; $(pobserved deferred)"
else bad "deferred: $(pwhy deferred)"; fi

# Token Status List: the wallet checks the HAIP SD-JWT VC's entry on
# ProtocolSoup's list (Wallet.CheckStatus), signed under its IACA.
preceive status "$HAIP_SDJWT" pre-authorized true -haip -proof-key-by-jwk -check-status
if jq -e '.stage == "done" and .received[0].status.value == "valid"' status-wallet.json >/dev/null 2>&1; then
  ok "status: the wallet checked its entry on ProtocolSoup's status list: $(jq -c '.received[0].status' status-wallet.json)"
else bad "status: $(pwhy status) $(jq -c '.received[0].status' status-wallet.json 2>/dev/null)"; fi

# Controls, each differing from issue-haip in one thing. prefused
# checks case $1 stopped at the wallet's stage $2, receiving nothing,
# with an error containing $3, the refusing side's reason.
prefused() {  # $1 name, $2 stage, $3 in the error, $4 what the control is
  local name="$1" stage="$2" reason="$3" what="$4"
  if jq -e --arg s "$stage" --arg r "$reason" '.stage == $s and ((.received // []) | length == 0) and (.error | contains($r))' "$name-wallet.json" >/dev/null 2>&1; then
    ok "control: $what: refused ($(jq -r '.error | split("error response: ")[-1] | .[:220]' "$name-wallet.json"))"
  else bad "control: $what: $(pwhy "$name")"; fi
}
preceive wrong-tx-code "$HAIP_SDJWT" pre-authorized true -haip -proof-key-by-jwk -tx-code 000000
prefused wrong-tx-code token "invalid_grant: invalid tx_code" "a wrong tx_code, by ProtocolSoup's Token Endpoint"
preceive untrusted-attester "$HAIP_SDJWT" pre-authorized true -haip -proof-key-by-jwk \
  -wallet-provider "https://localhost:$OTHER_WP_PORT" -wallet-provider-tls other-wallet-provider/tls-cert.pem
prefused untrusted-attester token "invalid_client: client attestation: attester trust chain: verify certificate chain: x509: certificate signed by unknown authority" \
  "a Wallet Attestation from a provider whose CA ProtocolSoup doesn't trust, by its Token Endpoint"
# The wallet's own refusal: it trusts another CA for issuers.
preceive untrusted-issuer "$HAIP_SDJWT" pre-authorized true -haip -proof-key-by-jwk -issuer-ca other-ca.pem
prefused untrusted-issuer credential "is invalid: wallet: verify issued credential: issuer certificate: certchain: certificate chain does not verify against a trusted root" \
  "the wallet trusts another issuer CA: it refuses the credential, for its chain"

# Known gaps of ProtocolSoup's, noted rather than failed; the run
# fails once either changes (README.md).
# Finding 3: a key-attested jwt proof naming its key by its index in
# the Key Attestation's attested_keys (kid "0", walletflow's default)
# isn't verified; ProtocolSoup takes the proof's key from its jwk
# header alone. The case differs from issue-haip in that alone.
preceive ka-index "$HAIP_SDJWT" pre-authorized true -haip
if jq -e '.stage == "credential" and (.error | contains("invalid_proof"))' ka-index-wallet.json >/dev/null 2>&1; then
  note "ProtocolSoup refuses a key-attested jwt proof naming its key by its index (README finding 3): $(jq -r '.error | split("error response: ")[-1] | .[:160]' ka-index-wallet.json)"
else bad "README finding 3 has changed: a key-attested jwt proof naming its key by index: $(pwhy ka-index)"; fi
# Finding 4: ProtocolSoup rounds an mdoc's validityInfo.signed down to
# the day, as it does a JWT credential's iat, which then precedes its
# Document Signer certificate, made at startup: walletflow refuses the
# mdoc, signed outside its signer's validity. Both its mdoc
# configurations, HAIP's and the other.
preceive mdoc-haip "$HAIP_MDOC" pre-authorized true -haip -proof-key-by-jwk
preceive mdoc "$PLAIN_MDOC" pre-authorized false
want="is invalid: wallet: verify issued credential: issuer certificate: mdoc: MSO signed $(date -u +%Y-%m-%d)T00:00:00Z, outside the document signer certificate's validity"
if jq -e --arg w "$want" '.stage == "credential" and (.error | contains($w))' mdoc-haip-wallet.json >/dev/null 2>&1 \
    && jq -e --arg w "$want" '.stage == "credential" and (.error | contains($w))' mdoc-wallet.json >/dev/null 2>&1; then
  note "the wallet refuses ProtocolSoup's mdocs, their MSO signed at the day's start, before their Document Signer certificate (README finding 4): $(jq -r '.error | split("issuer certificate: ")[-1]' mdoc-wallet.json)"
else bad "README finding 4 has changed: ProtocolSoup's mdocs: HAIP $(pwhy mdoc-haip); other $(pwhy mdoc)"; fi
