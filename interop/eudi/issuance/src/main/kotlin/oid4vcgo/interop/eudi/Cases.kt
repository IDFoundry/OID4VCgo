package oid4vcgo.interop.eudi

import eu.europa.ec.eudi.openid4vci.AuthorizedRequest
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceError
import eu.europa.ec.eudi.openid4vci.CredentialIssuanceEvent

import eu.europa.ec.eudi.openid4vci.DeferredCredentialQueryOutcome
import eu.europa.ec.eudi.openid4vci.Issuer
import eu.europa.ec.eudi.openid4vci.SubmissionOutcome
import kotlinx.coroutines.delay

private const val PRE_AUTHORIZED = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
private const val PRE_AUTHORIZED_CODE = "pre-authorized_code"
private const val TOKEN_PATH = "/token"
private const val CREDENTIAL_PATH = "/credential"
private const val TX_CODE = "493817"
private const val WRONG_TX_CODE = "000000"

// --- what every case checks of the exchanges the wallet made ---

/** The pre-authorized code Token Request: DPoP-bound and Wallet-attested. */
private fun Run.checkPreAuthorizedTokenRequest() {
    val t = wallet.recorder.to(TOKEN_PATH).lastOrNull { it.status == 200 }
    expect(
        t != null && t.form["grant_type"] == PRE_AUTHORIZED && t.dpop && t.clientAttestation && PRE_AUTHORIZED_CODE in t.form,
        "token request: pre-authorized code grant, DPoP proof, Wallet Attestation and PoP",
    ) { t.toString() }
    checkAttestationPoPIss(t, "token request")
}

/**
 * The Client Attestation PoP's iss, which draft-07 §5.2 requires and
 * FAPIgo's server doesn't (SPECIFICATIONS.md, "Known leniencies"): the
 * library names the client_id, as it does today, so a PoP without one
 * fails here rather than passing on the leniency unnoticed.
 */
private fun Run.checkAttestationPoPIss(
    e: Exchange?,
    what: String,
) {
    val iss = e?.attestationPoPIss
    expect(
        iss == wallet.cfg.clientId,
        "$what: Client Attestation PoP iss is the client_id, as eudi-lib-jvm-openid4vci-kt sends it (observed: ${iss?.ifEmpty { "absent" } ?: "no PoP"})",
    ) { "want ${wallet.cfg.clientId}: update README.md's findings if the library changed" }
}

/**
 * PAR, then the authorization code Token Request: PKCE S256, DPoP,
 * Wallet-attested, and the redirect URI the EUDI wallet app registers,
 * a private-use URI with an authority (the consent's redirect to it is
 * checked in [consent]).
 */
private fun Run.checkAuthorizationCodeRequests() {
    val par = wallet.recorder.to("/par").lastOrNull { it.status == 201 }
    expect(
        par != null && par.dpop && par.clientAttestation && par.form["response_type"] == "code" &&
            par.form["code_challenge_method"] == "S256" && "code_challenge" in par.form,
        "PAR: PKCE S256, DPoP proof (binding the code), Wallet Attestation and PoP",
    ) { par.toString() }
    expect(
        par != null && par.form["redirect_uri"] == wallet.cfg.redirectUri,
        "PAR: redirect_uri ${wallet.cfg.redirectUri}, a native client's private-use URI with an authority",
    ) { par?.form?.get("redirect_uri").toString() }
    val t = wallet.recorder.to(TOKEN_PATH).lastOrNull { it.status == 200 }
    expect(
        t != null && t.form["grant_type"] == "authorization_code" && t.dpop && t.clientAttestation && "code_verifier" in t.form,
        "token request: authorization code, PKCE verifier, DPoP proof, Wallet Attestation and PoP",
    ) { t.toString() }
    checkAttestationPoPIss(par, "PAR")
    checkAttestationPoPIss(t, "token request")
}

/** Every Credential Request used a fresh c_nonce, a DPoP-bound token, and (un)encrypted bodies as asked. */
private fun Run.checkCredentialRequests(
    path: String = CREDENTIAL_PATH,
    encrypted: Boolean = false,
) {
    val requests = wallet.recorder.to(path).filter { it.status in 200..299 }
    expect(
        requests.isNotEmpty() && requests.all { it.authorizationScheme == "DPoP" && it.dpop },
        "$path: DPoP access token with a DPoP proof",
    ) { requests.toString() }
    if (path == CREDENTIAL_PATH) {
        expect(wallet.recorder.to("/nonce").any { it.status == 200 }, "c_nonce from the Nonce Endpoint")
    }
    val want = if (encrypted) "application/jwt" else "application/json"
    expect(
        requests.all { it.requestContentType == want && it.responseContentType == want },
        if (encrypted) "$path: request and response encrypted (application/jwt)" else "$path: request and response unencrypted",
    ) { requests.map { "${it.requestContentType} -> ${it.responseContentType}" }.toString() }
}

/**
 * Requests [configurationId] with [proofs], and checks what's issued:
 * one credential per proven key, each verified by [Wallet.verify] and
 * bound to one of the keys.
 */
private suspend fun Run.issueAndVerify(
    issuer: Issuer,
    authorized: AuthorizedRequest,
    configurationId: String,
    proofs: Proofs,
): Pair<AuthorizedRequest, SubmissionOutcome.Success> =
    with(wallet) {
        val (updated, outcome) = issuer.issue(authorized, configurationId, proofs.spec)
        check(outcome is SubmissionOutcome.Success) { "the issuer answered $outcome" }
        verifyIssued(configurationId, outcome.credentials, proofs)
        updated to outcome
    }

private suspend fun Run.verifyIssued(
    configurationId: String,
    credentials: List<eu.europa.ec.eudi.openid4vci.IssuedCredential>,
    proofs: Proofs,
) {
    val format = if (configurationId == wallet.cfg.mdocConfigurationId) "mdoc" else "SD-JWT VC"
    expect(credentials.size == proofs.keys.size, "issued ${proofs.keys.size} $format") { "issued ${credentials.size}" }
    val bound = wallet.verify(configurationId, credentials)
    ok(if (format == "mdoc") "the mdoc verifies: issuerAuth, x5chain to the IACA, digests, docType, claims" else "EUDI's SD-JWT VC verifier accepts it: x5c to the issuer CA, vct, claims")
    expect(bound.toSet() == proofs.thumbprints && bound.size == proofs.keys.size, "each bound to a different key the proofs named")
}

/** Sends the Notification Endpoint an event for [success] (§11). */
private suspend fun Run.notifyAccepted(
    issuer: Issuer,
    authorized: AuthorizedRequest,
    notificationId: eu.europa.ec.eudi.openid4vci.NotificationId?,
) {
    if (notificationId == null) {
        bad("the Credential Response carries a notification_id")
        return
    }
    with(issuer) { authorized.notify(CredentialIssuanceEvent.Accepted(notificationId, "stored")) }.getOrThrow()
    val n = wallet.recorder.to("/notification").lastOrNull()
    expect(n?.status == 204 && n.authorizationScheme == "DPoP" && n.dpop, "notification credential_accepted answered 204") { n.toString() }
}

private fun isOAuthError(
    t: Throwable,
    code: String,
): Boolean = generateSequence(t) { it.cause }.any { (it.message ?: "").contains(code) || it.toString().contains(code) }

// --- the profiles ---

/** The issuer's default configuration: everything but deferral, key attestation in jwt proofs, and DPoP nonces. */
suspend fun baseCases(run: Run) {
    val sdjwt = run.wallet.cfg.sdJwtConfigurationId
    val mdoc = run.wallet.cfg.mdocConfigurationId

    // invalid_client is a 401 (RFC 6749 §5.2), whose error object the
    // library doesn't read (README finding 3): the exchange shows it.
    fun refusedWith401(path: String) = run.wallet.recorder.to(path).lastOrNull()?.status == 401

    var replayOffer = ""
    run.case("pre-authorized code, SD-JWT VC, jwt proof, offer by value") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        replayOffer = uri
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        run.checkPreAuthorizedTokenRequest()
        val (updated, success) = run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
        run.checkCredentialRequests()
        run.notifyAccepted(issuer, updated, success.notificationId)
    }

    run.control("the same pre-authorized code redeemed again", "the issuer refuses it", { isOAuthError(it, "invalid_grant") }) {
        val issuer = fromOffer(replayOffer)
        with(this) { issuer.authorizeByPreAuthorizedCode() }
    }

    var txOffer = ""
    run.control("a wrong tx_code", "the issuer refuses it", { isOAuthError(it, "invalid_grant") }) {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(mdoc), txCode = TX_CODE, byReference = true)
        txOffer = uri
        val issuer = fromOffer(uri)
        with(this) { issuer.authorizeByPreAuthorizedCode(WRONG_TX_CODE) }
    }

    run.case("pre-authorized code with tx_code, mdoc, offer by reference, after a wrong tx_code") {
        val issuer = fromOffer(txOffer)
        run.expect(recorder.exchanges.any { it.method == "GET" && it.path.startsWith("/credential-offer/") && it.status == 200 }, "fetched the offer from the Credential Offer Endpoint")
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode(TX_CODE) }
        run.ok("the right tx_code still redeems the code")
        run.checkPreAuthorizedTokenRequest()
        run.issueAndVerify(issuer, authorized, mdoc, Proofs.jwt())
        run.checkCredentialRequests()
    }

    run.case("pre-authorized code granting credential_identifiers, both formats") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt, mdoc), credentialIdentifiers = true)
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        val ids = authorized.credentialIdentifiers.orEmpty()
        run.expect(ids.keys.map { it.value }.toSet() == setOf(sdjwt, mdoc) && ids.values.all { it.isNotEmpty() }, "the Token Response's authorization_details grant a credential_identifier for each") { ids.toString() }
        val (next, _) = run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
        run.issueAndVerify(issuer, next, mdoc, Proofs.jwt())
        run.checkCredentialRequests()
    }

    run.case("pre-authorized code, the wallet asking for authorization_details at the Token Endpoint") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri)
        val attempt = runCatching { with(this) { issuer.authorizeByPreAuthorizedCode(requestAuthorizationDetails = true) } }
        val sent = recorder.to(TOKEN_PATH).lastOrNull()?.form?.get("authorization_details").orEmpty()
        if (sent.startsWith("%5B")) {
            // README finding 2: the library form-encodes the JSON array
            // itself, and the form encoding then encodes it again.
            run.known("the wallet sends authorization_details URL-encoded twice (README finding 2)")
            run.expect(
                attempt.exceptionOrNull()?.let { isOAuthError(it, "invalid_authorization_details") } == true,
                "the issuer refuses it as invalid_authorization_details",
            ) { attempt.toString() }
            val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
            run.ok("the refused request didn't spend the code: it still redeems without authorization_details")
            run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
            return@case
        }
        val authorized = attempt.getOrThrow()
        run.ok("the wallet sends authorization_details encoded once: README finding 2 is fixed")
        run.expect(authorized.credentialIdentifiers.orEmpty().keys.map { it.value } == listOf(sdjwt), "the Token Response grants a credential_identifier for it") { authorized.credentialIdentifiers.toString() }
        run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
    }

    run.case("authorization code, wallet-initiated, SD-JWT VC") {
        val issuer = walletInitiated(listOf(sdjwt))
        val authorized = with(this) { issuer.authorizeByCode() }
        run.checkAuthorizationCodeRequests()
        run.expect(recorder.to("/par").lastOrNull()?.form?.get("scope") == sdjwt, "PAR asks for the configuration's scope")
        val (updated, success) = run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
        run.checkCredentialRequests()
        run.notifyAccepted(issuer, updated, success.notificationId)
    }

    run.case("authorization code from an offer with issuer_state, both formats on one token") {
        val (uri, issuerState) = offer("authorization_code", listOf(sdjwt, mdoc), byReference = true)
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByCode() }
        run.checkAuthorizationCodeRequests()
        val par = recorder.to("/par").lastOrNull()
        run.expect(issuerState != null && par != null && "issuer_state" in par.form, "PAR carries the offer's issuer_state")
        val (next, _) = run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
        run.issueAndVerify(issuer, next, mdoc, Proofs.jwt())
        run.checkCredentialRequests()
    }

    run.case("authorization code by authorization_details, both formats, by credential_identifier") {
        val issuer = walletInitiated(listOf(sdjwt, mdoc), WalletOptions(authorizationDetails = true))
        val authorized = with(this) { issuer.authorizeByCode() }
        run.checkAuthorizationCodeRequests()
        val par = recorder.to("/par").lastOrNull()
        val details = par?.form?.get("authorization_details").orEmpty()
        run.expect(
            details.startsWith("[") && sdjwt in details && mdoc in details && "scope" !in par!!.form,
            "PAR asks by openid_credential authorization_details, not scope",
        ) { par.toString() }
        val ids = authorized.credentialIdentifiers.orEmpty()
        run.expect(ids.keys.map { it.value }.toSet() == setOf(sdjwt, mdoc) && ids.values.all { it.isNotEmpty() }, "the Token Response grants a credential_identifier for each") { ids.toString() }
        val (next, _) = run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
        val (last, success) = run.issueAndVerify(issuer, next, mdoc, Proofs.jwt())
        run.checkCredentialRequests()
        val id = success.notificationId
        if (id == null) {
            run.bad("the Credential Response carries a notification_id")
        } else {
            with(issuer) { last.notify(CredentialIssuanceEvent.Deleted(id, "the End-User deleted it")) }.getOrThrow()
            run.expect(recorder.to("/notification").lastOrNull()?.status == 204, "notification credential_deleted answered 204")
        }
    }

    run.case("batch issuance: three jwt proofs, SD-JWT VC") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt(3))
        run.checkCredentialRequests()
    }

    run.case("attestation proof, a key attestation of two keys, SD-JWT VC") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        run.issueAndVerify(issuer, authorized, sdjwt, Proofs.attestation(cfg.keyAttestationKey, 2))
        run.checkCredentialRequests()
    }

    run.case("attestation proof, mdoc") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(mdoc))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        run.issueAndVerify(issuer, authorized, mdoc, Proofs.attestation(cfg.keyAttestationKey, 1))
    }

    run.case("credential request and response encryption, both formats") {
        val options = WalletOptions(encryption = true)
        val issuer = walletInitiated(listOf(sdjwt, mdoc), options)
        val authorized = with(this) { issuer.authorizeByCode() }
        val (next, _) = run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
        run.issueAndVerify(issuer, next, mdoc, Proofs.jwt(2))
        run.checkCredentialRequests(encrypted = true)
    }

    run.case("signed Credential Issuer Metadata required") {
        val options = WalletOptions(signedMetadataTrust = cfg.issuerCa)
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri, options)
        val md = recorder.to("/.well-known/openid-credential-issuer").lastOrNull()
        run.expect(md?.responseContentType == "application/jwt", "the issuer answered with signed metadata (application/jwt), which the wallet verified") { md.toString() }
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
    }

    run.control(
        "signed metadata, the wallet trusting an unrelated CA",
        "the wallet refuses the metadata",
        { it.toString().contains("InvalidSignedMetadata") && it.toString().contains("not trusted") },
    ) {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        fromOffer(uri, WalletOptions(signedMetadataTrust = cfg.otherCa))
    }

    run.control("a Wallet Attestation from an attester the issuer doesn't trust, pre-authorized code", "the Token Endpoint refuses it with 401", { refusedWith401(TOKEN_PATH) }) {
        val client = walletAttestation(cfg.clientId, cfg.attesterIssuer, cfg.otherAttesterKey, cfg.otherAttesterX5c)
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri, WalletOptions(client = client))
        with(this) { issuer.authorizeByPreAuthorizedCode() }
    }

    run.control("a Wallet Attestation from an attester the issuer doesn't trust, authorization code", "PAR refuses it with 401", { refusedWith401("/par") }) {
        val client = walletAttestation(cfg.clientId, cfg.attesterIssuer, cfg.otherAttesterKey, cfg.otherAttesterX5c)
        val issuer = walletInitiated(listOf(sdjwt), WalletOptions(client = client))
        with(this) { issuer.authorizeByCode() }
    }

    run.control("a key attestation from a signer the issuer doesn't trust", "the Credential Endpoint refuses the proof", { it is CredentialIssuanceError.InvalidProof }) {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        val (_, outcome) = with(this) { issuer.issue(authorized, sdjwt, Proofs.attestation(cfg.otherKeyAttestationKey).spec) }
        if (outcome is SubmissionOutcome.Failed) throw outcome.error
        error("issued: $outcome")
    }

    run.control("the End-User denies consent", "the authorization response is access_denied", { it is AuthorizationRefused && it.error == "access_denied" }) {
        val issuer = walletInitiated(listOf(sdjwt))
        with(this) { issuer.authorizeByCode(approve = false) }
    }

    run.control("an SD-JWT VC checked against an unrelated CA", "EUDI's SD-JWT VC verifier refuses it", { it::class.simpleName.orEmpty().contains("SdJwtVerification") }) {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        val (_, outcome) = with(this) { issuer.issue(authorized, sdjwt, Proofs.jwt().spec) }
        check(outcome is SubmissionOutcome.Success) { "not issued: $outcome" }
        verify(sdjwt, outcome.credentials, cfg.otherCa)
    }

    run.control("an mdoc checked against an unrelated IACA", "the mdoc check refuses it", { it.message?.contains("IACA") == true }) {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(mdoc))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        val (_, outcome) = with(this) { issuer.issue(authorized, mdoc, Proofs.jwt().spec) }
        check(outcome is SubmissionOutcome.Success) { "not issued: $outcome" }
        verify(mdoc, outcome.credentials, cfg.otherCa)
    }
}

/** The issuer requiring a key attestation in every jwt proof (HAIP 1.0 §4.5.1). */
suspend fun keyAttestationCases(run: Run) {
    val sdjwt = run.wallet.cfg.sdJwtConfigurationId
    val mdoc = run.wallet.cfg.mdocConfigurationId
    run.case("jwt proof with a key attestation of two keys, SD-JWT VC, authorization code") {
        val issuer = walletInitiated(listOf(sdjwt))
        val authorized = with(this) { issuer.authorizeByCode() }
        run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwtWithKeyAttestation(cfg.keyAttestationKey, 2))
        run.checkCredentialRequests()
    }
    run.case("jwt proof with a key attestation, mdoc, pre-authorized code") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(mdoc))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        run.issueAndVerify(issuer, authorized, mdoc, Proofs.jwtWithKeyAttestation(cfg.keyAttestationKey))
    }
    run.control("a jwt proof's key attestation from a signer the issuer doesn't trust", "the Credential Endpoint refuses the proof", { it is CredentialIssuanceError.InvalidProof }) {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        val (_, outcome) = with(this) { issuer.issue(authorized, sdjwt, Proofs.jwtWithKeyAttestation(cfg.otherKeyAttestationKey).spec) }
        if (outcome is SubmissionOutcome.Failed) throw outcome.error
        error("issued: $outcome")
    }
}

/** The issuer deferring every Credential Request (§9). */
suspend fun deferredCases(run: Run) {
    val sdjwt = run.wallet.cfg.sdJwtConfigurationId
    val mdoc = run.wallet.cfg.mdocConfigurationId

    suspend fun Run.deferred(
        issuer: Issuer,
        authorized: AuthorizedRequest,
        configurationId: String,
        proofs: Proofs,
        later: Boolean,
        encrypted: Boolean = false,
    ) = with(wallet) {
        val (updated, outcome) = issuer.issue(authorized, configurationId, proofs.spec)
        check(outcome is SubmissionOutcome.Deferred) { "the issuer answered $outcome" }
        ok("the issuer deferred it: a transaction_id, interval ${outcome.interval}")
        // The wallet may poll at once, or wait the interval the issuer
        // asked for (§9.2).
        if (later) delay(outcome.interval)
        val issued = with(issuer) { updated.queryForDeferredCredential(outcome.transactionId) }.getOrThrow().second
        check(issued is DeferredCredentialQueryOutcome.Issued) { "the Deferred Credential Endpoint answered $issued" }
        verifyIssued(configurationId, issued.credentials, proofs)
        expect(issued.notificationId != null, "the Deferred Credential Response carries a notification_id")
        checkCredentialRequests("/deferred_credential", encrypted)
    }

    run.case("deferred, SD-JWT VC, authorization code, polled at once") {
        val issuer = walletInitiated(listOf(sdjwt))
        val authorized = with(this) { issuer.authorizeByCode() }
        run.deferred(issuer, authorized, sdjwt, Proofs.jwt(), later = false)
    }
    run.case("deferred, mdoc batch, pre-authorized code, polled after the interval") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(mdoc))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        run.deferred(issuer, authorized, mdoc, Proofs.jwt(2), later = true)
    }
    run.case("deferred, with request and response encryption") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri, WalletOptions(encryption = true))
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        run.deferred(issuer, authorized, sdjwt, Proofs.jwt(), later = false, encrypted = true)
    }
    run.control("a transaction_id polled again once issued", "the Deferred Credential Endpoint refuses it", { isOAuthError(it, "invalid_transaction_id") }) {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(sdjwt))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        val (updated, outcome) = with(this) { issuer.issue(authorized, sdjwt, Proofs.jwt().spec) }
        check(outcome is SubmissionOutcome.Deferred) { "not deferred: $outcome" }
        val first = with(issuer) { updated.queryForDeferredCredential(outcome.transactionId) }.getOrThrow()
        check(first.second is DeferredCredentialQueryOutcome.Issued) { "not issued: ${first.second}" }
        val again = with(issuer) { first.first.queryForDeferredCredential(outcome.transactionId) }.getOrThrow().second
        if (again is DeferredCredentialQueryOutcome.Errored) throw CredentialIssuanceError.IssuanceRequestFailed(again.error, again.errorDescription)
        error("answered $again")
    }
}

/** The Authorization Server and the Credential Issuer each requiring DPoP nonces (RFC 9449 §8, §9). */
suspend fun dpopNonceCases(run: Run) {
    val sdjwt = run.wallet.cfg.sdJwtConfigurationId
    val mdoc = run.wallet.cfg.mdocConfigurationId

    fun Run.checkNonceChallenges(paths: List<String>) {
        for (path in paths) {
            val exchanges = wallet.recorder.to(path)
            val challenged = exchanges.indexOfFirst { it.status in 400..401 && it.dpopNonce }
            expect(
                challenged >= 0 && exchanges.drop(challenged + 1).any { it.status in 200..299 },
                "$path challenged a proof without a nonce (use_dpop_nonce), and the wallet retried with it",
            ) { exchanges.map { "${it.status} nonce=${it.dpopNonce} ${it.wwwAuthenticate.orEmpty()}" }.toString() }
        }
    }

    run.case("authorization code with DPoP nonces, SD-JWT VC") {
        val issuer = walletInitiated(listOf(sdjwt))
        val authorized = with(this) { issuer.authorizeByCode() }
        run.checkAuthorizationCodeRequests()
        val (updated, success) = run.issueAndVerify(issuer, authorized, sdjwt, Proofs.jwt())
        run.notifyAccepted(issuer, updated, success.notificationId)
        run.checkNonceChallenges(listOf("/par", CREDENTIAL_PATH))
    }
    run.case("pre-authorized code with DPoP nonces, mdoc") {
        val (uri, _) = offer(PRE_AUTHORIZED_CODE, listOf(mdoc))
        val issuer = fromOffer(uri)
        val authorized = with(this) { issuer.authorizeByPreAuthorizedCode() }
        run.issueAndVerify(issuer, authorized, mdoc, Proofs.jwt())
        run.checkNonceChallenges(listOf(TOKEN_PATH, CREDENTIAL_PATH))
    }
}
