// Credo's holder (wallet): it receives credentials by pre-authorized
// code, attested by OID4VCgo's Wallet Provider through its agent
// (interop/walletprovider's "agent": POST /wallet-attestation and POST
// /key-attestation), and presents them to OpenID4VP 1.0 requests.
//
// Each answer names the stage it reached, and the error that stopped
// it, so that run.sh can tell a refusal from a failure elsewhere.

import { ClaimFormat, Kms, MdocRecord, SdJwtVcRecord } from '@credo-ts/core'
import type {
  OpenId4VcCredentialHolderBinding,
  OpenId4VciCredentialBindingOptions,
  OpenId4VciCredentialResponse,
  OpenId4VciDeferredCredentialResponse,
  OpenId4VciDpopRequestOptions,
  OpenId4VciResolvedCredentialOffer,
} from '@credo-ts/openid4vc'
import type { CredoAgent } from './agent.js'
import { remember, withKeysByThumbprint } from './keylookup.js'

export interface ReceiveRequest {
  offer: string
  tx_code?: string
  client_id: string
  // The Wallet Provider's agent, by its name in the driver's config
  // (Config.wallet_providers): the driver fetches only the URLs it was
  // started with.
  wallet_provider: string
  // false lets Credo look up the attested keys by kid alone, as it does
  // (keylookup.ts): the run's note on README finding 6.
  keys_by_thumbprint?: boolean
  // false asks the Wallet Provider for Key Attestations without the
  // c_nonce, which Credo then sends in a jwt proof's key_attestation
  // header, the proof carrying the c_nonce, rather than as the
  // attestation proof type.
  key_attestation_nonce?: boolean
}

export interface Received {
  id: string
  format: string
  configuration_id: string
  // An SD-JWT VC's status list entry, which run.sh revokes.
  status?: { uri: string; idx: number }
}

export interface ReceiveResult {
  stage: string
  error?: string
  token_type?: string
  key_attestation?: boolean
  proof_types: string[]
  deferred?: number
  received: Received[]
}

// DEFERRED_POLLS bounds how often a deferred credential is polled for.
const DEFERRED_POLLS = 5

export async function receive(agent: CredoAgent, req: ReceiveRequest): Promise<ReceiveResult> {
  const result: ReceiveResult = { stage: 'offer', proof_types: [], received: [] }
  try {
    await withKeysByThumbprint(req.keys_by_thumbprint !== false, () => receiveInto(agent, req, result))
    result.stage = 'done'
  } catch (error) {
    result.error = errorText(error)
  }
  return result
}

async function receiveInto(agent: CredoAgent, req: ReceiveRequest, result: ReceiveResult) {
  const holder = agent.openid4vc.holder
  const offer = await holder.resolveCredentialOffer(req.offer)

  result.stage = 'wallet-attestation'
  const instanceKey = await newKey(agent)
  const walletAttestationJwt = await attest(req.wallet_provider, '/wallet-attestation', {
    client_id: req.client_id,
    instance_key: bareJwk(instanceKey),
  })

  result.stage = 'token'
  const token = await holder.requestToken({ resolvedCredentialOffer: offer, txCode: req.tx_code, walletAttestationJwt })
  result.token_type = token.accessTokenResponse.token_type

  result.stage = 'credential'
  const resolver = bindingResolver(agent, req, instanceKey, result)
  const issued = await holder.requestCredentials({
    resolvedCredentialOffer: offer,
    accessToken: token.accessToken,
    cNonce: token.cNonce,
    dpop: token.dpop,
    credentialBindingResolver: resolver,
  })
  for (const c of issued.credentials) result.received.push(await store(agent, c))

  if (issued.deferredCredentials.length > 0) {
    result.stage = 'deferred'
    result.deferred = issued.deferredCredentials.length
    for (const d of issued.deferredCredentials) {
      result.received.push(await store(agent, await pollDeferred(agent, offer, d, token.accessToken, issued.dpop ?? token.dpop)))
    }
  }
}

// bindingResolver binds each credential to a new key: by its JWK, or,
// where the configuration's jwt proof requires a key attestation (or it
// takes only the attestation proof type), by a Key Attestation from the
// Wallet Provider over the key and the c_nonce. With the c_nonce in it,
// Credo sends it as the attestation proof type where the issuer takes
// that, and otherwise (or without the c_nonce in it) in a jwt proof's
// key_attestation header (Appendix F): result.proof_types records which.
function bindingResolver(agent: CredoAgent, req: ReceiveRequest, instanceKey: Kms.PublicJwk, result: ReceiveResult) {
  const withNonce = req.key_attestation_nonce !== false
  return async (options: OpenId4VciCredentialBindingOptions): Promise<OpenId4VcCredentialHolderBinding> => {
    const key = await newKey(agent)
    const { jwt, attestation } = options.proofTypes
    if (jwt ? !jwt.keyAttestationsRequired : !attestation) {
      result.proof_types.push('jwt')
      return { method: 'jwk', keys: [key] }
    }
    result.key_attestation = true
    result.proof_types.push(attestation && withNonce ? 'attestation' : 'jwt+key_attestation')
    const keyAttestationJwt = await attest(req.wallet_provider, '/key-attestation', {
      instance_key: bareJwk(instanceKey),
      keys: [bareJwk(key)],
      nonce: withNonce ? options.cNonce : '',
    })
    return { method: 'attestation', keyAttestationJwt }
  }
}

async function pollDeferred(
  agent: CredoAgent,
  offer: OpenId4VciResolvedCredentialOffer,
  deferred: OpenId4VciDeferredCredentialResponse,
  accessToken: string,
  dpop: OpenId4VciDpopRequestOptions | undefined
): Promise<OpenId4VciCredentialResponse> {
  let pending = deferred
  let currentDpop = dpop
  for (let i = 0; i < DEFERRED_POLLS; i++) {
    await sleep(Math.min(pending.interval ?? 1, 5) * 1000)
    const polled = await agent.openid4vc.holder.requestDeferredCredentials({
      issuerMetadata: offer.metadata,
      transactionId: pending.transactionId,
      credentialConfigurationId: pending.credentialConfigurationId,
      credentialConfiguration: pending.credentialConfiguration,
      accessToken,
      dpop: currentDpop,
      jwkThumbprintKmsKeyIdMapping: deferred.jwkThumbprintKmsKeyIdMapping,
    })
    currentDpop = polled.dpop ?? currentDpop
    if (polled.credentials.length > 0) return polled.credentials[0]
    pending = polled.deferredCredentials[0] ?? pending
  }
  throw new Error(`deferred credential ${deferred.transactionId} not issued after ${DEFERRED_POLLS} polls`)
}

async function store(agent: CredoAgent, c: OpenId4VciCredentialResponse): Promise<Received> {
  if (c.record instanceof SdJwtVcRecord) {
    const record = await agent.sdJwtVc.store({ record: c.record })
    const payload = jwtPayload(record.credentialInstances[0].compactSdJwtVc)
    const list = (payload.status as { status_list?: { uri: string; idx: number } } | undefined)?.status_list
    return { id: record.id, format: ClaimFormat.SdJwtDc, configuration_id: c.credentialConfigurationId, status: list }
  }
  if (c.record instanceof MdocRecord) {
    const record = await agent.mdoc.store({ record: c.record })
    return { id: record.id, format: ClaimFormat.MsoMdoc, configuration_id: c.credentialConfigurationId }
  }
  throw new Error(`unexpected credential record for ${c.credentialConfigurationId}`)
}

export interface PresentRequest {
  request: string
  // The stored credential to present for each credential query, by id.
  credentials: Record<string, string>
}

export interface PresentResult {
  stage: string
  error?: string
  status?: number
  body?: unknown
}

// present answers the request with the credentials it names, as
// Credo's holder selects them: only what the query asks for disclosed.
export async function present(agent: CredoAgent, req: PresentRequest): Promise<PresentResult> {
  const result: PresentResult = { stage: 'request' }
  try {
    const holder = agent.openid4vc.holder
    const resolved = await holder.resolveOpenId4VpAuthorizationRequest(req.request)
    result.stage = 'select'
    const queryResult = resolved.dcql?.queryResult
    if (!queryResult) throw new Error('the request has no DCQL query')
    for (const [queryId, recordId] of Object.entries(req.credentials)) {
      const match = queryResult.credential_matches[queryId]
      if (!match?.success) continue
      const named = match.valid_credentials.filter((m) => (m as unknown as { record: { id: string } }).record.id === recordId)
      if (named.length === 0) throw new Error(`credential ${recordId} doesn't answer query ${queryId}`)
      match.valid_credentials = named as typeof match.valid_credentials
    }
    const credentials = holder.selectCredentialsForDcqlRequest(queryResult)
    result.stage = 'response'
    const answer = await holder.acceptOpenId4VpAuthorizationRequest({
      authorizationRequestPayload: resolved.authorizationRequestPayload,
      dcql: { credentials },
    })
    result.status = answer.serverResponse?.status
    result.body = answer.serverResponse?.body
    if (!answer.ok) throw new Error(`the Verifier answered ${answer.serverResponse.status}`)
    result.stage = 'done'
  } catch (error) {
    result.error = errorText(error)
  }
  return result
}

async function newKey(agent: CredoAgent) {
  const { publicJwk } = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
  const jwk = Kms.PublicJwk.fromPublicJwk(publicJwk)
  remember(jwk)
  return jwk
}

// bareJwk is jwk's public key alone, as the Wallet Provider takes it.
function bareJwk(jwk: Kms.PublicJwk) {
  const { kty, crv, x, y } = jwk.toJson() as unknown as Record<string, string>
  return { kty, crv, x, y }
}

// walletProviders is the Wallet Provider agents' base URLs, by name, from
// the driver's config.
const walletProviders = new Map<string, string>()

// setWalletProviders sets walletProviders, from Config.wallet_providers.
export function setWalletProviders(providers: Record<string, string>) {
  walletProviders.clear()
  for (const [name, url] of Object.entries(providers)) walletProviders.set(name, url)
}

// attestationEndpoints is the Wallet Provider agent's two routes.
const attestationEndpoints = new Set(['/wallet-attestation', '/key-attestation'])

// attest asks the Wallet Provider's agent named provider for an
// attestation: its JWT.
async function attest(provider: string, path: string, body: unknown): Promise<string> {
  const base = walletProviders.get(provider)
  if (base === undefined) throw new Error(`no Wallet Provider named ${JSON.stringify(provider)} in the driver's config`)
  if (!attestationEndpoints.has(path)) throw new Error(`not a Wallet Provider agent route: ${path}`)
  const response = await fetch(new URL(path, base), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const text = await response.text()
  if (!response.ok) throw new Error(`the Wallet Provider's agent answered ${response.status}: ${text.trim()}`)
  return (JSON.parse(text) as { jwt: string }).jwt
}

function jwtPayload(compact: string): Record<string, unknown> {
  const jwt = compact.split('~')[0]
  return JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString('utf8'))
}

// errorText is an error's message, and its cause's: Credo wraps the
// server's error response in its cause, or in its own fields.
function errorText(error: unknown): string {
  const parts: string[] = []
  let e: unknown = error
  for (let depth = 0; e && depth < 4; depth++) {
    if (e instanceof Error) {
      parts.push(e.message)
      const extra = e as { errorResponse?: unknown; response?: { body?: unknown } }
      if (extra.errorResponse) parts.push(JSON.stringify(extra.errorResponse))
      e = e.cause
    } else {
      // A thrown value that isn't an Error, such as an error
      // response: its fields, not "[object Object]".
      parts.push(typeof e === 'object' ? jsonText(e) : String(e as string | number | boolean | bigint | symbol))
      e = undefined
    }
  }
  return parts.join(' | ')
}

// jsonText is v as JSON, or its tag when it has none, as for a cycle.
function jsonText(v: unknown): string {
  try {
    return JSON.stringify(v)
  } catch {
    return Object.prototype.toString.call(v)
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
