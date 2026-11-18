// Credo's Verifier: a DCQL request signed with its Access Certificate's
// key, as an x509_hash client, the response encrypted (direct_post.jwt);
// or, for the control, the request unsigned, which Credo can only send
// as a redirect_uri client.

import type { Agent, DcqlQuery, X509Certificate } from '@credo-ts/core'
import type { CredoAgent } from './agent.js'
import { certificateWithKey, type Config } from './issuer.js'

export const VERIFIER_ID = 'credo'

export async function requestSigner(agent: Agent, config: Config): Promise<X509Certificate> {
  return certificateWithKey(agent, config.verifier)
}

// createRequest is a request for query, signed by signer unless signed
// is false: its verification session's id and the request's URI.
export async function createRequest(agent: CredoAgent, signer: X509Certificate, query: DcqlQuery, signed: boolean) {
  const { authorizationRequest, verificationSession } = await agent.openid4vc.verifier.createAuthorizationRequest({
    verifierId: VERIFIER_ID,
    version: 'v1',
    responseMode: 'direct_post.jwt',
    requestSigner: signed ? { method: 'x5c', x5c: [signer], clientIdPrefix: 'x509_hash' } : { method: 'none' },
    dcql: { query },
  })
  return { id: verificationSession.id, request: authorizationRequest }
}
