// The control API run.sh drives, on loopback HTTP: it creates Credo's
// offers and requests and reports their sessions' outcomes.

import { type DcqlQuery, MdocDeviceResponse, type X509Certificate } from '@credo-ts/core'
import express from 'express'
import type { CredoAgent } from './agent.js'
import { ISSUER_ID } from './issuer.js'
import { createRequest } from './verifier.js'

export function controlApi(agent: CredoAgent, signer: X509Certificate) {
  const app = express()
  app.use(express.json())

  // An offer of the configurations by pre-authorized code, with a
  // numeric tx_code if asked for one.
  app.post('/issuer/offers', async (req, res) => {
    const body = req.body as { configuration_ids: string[]; tx_code?: boolean }
    const metadata = await agent.openid4vc.issuer.getIssuerMetadata(ISSUER_ID)
    const { credentialOffer, issuanceSession } = await agent.openid4vc.issuer.createCredentialOffer({
      issuerId: ISSUER_ID,
      version: 'v1',
      credentialConfigurationIds: body.configuration_ids,
      preAuthorizedCodeFlowConfig: {
        authorizationServerUrl: metadata.credentialIssuer.credential_issuer,
        txCode: body.tx_code ? { input_mode: 'numeric', length: 6 } : undefined,
      },
    })
    res.json({ id: issuanceSession.id, offer: credentialOffer, tx_code: issuanceSession.userPin })
  })

  app.get('/issuer/sessions/:id', async (req, res) => {
    const session = await agent.openid4vc.issuer.getIssuanceSessionById(req.params.id)
    res.json({ state: session.state, error: session.errorMessage })
  })

  app.post('/verifier/requests', async (req, res) => {
    const body = req.body as { query: DcqlQuery; signed: boolean }
    res.json(await createRequest(agent, signer, body.query, body.signed))
  })

  // A verification session's state, its error, and, once verified, the
  // claims of each credential presented, by query id.
  app.get('/verifier/sessions/:id', async (req, res) => {
    const session = await agent.openid4vc.verifier.getVerificationSessionById(req.params.id)
    let presented: Record<string, unknown> | undefined
    if (session.state === 'ResponseVerified') {
      const verified = await agent.openid4vc.verifier.getVerifiedAuthorizationResponse(session.id)
      presented = Object.fromEntries(
        Object.entries(verified.dcql?.presentations ?? {}).map(([id, list]) => [
          id,
          // An SD-JWT VC's disclosed claims; an mdoc device response's
          // issuer-signed elements.
          list.map((p) => (p instanceof MdocDeviceResponse ? p.issuerClaims : 'prettyClaims' in p ? p.prettyClaims : undefined)),
        ])
      )
    }
    res.json({ state: session.state, error: session.errorMessage, presented })
  })

  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ error: String(error instanceof Error ? error.message : error) })
  })
  return app
}
