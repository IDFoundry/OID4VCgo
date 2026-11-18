// The Credo agent: Askar's storage and key management, in memory, and
// the OpenID4VC module as Credential Issuer and Verifier on one Express
// app, and as holder.

import { AskarModule } from '@credo-ts/askar'
import {
  Agent,
  ConsoleLogger,
  type GetTrustedIssuersForVerification,
  type LogLevel,
  type VerificationSigner,
} from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { OpenId4VcModule } from '@credo-ts/openid4vc'
import { NativeAskar } from '@openwallet-foundation/askar-nodejs'
import type { Express } from 'express'
import { type Config, credentialMapper } from './issuer.js'

export function createAgent(app: Express, baseUrl: string, config: Config, logLevel: LogLevel) {
  return new Agent({
    config: { logger: new ConsoleLogger(logLevel), getTrustedIssuersForVerification: trust(config) },
    dependencies: agentDependencies,
    modules: {
      askar: new AskarModule({
        askar: NativeAskar,
        store: { id: 'credo-interop', key: 'credo-interop', database: { type: 'sqlite', config: { inMemory: true } } },
      }),
      openid4vc: new OpenId4VcModule({
        app,
        issuer: {
          baseUrl: `${baseUrl}/oid4vci`,
          // As HAIP 1.0 has it: every Token Request DPoP-bound and
          // carrying a Wallet Attestation.
          dpopRequired: true,
          walletAttestationsRequired: true,
          credentialRequestToCredentialMapper: credentialMapper,
        },
        verifier: { baseUrl: `${baseUrl}/oid4vp` },
      }),
    },
  })
}

export type CredoAgent = ReturnType<typeof createAgent>

// trust is what each verification trusts, by its type: the issuer's
// Wallet Attestations and Key Attestations the Wallet Provider's CA;
// the Verifier's credentials the run's CA and IACA; the holder's
// credentials (as it receives them) OID4VCgo's issuer's CA and IACA,
// and its requests (x509_hash) OID4VCgo's verifiers' CA; anything else
// signed under x5c nothing.
function trust(config: Config): GetTrustedIssuersForVerification<VerificationSigner, { type: string }> {
  return (_agentContext, { signer, verification }) => {
    if (signer.method !== 'x509') return Promise.resolve(undefined)
    switch (verification.type) {
      case 'oauth2ClientAttestation':
      case 'openId4VciKeyAttestation':
        return Promise.resolve({ trustedIssuers: [{ method: 'x509', issuance: config.attester_anchors }] })
      case 'openId4VpCredential':
        return Promise.resolve({ trustedIssuers: [{ method: 'x509', issuance: config.credential_anchors }] })
      case 'credential':
        return Promise.resolve({ trustedIssuers: [{ method: 'x509', issuance: config.holder_credential_anchors }] })
      case 'oauth2SecuredAuthorizationRequest':
        return Promise.resolve({ trustedIssuers: [{ method: 'x509', issuance: config.holder_request_anchors }] })
      default:
        return Promise.resolve({ trustedIssuers: [] })
    }
  }
}
