// Credo's Credential Issuer: an SD-JWT VC PID signed under x5c, and an
// mDL signed by a Document Signer under the run's IACA, both bound to
// the wallet's jwk.

import { type Agent, ClaimFormat, Kms, X509Certificate } from '@credo-ts/core'
import {
  type OpenId4VciCredentialConfigurationsSupportedWithFormats,
  OpenId4VciCredentialFormatProfile,
  type OpenId4VciCredentialRequestToCredentialMapper,
  type OpenId4VciSignMdocCredentials,
  type OpenId4VciSignSdJwtCredentials,
} from '@credo-ts/openid4vc'

// Config is the setup's credo.json, plus attester_anchors, which run.sh
// adds: the Wallet Provider's CA.
export interface Config {
  tls_cert_pem: string
  tls_key_pem: string
  issuer: Signer
  mdoc_signer: Signer
  verifier: Signer
  credential_anchors: string[]
  attester_anchors: string[]
}

// Signer is a private JWK and its certificate chain, base64 DER, leaf
// first.
export interface Signer {
  key: Record<string, string>
  x5c: string[]
}

export const ISSUER_ID = 'credo'
export const PID_SD_JWT = 'pid-sd-jwt'
export const MDL_MDOC = 'mdl-mdoc'
const PID_VCT = 'urn:eudi:pid:1'
const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL'
const MDL_NAMESPACE = 'org.iso.18013.5.1'

const proofTypes = {
  jwt: { proof_signing_alg_values_supported: [Kms.KnownJwaSignatureAlgorithms.ES256] },
}

export const credentialConfigurations = {
  [PID_SD_JWT]: {
    format: OpenId4VciCredentialFormatProfile.SdJwtDc,
    vct: PID_VCT,
    scope: PID_SD_JWT,
    cryptographic_binding_methods_supported: ['jwk'],
    credential_signing_alg_values_supported: [Kms.KnownJwaSignatureAlgorithms.ES256],
    proof_types_supported: proofTypes,
  },
  [MDL_MDOC]: {
    format: OpenId4VciCredentialFormatProfile.MsoMdoc,
    doctype: MDL_DOCTYPE,
    scope: MDL_MDOC,
    cryptographic_binding_methods_supported: ['cose_key'],
    credential_signing_alg_values_supported: [Kms.KnownCoseSignatureAlgorithms.ES256],
    proof_types_supported: proofTypes,
  },
} satisfies OpenId4VciCredentialConfigurationsSupportedWithFormats

let sdJwtSigner: X509Certificate
let mdocSigner: X509Certificate
let issuerIdentifier: string

// issuerCertificates imports the issuer's two signing keys into the
// agent's key management and binds each certificate to its key; its
// SD-JWT VCs name identifier, the Credential Issuer Identifier, as iss.
export async function issuerCertificates(agent: Agent, config: Config, identifier: string) {
  sdJwtSigner = await certificateWithKey(agent, config.issuer)
  mdocSigner = await certificateWithKey(agent, config.mdoc_signer)
  issuerIdentifier = identifier
}

// certificateWithKey is signer's leaf certificate, its key imported.
export async function certificateWithKey(agent: Agent, signer: Signer) {
  const { keyId } = await agent.kms.importKey({ privateJwk: signer.key as unknown as Kms.KmsJwkPrivate })
  const certificate = X509Certificate.fromEncodedCertificate(signer.x5c[0])
  certificate.keyId = keyId
  return certificate
}

// credentialMapper issues each configuration's credential, one per
// holder key.
export const credentialMapper: OpenId4VciCredentialRequestToCredentialMapper = ({
  holderBinding,
  credentialConfigurationId,
}) => {
  if (credentialConfigurationId === PID_SD_JWT) {
    return {
      type: 'credentials',
      format: ClaimFormat.SdJwtDc,
      credentials: holderBinding.keys.map((holder) => ({
        payload: {
          vct: PID_VCT,
          given_name: 'Erika',
          family_name: 'Mustermann',
          birthdate: '1964-08-12',
          nationalities: ['DE'],
        },
        holder,
        issuer: { method: 'x5c', x5c: [sdJwtSigner], issuer: issuerIdentifier },
        disclosureFrame: { _sd: ['given_name', 'family_name', 'birthdate', 'nationalities'] },
      })),
    } satisfies OpenId4VciSignSdJwtCredentials
  }
  if (credentialConfigurationId === MDL_MDOC) {
    const now = new Date()
    return {
      type: 'credentials',
      format: ClaimFormat.MsoMdoc,
      credentials: holderBinding.keys.map((holder) => {
        if (holder.method !== 'jwk') throw new Error('an mdoc is bound to a jwk')
        return {
          docType: MDL_DOCTYPE,
          validityInfo: { validUntil: new Date(now.getTime() + 30 * 24 * 3600 * 1000) },
          issuerCertificate: mdocSigner,
          holderKey: holder.jwk,
          namespaces: {
            [MDL_NAMESPACE]: {
              given_name: 'Erika',
              family_name: 'Mustermann',
              issuing_country: 'AT',
              document_number: 'CREDO-1',
            },
          },
        }
      }),
    } satisfies OpenId4VciSignMdocCredentials
  }
  throw new Error(`no credential for configuration ${credentialConfigurationId}`)
}
