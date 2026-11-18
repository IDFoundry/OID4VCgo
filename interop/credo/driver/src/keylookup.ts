// Credo signs with a key its key management names by the JWK's kid
// (Kms.PublicJwk.keyId), and has no other way to find it: a JWK without
// a kid can't be signed with. A Wallet Attestation's cnf.jwk and a Key
// Attestation's attested_keys are the Wallet Provider's copies of the
// wallet's public keys, and nothing asks them to carry the kid the
// wallet's key management gave them; OID4VCgo's Wallet Provider's
// don't. So Credo's holder can neither sign the Client Attestation PoP
// nor use the attested keys (README finding 6).
//
// withKeysByThumbprint runs fn with keyId answering, for a JWK without a
// kid, the key management's id of the key the holder made with the same
// JWK thumbprint (remember): what Credo would need to do itself. Outside
// it, keyId is Credo's own, so the run can show the finding.

import { AsyncLocalStorage } from 'node:async_hooks'
import { Kms, TypedArrayEncoder } from '@credo-ts/core'

const byThumbprint = new Map<string, string>()
const scope = new AsyncLocalStorage<boolean>()

function thumbprint(jwk: Kms.PublicJwk) {
  return TypedArrayEncoder.toBase64Url(jwk.getJwkThumbprint())
}

// remember records a key the holder made, by its JWK's thumbprint.
export function remember(jwk: Kms.PublicJwk) {
  byThumbprint.set(thumbprint(jwk), jwk.keyId)
}

export function withKeysByThumbprint<T>(enabled: boolean, fn: () => Promise<T>): Promise<T> {
  return scope.run(enabled, fn)
}

const keyId = Object.getOwnPropertyDescriptor(Kms.PublicJwk.prototype, 'keyId')
if (!keyId?.get || !keyId.set) throw new Error('Kms.PublicJwk has no keyId accessor to extend')
const credoKeyId = keyId.get
Object.defineProperty(Kms.PublicJwk.prototype, 'keyId', {
  configurable: true,
  set: keyId.set,
  get(this: Kms.PublicJwk) {
    if (!this.hasKeyId && scope.getStore()) {
      const id = byThumbprint.get(thumbprint(this))
      if (id) return id
    }
    return credoKeyId.call(this)
  },
})
