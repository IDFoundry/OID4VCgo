// Credo (credo-ts) for interop/credo/run.sh: one agent that is an
// OpenID4VCI 1.0 Credential Issuer and an OpenID4VP 1.0 Verifier, its
// protocol endpoints served over HTTPS at --base-url (on loopback
// --port), and a control API on loopback HTTP (--control-port), which
// run.sh drives with curl (control.ts):
//
//   POST /issuer/offers        {configuration_ids, tx_code}  -> {id, offer, tx_code}
//   GET  /issuer/sessions/ID                                -> {state, error}
//   POST /verifier/requests    {query, signed}               -> {id, request}
//   GET  /verifier/sessions/ID                              -> {state, error, presented}
//
// --config is the setup's credo.json (keys, certificate chains, trust
// anchors), with run.sh's attester_anchors. A holder role, for the
// directions where OID4VCgo issues and verifies, would be a third set
// of routes on the same control API, and the OpenID4VC module's holder
// on the same agent.
//
// It prints one JSON line once it serves: {"ready": true, ...}.

import { readFileSync } from 'node:fs'
import { createServer } from 'node:https'
import { LogLevel } from '@credo-ts/core'
import express from 'express'
import { createAgent } from './agent.js'
import { controlApi } from './control.js'
import { type Config, credentialConfigurations, ISSUER_ID, issuerCertificates } from './issuer.js'
import { requestSigner, VERIFIER_ID } from './verifier.js'

function arg(argv: string[], name: string, fallback?: string) {
  const i = argv.indexOf(`--${name}`)
  if (i >= 0 && i + 1 < argv.length) return argv[i + 1]
  if (fallback !== undefined) return fallback
  throw new Error(`--${name} is required`)
}

const logLevels: Record<string, LogLevel> = {
  debug: LogLevel.Debug,
  info: LogLevel.Info,
  warn: LogLevel.Warn,
  error: LogLevel.Error,
}

async function main() {
  const argv = process.argv.slice(2)
  const baseUrl = arg(argv, 'base-url')
  const logLevel = logLevels[arg(argv, 'log-level', 'warn')]
  if (logLevel === undefined) throw new Error(`--log-level is one of ${Object.keys(logLevels).join(', ')}`)
  const config = JSON.parse(readFileSync(arg(argv, 'config'), 'utf8')) as Config

  const app = express()
  const agent = createAgent(app, baseUrl, config, logLevel)
  await agent.initialize()

  await agent.openid4vc.issuer.createIssuer({
    issuerId: ISSUER_ID,
    credentialConfigurationsSupported: credentialConfigurations,
    dpopSigningAlgValuesSupported: ['ES256'],
    clientAttestationSigningAlgValuesSupported: ['ES256'],
    clientAttestationPopSigningAlgValuesSupported: ['ES256'],
  })
  const metadata = await agent.openid4vc.issuer.getIssuerMetadata(ISSUER_ID)
  await issuerCertificates(agent, config, metadata.credentialIssuer.credential_issuer)
  await agent.openid4vc.verifier.createVerifier({ verifierId: VERIFIER_ID })
  const signer = await requestSigner(agent, config)

  const server = createServer({ cert: config.tls_cert_pem, key: config.tls_key_pem }, app)
  await new Promise<void>((resolve) => server.listen(Number(arg(argv, 'port')), '127.0.0.1', resolve))
  const control = controlApi(agent, signer).listen(Number(arg(argv, 'control-port')), '127.0.0.1')
  await new Promise<void>((resolve) => control.on('listening', resolve))

  console.log(JSON.stringify({ ready: true, credential_issuer: metadata.credentialIssuer.credential_issuer }))

  const stop = async () => {
    server.close()
    control.close()
    await agent.shutdown()
    process.exit(0)
  }
  process.on('SIGTERM', stop)
  process.on('SIGINT', stop)
}

main().catch((error) => {
  console.error(JSON.stringify({ ready: false, error: String(error?.stack ?? error) }))
  process.exit(1)
})
