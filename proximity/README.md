# proximity: driving it from Kotlin or Swift

`proximity` does the ISO/IEC 18013-5 protocol: engagement, session
encryption, request and response. The app does the radio work. Over BLE,
the app's job is to:

1. advertise or scan for the service UUID,
2. connect and set up the GATT characteristics,
3. split each message into chunks and reassemble them, and
4. pass whole messages to and from this package.

This file covers BLE GATT and NFC engagement. Go supports QR, static
and negotiated handover for BLE and NFC-only carriers. Over NFC, the
byte protocols — the Type 4 Tag, TNEP, and classic NFC message transfer
— are Go too, in [`nfcapdu`](nfcapdu): the app only moves APDUs (see
[NFC APDUs](#nfc-apdus) and the
[Android guide](../mobile/android/docs/PresentingInPerson.md)).
BLE L2CAP is not supported.

## NFC engagement messages

For static handover, `NewNFCDeviceSession(nil, WithBLEModes(...))`
creates one stable engagement. Expose `HandoverSelect()` as the Type 4
NDEF file payload, with NLEN added by the platform. Reuse the same
session for repeated reads. `NewNFCReaderSession(hs, readerOptions...)`
selects its BLE carrier. Static roles share the advertised UUID; the
existing BLE GATT transport, reader trust and consent flow then apply.

For negotiated handover, the holder starts with
`NewNFCNegotiatedDeviceSession` and passes a complete Hr to
`HandleHandoverRequest`. The reader retains the exact output of
`NewNFCHandoverRequest`, performs the platform TNEP exchange, and passes
the received Hs and retained Hr to `NewNFCNegotiatedReaderSession`.
The negotiated mdoc central-client UUID comes from Hr; its Hs omits it.
A second identical Hr returns the same Hs before establishment; another
request cannot replace the accepted transcript.

NDEF parsing is bounded by `MaxNDEFBytes` (65535), supports short and
normal-length records, and rejects chunked records and malformed IDs,
references or message boundaries. The exact received Hs/Hr bytes enter
the session transcript; do not parse and regenerate messages before
passing them into the constructors.

For classic NFC-only retrieval, use `NewNFCDataDeviceSession` with
`NFCDataParameters` and `NewNFCDataReaderSession`. Carrier parsing is
available through `ParseNFCDataHandover`. For TNEP NFC-only, use
`NewNFCNegotiatedDataDeviceSession`,
`NewNFCHandoverRequestWithNFCData`, and `NewNFCNegotiatedDataReaderSession`.
The reader checks the selected limits against its original offer.
`nfcapdu` wraps complete encrypted messages in DO53 and implements
ENVELOPE/GET RESPONSE. Unit tests include the exact Annex D
negotiated transcript and credential verification for all three paths;
real-device interoperability and specification review remain required
before claiming conformance.

The BLE details below follow ISO/IEC 18013-5:2021 §8.3.3.1.1 (Tables 11–13),
cross-checked against [Multipaz](https://github.com/openwallet-foundation/multipaz)'s
BLE transport (`multipaz/src/commonMain/.../mdoc/transport/`).

## Roles

The mdoc picks the BLE modes in its QR code (`WithBLEMode`, or
`WithBLEModes` for both, each with its own service UUID:
`PeripheralServerUUID`, `CentralClientUUID`). The reader
learns it from `ReaderSession.BLEMode()`. If an engagement offers both
modes, the reader picks central client mode, as §8.3.3.1.1.1 recommends.

| | mdoc peripheral server mode (default) | mdoc central client mode |
|---|---|---|
| GATT server, advertises the service UUID | mdoc | reader |
| GATT client, scans and connects | reader | mdoc |
| Characteristic UUID base | `0000000N-a123-48ce-896b-4c76973373e6` | same |
| State | N = `1` | N = `5` |
| Client2Server | N = `2` | N = `6` |
| Server2Client | N = `3` | N = `7` |
| Ident | not used | N = `8` |

The service UUID is `ServiceUUID()` on either session. It's random for
each session.

Characteristic properties:

| Characteristic | Properties |
|---|---|
| State | notify, write without response |
| Client2Server | write without response |
| Server2Client | notify |
| Ident | read |

Each side writes on one characteristic and receives on the other.
Whichever side is the GATT **client** writes its messages to
Client2Server. The GATT **server** sends its messages as Server2Client
notifications.

## Connection sequence

1. **Engage.** The mdoc calls `NewDeviceSession`, then shows `QRCode()`.
   The reader scans the QR code and calls `NewReaderSession(qr, opts...)`, with the decisions step 6 lists.
2. **Connect.** The GATT server advertises `ServiceUUID()`. The GATT
   client scans for it, connects, and negotiates the MTU.
3. **Check Ident (central client mode only).** The reader serves
   `ReaderSession.BLEIdent()` on the Ident characteristic. The mdoc
   reads it and disconnects if it differs from `DeviceSession.BLEIdent()`.
4. **Subscribe and start.** The GATT client subscribes to State and
   Server2Client notifications, then writes `0x01` (start) to State.
5. **Request.** The reader sends `Establishment(docType, elements)`. The
   mdoc passes it to `HandleSessionEstablishment`, then
   `ParseDeviceRequest`, then `VerifyReaderAuth` with its trusted reader
   roots, and shows a consent prompt: who is asking, what, and whether
   the reader says it will keep each element. A reader that passes
   `NewReaderSession` `WithReaderAuth(key, chain)` signs its request
   (§9.1.4). `VerifyReaderAuth`'s `Status` is one of:
   - **`ReaderTrusted`:** the signature verifies, by a certificate that
     chains to the roots. `Chain[0]` names the reader.
   - **`ReaderUntrusted`:** the signature verifies, but the certificate
     doesn't chain to the roots, or fails the `LeafPolicy`
     (`RequireReaderAuthenticationEKU`). Show the name it claims, as
     unverified.
   - **`ReaderUnauthenticated`:** no readerAuth. Anyone who scanned the
     QR code can send a request. Reader authentication is optional, and
     an mDL must release its mandatory elements without it (§7.2.1).
   - **`ReaderInvalid`:** a readerAuth that's malformed, or doesn't sign
     this session's request: possibly replayed. Refuse it, or treat it
     as unauthenticated.
6. **Respond.** If the user consents, the mdoc sends
   `Encrypt(BuildDeviceResponse(req, ...), false)`, disclosing only
   elements the request lists (any other is refused). If they decline, or
   nothing matches, the mdoc sends `Termination()` instead. The reader
   passes either one to `Verify(ctx, msg, roots, now)`. A reader makes
   a Verifier's decisions when it calls `NewReaderSession`: its
   assurance (`WithAssurance`) and its document signers' revocation
   (`WithIssuerRevocation(certrevocation.CRLs{...})`, or
   `certrevocation.NoCheck{}` to decline) always, and under
   `verifier.AssuranceProduction` which issuers may issue which
   document types (`WithIssuerAuthorization` or
   `WithAnyIssuerForAnyType`) and the documents' status
   (`WithStatus(&verifier.StatusPolicy{...})`, checked in `Verify`
   against the MSO's status list or identifier list, or
   `WithNoStatusCheck`). `Verified.Credential()` is the document as a
   `verifier.VerifiedCredential`, for checking its status after `Verify`.
   A reader can pass `NewReaderSession`
   `WithMaxClockSkew` — so an mdoc issued by a clock a little ahead of
   the reader's isn't refused as not yet valid. By default only document
   signer certificates issued for that purpose, with the mDL document
   signer extended key usage, are accepted;
   `WithDocumentSignerPolicy(mdoc.LenientDocumentSignerPolicy)` also
   accepts one without an extended key usage.
7. **End.** Either side can end the session. Send a `Termination()`
   message (status 20), or write `0x02` (end) to State. Treat a `0x02`
   from the other side the same way. The GATT client then unsubscribes
   from State and Server2Client and disconnects (§8.3.3.1.1.7).
8. **Lost connection.** Before State was set to `0x01`, reconnect. After
   it, don't: start a new session with a new `NewDeviceSession`
   (§8.3.3.1.1.8).

## Chunking

A message can be larger than one characteristic write. Split it into
chunks, each of these:

```
[ 1 prefix byte ][ up to (chunk size − 1) message bytes ]
  0x01 = more chunks follow
  0x00 = last chunk
```

Use a chunk size of `MTU − 3` bytes, prefix included (§8.3.3.1.1.6),
capped at 512 — the most a GATT attribute value can hold, and what
Multipaz and the second-edition draft use. The receiver strips the prefix bytes and appends
the rest. On a `0x00` chunk, it passes the whole message to this
package. Any other prefix value is a protocol error: disconnect.

This package never sees chunks, only whole messages.

## Timeouts

These are the app's to enforce. The spec recommends allowing at least
30 seconds from engagement to the SessionEstablishment (§8.2.3), and at
least 300 seconds of inactivity before ending a session (§9.1.1.4).

## Errors

Each `DeviceSession` and `ReaderSession` method that takes a message
returns an error when the message is bad. Map it to a reply with
`StatusFor(err)`:

- **`ok == true`:** send `StatusMessage(status)` (`{status: 10}` or
  `{status: 11}`, unencrypted), then disconnect. The session is closed.
- **`ok == false`:** the error is a verification failure, or the session
  was already closed. Show the error and disconnect.

A `ParseDeviceRequest` error is a request that decrypted but isn't a
valid DeviceRequest: `ErrCBORDecoding` for bytes that aren't CBOR,
`ErrCBORValidation` for CBOR of the wrong shape. The holder can answer
it inside the session instead, with `ErrorResponse(err)`: an encrypted
DeviceResponse with no documents and status 11 or 12 (§8.3.2.1.2.3),
which also ends the session. The reader's `Verify` returns it as a
`*DeviceResponseStatusError`.

`MaxMessageBytes` (2 MiB) caps every message. Reassembly can drop a
message as soon as it grows past that, instead of buffering it.

## Sketch (holder, peripheral server mode)

This is pseudocode against this package's API. Apps use the mobile
libraries' `ProximityPresentation` and `ProximityReader` instead (see
[`mobile/`](../mobile)), which wrap it and carry the GATT side.

```kotlin
val session = Proximity.newDeviceSession(null)
showQr(session.qrCode())
gattServer.advertise(session.serviceUUID())

onMessage { msg ->            // a reassembled Client2Server message
  try {
    val req = try {
      Proximity.parseDeviceRequest(session.handleSessionEstablishment(msg))
    } catch (e: ParseError) {             // decrypted, but not a DeviceRequest
      sendChunked(session.errorResponse(e)); disconnect(); return
    }
    val reader = session.verifyReaderAuth(req[0], readerTrust)
    val consented = askUser(req, reader)  // null if declined
    val reply = if (consented == null) session.termination()
      else session.encrypt(Proximity.buildDeviceResponse(
             req[0], mdoc, deviceKey, session.sessionTranscriptBytes(), consented), false)
    sendChunked(reply)                    // as Server2Client notifications
  } catch (e: Exception) {
    Proximity.statusFor(e)?.let { sendChunked(Proximity.statusMessage(it)) }
    disconnect()
  }
}
```

## NFC APDUs

Package `nfcapdu` does every NFC exchange byte by byte, with no I/O:

- **Holder.** `nfcapdu.NewHolder` serves the handover as a Type 4 Tag:
  the static `HandoverSelect()`, or TNEP with `HandleHandoverRequest`
  as `Negotiate`; with `Data` set, it also serves NFC data retrieval.
  The app's host card emulation service passes each command APDU to
  `Process` and sends back `Step.Response`. `Step.HandoverRead` is the
  moment to commit NFC (for BLE retrieval); `Step.Message` is a session
  message, answered later with `Respond` once the user consents. On
  field loss call `Deactivate`, and end the presentation if it reports
  `Cancel`.
- **Reader.** `nfcapdu.ReadHandover` and `nfcapdu.Transact` return an
  `Exchange`: send `Command()` over the tag connection after waiting
  `Wait()`, pass the response to `Next`, and repeat until `Command()`
  is nil; `Result()` is then the Hs, or the mdoc's answer. TNEP's
  waits come back as `Wait()` so the app can cancel them; `Close` an
  abandoned `Exchange`.

## Combined QR and NFC offers

`NewCombinedDeviceSession(random, CombinedOptions{Negotiated: false}, opts...)`
prepares two independent `DeviceSession` offers. `QROffer()` supplies immediate
QR/BLE metadata; `NFCOffer()` supplies Type 4/TNEP handover bytes. Serialize access
as for `DeviceSession`. On a QR BLE connection call `Select(false)`; on valid NFC
application selection call `Select(true)`. Drive only the returned session, stop
the losing native transport, and call `Close()` on cancellation. A losing claim
fails. QR omission is available for NFC data without Bluetooth permissions.

Each offer has its own key and service UUIDs. QR binds null Handover; NFC binds
the exact static `[Hs, null]` or negotiated `[Hs, Hr]`. No key-reuse exception is
assumed. Annex D transcript tests remain unchanged; combined tests additionally
verify signed round trips and reject device authentication with wrong handovers.
Native Android serializes QR cleanup before NFC BLE creation and preserves the
complete-Hs-read gate. `walletflow.StartCombinedProximityPresentation` and the
additive gomobile/Kotlin APIs share one consent flow. See Android's
`docs/PresentingInPerson.md` for lifecycle integration and `STATUS.md` for gates.
