// Package proximity implements ISO/IEC 18013-5 in-person (proximity)
// presentation over BLE, both roles, as bytes in and bytes out: the
// mdoc (holder) side is DeviceSession, the mdoc reader (verifier) side
// is ReaderSession. The radio transport — BLE GATT, and message
// chunking over it — stays in the mobile app; it only carries the
// messages this package builds and reads. See README.md for how a
// Kotlin or Swift app drives it.
//
// It builds on credential/mdoc (IssuerSigned, the MSO, device
// signature and MAC) and oid4vpmdoc (DeviceResponse encoding), and adds
// what proximity needs on top: device engagement, the session
// transcript, and session encryption.
//
// # Flow
//
//	mdoc (DeviceSession)                        reader (ReaderSession)
//	--------------------                        ----------------------
//	NewDeviceSession
//	  EDeviceKey, service UUID
//	QRCode() ── "mdoc:" + DeviceEngagement ──▶  NewReaderSession(qr)
//	                                              EReaderKey, SKReader/SKDevice
//	          ◀═════════ BLE connect to ServiceUUID ═════════▶
//	                                            Establishment(docType, elements)
//	HandleSessionEstablishment ◀── SessionEstablishment ──
//	  SKReader/SKDevice                           {eReaderKey, data: E(DeviceRequest)}
//	  → DeviceRequest
//	ParseDeviceRequest → []DocRequest
//	  (consent prompt)
//	BuildDeviceResponse
//	Encrypt(resp, false) ── SessionData ──────▶  Verify(msg, roots, now)
//	                        {data: E(DeviceResponse)}  → Verified
//	Termination() ◀──── {status: 20}, either side ────▶ Termination()
//
// If the user declines, or nothing matches the request, the mdoc sends
// Termination instead of a response and Verify returns ErrDeclined —
// as Multipaz does, rather than a DeviceResponse with documentErrors.
//
// # Messages
//
//   - DeviceEngagement (§8.2.1.1), carried in the QR code (§8.2.2.3):
//     {0: "1.0", 1: [1, EDeviceKeyBytes], 2: [[2, 1, BleOptions]]}, with
//     one BLE retrieval method in mdoc peripheral server mode (the
//     default) or central client mode (WithBLEMode). A reader offered
//     both selects central client mode (§8.3.3.1.1.1).
//   - SessionTranscript (§9.1.5.1): [DeviceEngagementBytes,
//     EReaderKeyBytes, Handover], Handover null for QR engagement.
//   - Session keys (§9.1.5.2): ECDH over P-256, then HKDF-SHA256 with
//     salt SHA-256(SessionTranscriptBytes) and info "SKReader" or
//     "SKDevice".
//   - SessionEstablishment and SessionData (§9.1.1.4), encrypted with
//     AES-256-GCM (§9.1.1.5): IV = 8-byte direction identifier (0
//     reader→mdoc, 1 mdoc→reader) || 4-byte big-endian counter, from 1
//     in each direction. The counter isn't sent, so a replayed or
//     reordered message fails to decrypt.
//   - DeviceRequest and DeviceResponse (§8.3.2.1.2): one DocRequest per
//     session, and a DeviceResponse with one document, authenticated by
//     a device signature (§9.1.3.6) — or, when reading, a device MAC
//     (§9.1.3.5).
//   - Reader verification (§9.3.1, §9.3.3): issuer chain to a trust
//     anchor, the IACA's countryName (and stateOrProvinceName) matching
//     the document signer's, the MSO's signed date within the signer
//     certificate's validity, digests, docType and validity window.
//   - BLE Ident (§8.3.3.1.1), for mdoc central client mode: BLEIdent.
//
// # Errors and status
//
// Status codes come from §9.1.1.4's Table 20. A message that fails to
// decrypt is ErrSessionEncryption (status 10), and one that isn't the
// expected CBOR, or is over MaxMessageBytes, is ErrCBORDecoding (status
// 11). Either one closes the session: send StatusMessage(status) from
// StatusFor, then disconnect. Status 20 ends a session normally.
//
// # Out of scope
//
//   - BLE, NFC and Wi-Fi Aware transport code, and BLE L2CAP.
//   - NFC engagement and NFC handover. The session transcript takes the
//     Handover as a parameter internally (the Annex D tests use it), but
//     only QR engagement is exposed.
//   - Reader authentication: WithReaderAuth exists, and Establishment
//     refuses to send until it's implemented. A received readerAuth is
//     kept in DocRequest.ReaderAuth, unverified. So the holder side
//     can't tell who the reader is: whoever scanned the QR code can ask,
//     and a consent prompt can show what it asks for, never a verified
//     reader identity — the holder decides on that alone.
//   - More than one request per session, and more than one document per
//     response.
//   - ISO/IEC 18013-7 (online presentation), OpenID4VP over the Digital
//     Credentials API, and transaction data.
//   - Mobile bindings: the exported API uses only bytes, strings,
//     crypto.Signer and *x509.CertPool, for a later gomobile wrapper.
package proximity
