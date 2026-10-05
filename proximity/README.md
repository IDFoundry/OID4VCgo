# proximity: driving it from Kotlin or Swift

`proximity` does the ISO/IEC 18013-5 protocol: engagement, session
encryption, request and response. The app does the radio work. Over BLE,
the app's job is to:

1. advertise or scan for the service UUID,
2. connect and set up the GATT characteristics,
3. split each message into chunks and reassemble them, and
4. pass whole messages to and from this package.

This file covers BLE only. NFC isn't supported yet, nor is BLE L2CAP.

The BLE details below follow ISO/IEC 18013-5:2021 §8.3.3.1.1 (Tables 11–13),
cross-checked against [Multipaz](https://github.com/openwallet-foundation/multipaz)'s
BLE transport (`multipaz/src/commonMain/.../mdoc/transport/`).

## Roles

The mdoc picks the BLE mode in its QR code (`WithBLEMode`). The reader
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
   The reader scans the QR code and calls `NewReaderSession(qr)`.
2. **Connect.** The GATT server advertises `ServiceUUID()`. The GATT
   client scans for it, connects, and negotiates the MTU.
3. **Check Ident (central client mode only).** The reader serves
   `ReaderSession.BLEIdent()` on the Ident characteristic. The mdoc
   reads it and disconnects if it differs from `DeviceSession.BLEIdent()`.
4. **Subscribe and start.** The GATT client subscribes to State and
   Server2Client notifications, then writes `0x01` (start) to State.
5. **Request.** The reader sends `Establishment(docType, elements)`. The
   mdoc passes it to `HandleSessionEstablishment`, then
   `ParseDeviceRequest`, and shows a consent prompt.
6. **Respond.** If the user consents, the mdoc sends
   `Encrypt(BuildDeviceResponse(...), false)`. If they decline, or
   nothing matches, the mdoc sends `Termination()` instead. The reader
   passes either one to `Verify`.
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

`MaxMessageBytes` (2 MiB) caps every message. Reassembly can drop a
message as soon as it grows past that, instead of buffering it.

## Sketch (holder, peripheral server mode)

This is pseudocode, because the gomobile wrapper doesn't exist yet.

```kotlin
val session = Proximity.newDeviceSession(null)
showQr(session.qrCode())
gattServer.advertise(session.serviceUUID())

onMessage { msg ->            // a reassembled Client2Server message
  try {
    val req = Proximity.parseDeviceRequest(session.handleSessionEstablishment(msg))
    val consented = askUser(req)          // null if declined
    val reply = if (consented == null) session.termination()
      else session.encrypt(Proximity.buildDeviceResponse(
             mdoc, req[0].docType, deviceKey, session.sessionTranscriptBytes(), consented), false)
    sendChunked(reply)                    // as Server2Client notifications
  } catch (e: Exception) {
    Proximity.statusFor(e)?.let { sendChunked(Proximity.statusMessage(it)) }
    disconnect()
  }
}
```
