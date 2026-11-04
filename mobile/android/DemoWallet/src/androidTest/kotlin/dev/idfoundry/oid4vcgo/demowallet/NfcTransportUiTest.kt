package dev.idfoundry.oid4vcgo.demowallet

import androidx.compose.material3.MaterialTheme
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import dev.idfoundry.oid4vcwallet.ProximityBLEMode
import org.junit.Rule
import org.junit.Test

/** A tap must not be reported as NFC data when the session actually selected BLE. */
class NfcTransportUiTest {
    @get:Rule val compose = createComposeRule()

    @Test fun armedNfcReaderShowsSelectionAndCanCancel() {
        var cancelled = false
        compose.setContent { MaterialTheme {
            NfcReaderWaiting(testPreset, null, onCancel = { cancelled = true }, onRetry = {})
        } }
        compose.onNodeWithTag("reader-nfc-waiting").assertIsDisplayed()
        compose.onNodeWithText("NFC verification").assertIsDisplayed()
        compose.onNodeWithText("Test mdoc: name").assertIsDisplayed()
        compose.onNodeWithTag("reader-nfc-ready").assertIsDisplayed()
        compose.onNodeWithTag("nfc-tap-indicator").assertIsDisplayed()
        compose.onNodeWithTag("reader-nfc-cancel").performClick()
        compose.runOnIdle { org.junit.Assert.assertTrue(cancelled) }
    }

    @Test fun nfcErrorOffersRetryWithoutClaimingReaderIsReady() {
        var retried = false
        compose.setContent { MaterialTheme {
            NfcReaderWaiting(testPreset, "Turn on NFC and try again.", onCancel = {}, onRetry = { retried = true })
        } }
        compose.onNodeWithTag("reader-nfc-ready").assertDoesNotExist()
        compose.onNodeWithText("Turn on NFC and try again.").assertIsDisplayed()
        compose.onNodeWithTag("reader-nfc-retry").performClick()
        compose.runOnIdle { org.junit.Assert.assertTrue(retried) }
    }

    @Test fun nfcDataDoesNotDisplayBleMode() {
        compose.setContent { MaterialTheme { ReaderDataTransport(true, ProximityBLEMode.CENTRAL_CLIENT) } }
        compose.onNodeWithText(NFC_ONLY).assertIsDisplayed()
        compose.onNodeWithTag("reader-ble-mode").assertDoesNotExist()
    }

    @Test fun bleCentralDisplaysActualRole() {
        compose.setContent { MaterialTheme { ReaderDataTransport(false, ProximityBLEMode.CENTRAL_CLIENT) } }
        compose.onNodeWithText("Central client mode: the holder connected to this reader").assertIsDisplayed()
        compose.onNodeWithText(NFC_ONLY).assertDoesNotExist()
    }

    @Test fun blePeripheralDisplaysActualRole() {
        compose.setContent { MaterialTheme { ReaderDataTransport(false, ProximityBLEMode.PERIPHERAL_SERVER) } }
        compose.onNodeWithText("Peripheral server mode: this reader connected to the holder").assertIsDisplayed()
        compose.onNodeWithText(NFC_ONLY).assertDoesNotExist()
    }

    private companion object {
        const val NFC_ONLY = "NFC only"
        val testPreset = readerPresets.first { it.title == "Test mdoc: name" }
    }
}
