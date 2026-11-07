package com.mdanetpro.app

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.mutableStateOf

class MainActivity : ComponentActivity() {
    private val app get() = MdaApp.instance
    val openChat = mutableStateOf<String?>(null)
    val showRequests = mutableStateOf(false)
    private var pendingExport: String? = null

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    private val importInvite = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        uri?.let { readInvite(it) }
    }

    private val exportInvite = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri: Uri? ->
        val text = pendingExport
        if (uri != null && text != null) {
            contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) }
            app.notices.tryEmit("Invite saved" to "Send this .mdar file to the people you want to invite.")
        }
        pendingExport = null
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33) notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        NodeService.start(this)
        handleIntent(intent)
        setContent { MdaTheme { AppScreen(this) } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    override fun onResume() { super.onResume(); app.inForeground = true }
    override fun onPause() { super.onPause(); app.inForeground = false }

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        intent.getStringExtra("chat")?.let { openChat.value = it }
        if (intent.getBooleanExtra("requests", false)) showRequests.value = true
        if (intent.action == Intent.ACTION_VIEW) intent.data?.let { readInvite(it) }
    }

    private fun readInvite(uri: Uri) {
        val text = try { contentResolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) } } catch (_: Exception) { null }
        if (text.isNullOrBlank()) app.notices.tryEmit("Invite file" to "Could not read that file.")
        else app.engine.importMdar(text)
    }

    fun pickInvite() = importInvite.launch(arrayOf("*/*"))

    fun saveInvite(network: String) {
        app.engine.exportMdar(network) { text ->
            runOnUiThread {
                if (text == null) return@runOnUiThread
                pendingExport = text
                exportInvite.launch("${network.replace(Regex("[^A-Za-z0-9_-]"), "_")}.mdar")
            }
        }
    }

    fun shareInvite(network: String) {
        app.engine.exportMdar(network) { text ->
            runOnUiThread {
                if (text == null) return@runOnUiThread
                val dir = java.io.File(cacheDir, "invites").apply { mkdirs() }
                val file = java.io.File(dir, "${network.replace(Regex("[^A-Za-z0-9_-]"), "_")}.mdar").apply { writeText(text) }
                // Share as text: the invite is plain base64, so any chat app can carry it.
                val send = Intent(Intent.ACTION_SEND).setType("text/plain")
                    .putExtra(Intent.EXTRA_SUBJECT, "Join '$network' on MDANetPro")
                    .putExtra(Intent.EXTRA_TEXT, text)
                startActivity(Intent.createChooser(send, "Share invite (${file.name})"))
            }
        }
    }
}
