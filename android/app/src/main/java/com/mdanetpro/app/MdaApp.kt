package com.mdanetpro.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.mdanetpro.core.Engine
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow

class MdaApp : Application() {
    companion object {
        lateinit var instance: MdaApp
            private set
        const val CH_SERVICE = "node"
        const val CH_MESSAGES = "messages"
        const val CH_REQUESTS = "requests"
    }

    val snapshot = MutableStateFlow<Engine.Snapshot?>(null)
    val notices = MutableSharedFlow<Pair<String, String>>(extraBufferCapacity = 16)
    @Volatile var visibleChat: String? = null
    @Volatile var inForeground = false

    val engine: Engine by lazy {
        Engine(filesDir, object : Engine.Platform {
            override fun onSnapshot(snapshot: Engine.Snapshot) { this@MdaApp.snapshot.value = snapshot }

            override fun onChatMessage(from: String, nickname: String, text: String) {
                if (inForeground && visibleChat == from) return
                notify(from.hashCode(), CH_MESSAGES, nickname, text, Intent(this@MdaApp, MainActivity::class.java).putExtra("chat", from))
            }

            override fun onJoinRequest(request: Engine.JoinRequestView) {
                notify(request.id.hashCode(), CH_REQUESTS, "Join request: ${request.network}",
                    "${request.nickname} wants to join. Open MDANetPro to approve.", Intent(this@MdaApp, MainActivity::class.java).putExtra("requests", true))
            }

            override fun onNotice(title: String, text: String) {
                notices.tryEmit(title to text)
                if (!inForeground && title == "Joined") notify(title.hashCode(), CH_REQUESTS, title, text, Intent(this@MdaApp, MainActivity::class.java))
            }
        })
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        if (Build.VERSION.SDK_INT >= 26) {
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(NotificationChannel(CH_SERVICE, "Node running", NotificationManager.IMPORTANCE_MIN))
            nm.createNotificationChannel(NotificationChannel(CH_MESSAGES, "Messages", NotificationManager.IMPORTANCE_HIGH))
            nm.createNotificationChannel(NotificationChannel(CH_REQUESTS, "Join requests", NotificationManager.IMPORTANCE_HIGH))
        }
    }

    private fun notify(id: Int, channel: String, title: String, text: String, intent: Intent) {
        val pi = PendingIntent.getActivity(this, id, intent.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val n = NotificationCompat.Builder(this, channel)
            .setSmallIcon(R.drawable.ic_stat_node)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setAutoCancel(true)
            .setContentIntent(pi)
            .build()
        try { NotificationManagerCompat.from(this).notify(id, n) } catch (_: SecurityException) {}
    }
}
