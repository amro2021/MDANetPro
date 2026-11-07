package com.mdanetpro.app

import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * Keeps the node running while the app is in the background, so members behind NAT keep their
 * relay connection and messages arrive. Also follows Wi-Fi <-> mobile data switches.
 */
class NodeService : Service() {
    private var multicastLock: WifiManager.MulticastLock? = null
    private var callback: ConnectivityManager.NetworkCallback? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            MdaApp.instance.engine.stop()
            stopSelf()
            return START_NOT_STICKY
        }
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(this, 1, Intent(this, NodeService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE)
        val notification = NotificationCompat.Builder(this, MdaApp.CH_SERVICE)
            .setSmallIcon(R.drawable.ic_stat_node)
            .setContentTitle("MDANetPro is connected")
            .setContentText("Receiving messages from your networks")
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
            .build()
        ServiceCompat.startForeground(this, 1, notification,
            if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0)

        if (multicastLock == null) {
            // Needed to receive "Networks Nearby" broadcasts on Wi-Fi.
            val wifi = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            multicastLock = wifi.createMulticastLock("mdanetpro").apply { setReferenceCounted(false); acquire() }
        }
        if (callback == null) {
            val cm = getSystemService(ConnectivityManager::class.java)
            callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = MdaApp.instance.engine.onNetworkChanged()
                override fun onLost(network: Network) = MdaApp.instance.engine.onNetworkChanged()
            }.also { cm.registerDefaultNetworkCallback(it) }
        }
        MdaApp.instance.engine.start()
        return START_STICKY
    }

    override fun onDestroy() {
        callback?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        multicastLock?.release()
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "com.mdanetpro.app.STOP"

        fun start(context: Context) {
            val intent = Intent(context, NodeService::class.java)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }
    }
}
