package com.banner.dnswatch.capture

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import com.banner.dnswatch.MainActivity
import android.app.PendingIntent

/** Keeps the process alive (and shows a status notification) while capturing. */
class CaptureService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val chId = "dnswatch.capture"
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(chId, "Capture", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n: Notification = Notification.Builder(this, chId)
            .setContentTitle("DNSWatch is monitoring")
            .setContentText("Capturing DNS / SNI / connections")
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
        startForeground(1, n)
        return START_STICKY
    }

    companion object {
        fun start(ctx: Context) = ctx.startForegroundService(Intent(ctx, CaptureService::class.java))
        fun stop(ctx: Context) = ctx.stopService(Intent(ctx, CaptureService::class.java))
    }
}
