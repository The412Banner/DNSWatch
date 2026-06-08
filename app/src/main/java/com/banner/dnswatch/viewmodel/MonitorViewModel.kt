package com.banner.dnswatch.viewmodel

import android.app.Application
import android.content.pm.ApplicationInfo
import android.os.Handler
import android.os.Looper
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.banner.dnswatch.capture.CaptureEngine
import com.banner.dnswatch.capture.CaptureService
import com.banner.dnswatch.data.AppInfo
import com.banner.dnswatch.data.HostClass
import com.banner.dnswatch.data.NetEvent
import com.banner.dnswatch.root.Root
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.ConcurrentLinkedQueue

class MonitorViewModel(app: Application) : AndroidViewModel(app) {

    val apps = mutableStateListOf<AppInfo>()
    val selected = mutableStateMapOf<String, AppInfo>()   // packageName -> AppInfo
    val events = mutableStateListOf<NetEvent>()
    val blocked = mutableStateListOf<String>()

    var rootOk by mutableStateOf<Boolean?>(null); private set
    var running by mutableStateOf(false); private set
    var status by mutableStateOf(""); private set
    var loadingApps by mutableStateOf(false); private set

    // filters
    var query by mutableStateOf("")
    var showResolver by mutableStateOf(true)
    var onlyTrackers by mutableStateOf(false)

    private val MAX = 1500
    private val incoming = ConcurrentLinkedQueue<NetEvent>()
    private val handler = Handler(Looper.getMainLooper())
    private var engine: CaptureEngine? = null

    init { checkRoot(); loadApps() }

    private fun checkRoot() = viewModelScope.launch {
        rootOk = withContext(Dispatchers.IO) { Root.isAvailable() }
    }

    fun loadApps() = viewModelScope.launch {
        loadingApps = true
        val pm = getApplication<Application>().packageManager
        val list = withContext(Dispatchers.IO) {
            pm.getInstalledApplications(0).map { ai: ApplicationInfo ->
                AppInfo(
                    packageName = ai.packageName,
                    label = pm.getApplicationLabel(ai).toString(),
                    uid = ai.uid,
                    isSystem = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                )
            }.sortedWith(compareBy({ it.isSystem }, { it.label.lowercase() }))
        }
        apps.clear(); apps.addAll(list); loadingApps = false
    }

    fun toggle(app: AppInfo) {
        if (selected.containsKey(app.packageName)) selected.remove(app.packageName)
        else selected[app.packageName] = app
    }

    fun start() {
        if (running || selected.isEmpty()) { status = "select at least one app"; return }
        val labels = selected.values.associate { it.uid to it.label }
        val eng = CaptureEngine(onEvent = { incoming.add(it) }, appLabels = labels)
        val err = eng.start(selected.values.map { it.uid })
        if (err != null) { status = err; return }
        engine = eng
        running = true
        status = "monitoring ${selected.size} app(s)"
        CaptureService.start(getApplication())
        scheduleDrain()
    }

    fun stop() {
        engine?.stop(); engine = null
        running = false
        status = "stopped"
        CaptureService.stop(getApplication())
        handler.removeCallbacksAndMessages(null)
    }

    fun clear() { events.clear(); incoming.clear() }

    fun toggleBlock(host: String) {
        val eng = engine
        if (eng == null) { status = "start monitoring first to block"; return }
        if (blocked.contains(host)) { eng.unblock(host); blocked.remove(host) }
        else { eng.block(host); blocked.add(host) }
    }

    private fun scheduleDrain() {
        handler.postDelayed({
            if (running || incoming.isNotEmpty()) {
                var n = 0
                while (true) {
                    val e = incoming.poll() ?: break
                    events.add(0, e)
                    if (++n >= 300) break
                }
                while (events.size > MAX) events.removeAt(events.size - 1)
                if (running) scheduleDrain()
            }
        }, 150)
    }

    fun filtered(): List<NetEvent> {
        val q = query.trim().lowercase()
        return events.filter { e ->
            (showResolver || e.uid >= 0) &&
                (!onlyTrackers || e.hostClass == HostClass.TRACKER) &&
                (q.isEmpty() || (e.host?.lowercase()?.contains(q) == true) ||
                    (e.remoteIp?.contains(q) == true) || e.appLabel.lowercase().contains(q))
        }
    }

    fun export(): String {
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(System.currentTimeMillis())
        val dir = getApplication<Application>().getExternalFilesDir(null)
        val f = File(dir, "dnswatch-$ts.txt")
        f.writeText(buildString {
            appendLine("# DNSWatch capture $ts")
            appendLine("# apps: ${selected.values.joinToString { it.label }}")
            appendLine("# blocked: ${blocked.joinToString()}")
            appendLine()
            events.asReversed().forEach { e ->
                appendLine("${e.timeMs}\t${e.appLabel}\t${e.kind}\t${e.direction}\t${e.proto}\t${e.host ?: "-"}\t${e.remoteIp ?: "-"}:${e.port}\t${e.answers.joinToString(",")}")
            }
        })
        return f.absolutePath
    }
}
