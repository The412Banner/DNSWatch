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
import java.io.BufferedWriter
import java.io.File
import java.io.FileWriter
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

    // recording
    var recording by mutableStateOf(false); private set
    var recordPath by mutableStateOf<String?>(null); private set
    var recordCount by mutableStateOf(0); private set
    private var logWriter: BufferedWriter? = null
    private var recordFile: File? = null

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
        // flush a final drain, then stop recording so nothing is lost
        drainOnce(Int.MAX_VALUE)
        if (recording) stopRecording()
        handler.removeCallbacksAndMessages(null)
    }

    // ---- session recording (full log to file, beyond the in-memory cap) ----
    fun toggleRecord() { if (recording) stopRecording() else startRecording() }

    private fun startRecording() {
        val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(System.currentTimeMillis())
        val dir = getApplication<Application>().getExternalFilesDir(null)
        val f = File(dir, "dnswatch-session-$ts.log")
        val w = BufferedWriter(FileWriter(f))
        w.write("# DNSWatch session $ts\n")
        w.write("# apps: ${selected.values.joinToString { "${it.label}(uid ${it.uid})" }}\n")
        w.write("# columns: epochMs\tapp\tkind\tdir\tproto\thost\tip:port\tanswers\n")
        // seed with whatever is already on screen (oldest first)
        events.asReversed().forEach { w.write(line(it)) }
        recordFile = f; logWriter = w; recordCount = events.size
        recording = true
        recordPath = f.absolutePath
        status = "recording → ${f.name}"
    }

    private fun stopRecording() {
        recording = false
        runCatching { logWriter?.flush(); logWriter?.close() }
        logWriter = null
        val f = recordFile ?: return
        // copy to /sdcard/Download for easy access (root; falls back to app dir)
        val dest = "/sdcard/Download/${f.name}"
        val (code, _) = Root.exec("cp '${f.absolutePath}' '$dest' && chmod 644 '$dest'")
        recordPath = if (code == 0) dest else f.absolutePath
        status = "saved $recordCount events → $recordPath"
    }

    private fun line(e: NetEvent) =
        "${e.timeMs}\t${e.appLabel}\t${e.kind}\t${e.direction}\t${e.proto}\t" +
            "${e.host ?: "-"}\t${e.remoteIp ?: "-"}:${e.port}\t${e.answers.joinToString(",")}\n"

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
                drainOnce(300)
                if (running) scheduleDrain()
            }
        }, 150)
    }

    /** Moves up to [limit] queued events into the UI list; records each first so
     *  the on-disk log keeps everything even past the in-memory cap. */
    private fun drainOnce(limit: Int) {
        var n = 0
        while (n < limit) {
            val e = incoming.poll() ?: break
            if (recording) runCatching { logWriter?.write(line(e)); recordCount++ }
            events.add(0, e)
            n++
        }
        while (events.size > MAX) events.removeAt(events.size - 1)
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
