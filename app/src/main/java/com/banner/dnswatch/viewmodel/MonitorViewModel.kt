package com.banner.dnswatch.viewmodel

import android.app.Application
import android.content.Context
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
import com.banner.dnswatch.capture.TrackerLoader
import com.banner.dnswatch.data.AppInfo
import com.banner.dnswatch.data.HostClass
import com.banner.dnswatch.data.HostStat
import com.banner.dnswatch.data.NetEvent
import com.banner.dnswatch.data.TrackerDb
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
    val hostStats = mutableStateMapOf<String, HostStat>() // host -> rollup

    var rootOk by mutableStateOf<Boolean?>(null); private set
    var running by mutableStateOf(false); private set
    var status by mutableStateOf(""); private set
    var loadingApps by mutableStateOf(false); private set

    // modes / options (set before Start)
    var fullDevice by mutableStateOf(false)
    var savePcap by mutableStateOf(false)
    var pcapPath by mutableStateOf<String?>(null); private set

    // tracker catalog source
    var trackerSource by mutableStateOf(TrackerDb.Source.BUILT_IN); private set
    var trackerStatus by mutableStateOf("built-in list"); private set

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
    private val prefs = app.getSharedPreferences("dnswatch", Context.MODE_PRIVATE)

    init {
        checkRoot(); loadApps()
        blocked.addAll(prefs.getStringSet("blocked", emptySet()) ?: emptySet())
        val saved = prefs.getString("tracker_source", null)
        selectTrackerSource(TrackerDb.Source.entries.firstOrNull { it.name == saved } ?: TrackerDb.Source.BUILT_IN)
    }

    fun selectTrackerSource(s: TrackerDb.Source) {
        trackerSource = s
        TrackerDb.source = s
        prefs.edit().putString("tracker_source", s.name).apply()
        if (s == TrackerDb.Source.BUILT_IN) {
            TrackerDb.external = emptySet(); trackerStatus = "built-in list"; reclassify(); return
        }
        trackerStatus = "loading ${s.label}…"
        viewModelScope.launch {
            val set = withContext(Dispatchers.IO) { TrackerLoader.load(s, getApplication<Application>().filesDir) }
            TrackerDb.external = set
            trackerStatus = if (set.isEmpty()) "${s.label}: load failed — using built-in" else "${s.label}: ${set.size} domains"
            reclassify()
        }
    }

    private fun reclassify() {
        for ((h, st) in hostStats.toList()) hostStats[h] = st.copy(hostClass = TrackerDb.classify(h))
    }

    private fun checkRoot() = viewModelScope.launch {
        rootOk = withContext(Dispatchers.IO) { Root.isAvailable() }
    }

    fun loadApps() = viewModelScope.launch {
        loadingApps = true
        val pm = getApplication<Application>().packageManager
        val list = withContext(Dispatchers.IO) {
            pm.getInstalledApplications(0).map { ai: ApplicationInfo ->
                AppInfo(ai.packageName, pm.getApplicationLabel(ai).toString(), ai.uid,
                    (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0)
            }.sortedWith(compareBy({ it.isSystem }, { it.label.lowercase() }))
        }
        apps.clear(); apps.addAll(list); loadingApps = false
    }

    fun toggle(app: AppInfo) {
        if (selected.containsKey(app.packageName)) selected.remove(app.packageName)
        else selected[app.packageName] = app
    }

    fun start() {
        if (running) return
        if (!fullDevice && selected.isEmpty()) { status = "select an app or turn on whole-device"; return }
        // full-device needs labels for every app; per-app only the selected ones
        val labels = if (fullDevice) apps.associate { it.uid to it.label }
                     else selected.values.associate { it.uid to it.label }
        pcapPath = if (savePcap) File(getApplication<Application>().getExternalFilesDir(null),
            "dnswatch-${ts()}.pcap").absolutePath else null
        val eng = CaptureEngine(onEvent = { incoming.add(it) }, appLabels = labels)
        val err = eng.start(
            uids = selected.values.map { it.uid },
            fullDevice = fullDevice,
            pcapPath = pcapPath,
            primeBlocks = blocked.toList(),
        )
        if (err != null) { status = err; return }
        engine = eng
        running = true
        status = if (fullDevice) "monitoring whole device" else "monitoring ${selected.size} app(s)"
        CaptureService.start(getApplication())
        scheduleDrain()
    }

    fun stop() {
        engine?.stop(); engine = null
        running = false
        status = "stopped"
        CaptureService.stop(getApplication())
        drainOnce(Int.MAX_VALUE)
        if (recording) stopRecording()
        handler.removeCallbacksAndMessages(null)
    }

    // ---- session recording ----
    fun toggleRecord() { if (recording) stopRecording() else startRecording() }

    private fun startRecording() {
        val f = File(getApplication<Application>().getExternalFilesDir(null), "dnswatch-session-${ts()}.log")
        val w = BufferedWriter(FileWriter(f))
        w.write("# DNSWatch session ${ts()}\n")
        w.write("# scope: ${if (fullDevice) "whole device" else selected.values.joinToString { "${it.label}(uid ${it.uid})" }}\n")
        w.write("# columns: epochMs\tapp\tkind\tdir\tproto\thost\tip:port\tanswers\n")
        events.asReversed().forEach { w.write(line(it)) }
        recordFile = f; logWriter = w; recordCount = events.size
        recording = true; recordPath = f.absolutePath
        status = "recording → ${f.name}"
    }

    private fun stopRecording() {
        recording = false
        runCatching { logWriter?.flush(); logWriter?.close() }
        logWriter = null
        val f = recordFile ?: return
        recordPath = copyToDownloads(f)
        status = "saved $recordCount events → $recordPath"
    }

    private fun line(e: NetEvent) =
        "${e.timeMs}\t${e.appLabel}\t${e.kind}\t${e.direction}\t${e.proto}\t" +
            "${e.host ?: "-"}\t${e.remoteIp ?: "-"}:${e.port}\t${e.answers.joinToString(",")}\n"

    fun clear() { events.clear(); incoming.clear(); hostStats.clear() }

    // ---- blocking ----
    fun toggleBlock(host: String) {
        val eng = engine
        if (blocked.contains(host)) { eng?.unblock(host); blocked.remove(host) }
        else { eng?.block(host); blocked.add(host) }
        persistBlocked()
        if (eng == null) status = "saved to block-list — applies on next Start"
    }

    fun blockAllTrackers() {
        val eng = engine
        val targets = hostStats.values.filter { it.hostClass == HostClass.TRACKER && it.host !in blocked }
        targets.forEach { eng?.block(it.host); blocked.add(it.host) }
        persistBlocked()
        status = "blocked ${targets.size} tracker host(s)"
    }

    private fun persistBlocked() {
        prefs.edit().putStringSet("blocked", blocked.toSet()).apply()
    }

    private fun scheduleDrain() {
        handler.postDelayed({
            if (running || incoming.isNotEmpty()) {
                drainOnce(300)
                if (running) scheduleDrain()
            }
        }, 150)
    }

    private fun drainOnce(limit: Int) {
        var n = 0
        while (n < limit) {
            val e = incoming.poll() ?: break
            if (recording) runCatching { logWriter?.write(line(e)); recordCount++ }
            e.host?.let { h ->
                val cur = hostStats[h]
                hostStats[h] = HostStat(h, (cur?.count ?: 0) + 1,
                    if (cur?.hostClass == HostClass.TRACKER) HostClass.TRACKER else e.hostClass,
                    e.timeMs, e.proto)
            }
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

    /** host rollup, trackers first then by hit count. */
    fun hostSummary(): List<HostStat> =
        hostStats.values.sortedWith(compareByDescending<HostStat> { it.hostClass == HostClass.TRACKER }
            .thenByDescending { it.count })

    /** Writes the current capture to a text file and returns it (for Share). */
    fun export(): File {
        val f = File(getApplication<Application>().getExternalFilesDir(null), "dnswatch-${ts()}.txt")
        f.writeText(buildString {
            appendLine("# DNSWatch capture ${ts()}")
            appendLine("# scope: ${if (fullDevice) "whole device" else selected.values.joinToString { it.label }}")
            appendLine("# blocked: ${blocked.joinToString()}")
            appendLine()
            events.asReversed().forEach { e ->
                appendLine("${e.timeMs}\t${e.appLabel}\t${e.kind}\t${e.direction}\t${e.proto}\t${e.host ?: "-"}\t${e.remoteIp ?: "-"}:${e.port}\t${e.answers.joinToString(",")}")
            }
        })
        copyToDownloads(f)
        return f
    }

    /** Best-effort root copy into /sdcard/Download; returns the visible path. */
    private fun copyToDownloads(f: File): String {
        val dest = "/sdcard/Download/${f.name}"
        val (code, _) = Root.exec("mkdir -p /sdcard/Download && cp '${f.absolutePath}' '$dest' && chmod 644 '$dest'")
        return if (code == 0) dest else f.absolutePath
    }

    fun pcapFile(): File? = pcapPath?.let { File(it) }?.takeIf { it.exists() }

    private fun ts() = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(System.currentTimeMillis())
}
