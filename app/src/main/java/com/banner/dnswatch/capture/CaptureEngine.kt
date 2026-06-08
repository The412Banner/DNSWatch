package com.banner.dnswatch.capture

import com.banner.dnswatch.data.Direction
import com.banner.dnswatch.data.EventKind
import com.banner.dnswatch.data.NetEvent
import com.banner.dnswatch.data.TrackerDb
import com.banner.dnswatch.root.Root
import java.io.FileOutputStream
import java.io.OutputStream
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Root capture engine.
 *
 *  - Per-app mode: an iptables owner-match rule per selected uid mirrors that
 *    app's outbound packets to NFLOG group [GROUP].
 *  - Whole-device mode: one global OUTPUT rule mirrors everything; NFLOG carries
 *    the per-packet uid, so events still attribute to the owning app.
 *  - Global :53 rules build the IP->host map / resolver feed.
 *  - A single `tcpdump -i nflog:GROUP` pipe feeds the pure-Kotlin parser
 *    (DNS + TLS SNI + QUIC SNI). Optionally tee'd to a raw .pcap.
 *
 * Android routes app DNS through netd, so raw :53 queries aren't owner-tagged;
 * per-app hostnames come from SNI + the IP->host map (encryption-proof for SNI).
 */
class CaptureEngine(
    private val onEvent: (NetEvent) -> Unit,
    private val appLabels: Map<Int, String>,
) {
    companion object { const val GROUP = 30 }

    private val running = AtomicBoolean(false)
    private val ids = AtomicLong(0)
    private var tcpdump: Process? = null
    private var thread: Thread? = null
    private var pcapSink: OutputStream? = null
    private var fullDevice = false

    private val selectedUids = HashSet<Int>()
    private val ipToHost = ConcurrentHashMap<String, String>()
    private val hostToIps = ConcurrentHashMap<String, MutableSet<String>>()
    private val blockedHosts = ConcurrentHashMap.newKeySet<String>()
    private val appliedDrops = ConcurrentHashMap.newKeySet<String>() // "uid|ip" or "all|ip"
    private val seenConn = ConcurrentHashMap.newKeySet<String>()     // "uid|ip|port"

    val isRunning get() = running.get()

    fun start(
        uids: Collection<Int>,
        fullDevice: Boolean = false,
        pcapPath: String? = null,
        primeBlocks: Collection<String> = emptyList(),
    ): String? {
        if (running.get()) return "already running"
        if (!Root.isAvailable()) return "root (su) not available"
        this.fullDevice = fullDevice
        selectedUids.clear(); selectedUids.addAll(uids)
        blockedHosts.clear(); blockedHosts.addAll(primeBlocks)

        teardownRules() // clean any stale rules first
        val (code, out) = Root.execAll(*buildSetupRules().toTypedArray())
        if (code != 0) return "iptables setup failed: ${out.take(160)}"

        pcapSink = pcapPath?.let { runCatching { FileOutputStream(it) }.getOrNull() }
        val proc = Root.spawn("tcpdump -i nflog:$GROUP -U -s 0 -w - 2>/dev/null")
        tcpdump = proc
        running.set(true)
        thread = Thread { readLoop(proc) }.also { it.isDaemon = true; it.start() }
        return null
    }

    fun stop() {
        running.set(false)
        try { tcpdump?.destroy() } catch (_: Exception) {}
        Root.exec("pkill -f 'tcpdump -i nflog:$GROUP'")
        teardownRules()
        runCatching { pcapSink?.flush(); pcapSink?.close() }
        pcapSink = null
        tcpdump = null
        seenConn.clear()
    }

    // ---- blocking ----
    fun block(host: String) {
        blockedHosts.add(host)
        hostToIps[host]?.forEach { ip -> dropTargets().forEach { applyDrop(it, ip) } }
    }
    fun unblock(host: String) {
        blockedHosts.remove(host)
        hostToIps[host]?.forEach { ip -> dropTargets().forEach { removeDrop(it, ip) } }
    }

    private fun dropTargets(): List<Int?> = if (fullDevice) listOf(null) else selectedUids.toList()

    // ---- rule construction ----
    private fun buildSetupRules(): List<String> {
        val r = ArrayList<String>()
        for (cmd in listOf("iptables", "ip6tables")) {
            if (fullDevice) {
                r += "$cmd -t mangle -A OUTPUT -j NFLOG --nflog-group $GROUP"
            } else {
                for (uid in selectedUids)
                    r += "$cmd -t mangle -A OUTPUT -m owner --uid-owner $uid -j NFLOG --nflog-group $GROUP"
                r += "$cmd -t mangle -A OUTPUT -p udp --dport 53 -j NFLOG --nflog-group $GROUP"
                r += "$cmd -t mangle -A OUTPUT -p tcp --dport 53 -j NFLOG --nflog-group $GROUP"
            }
            r += "$cmd -t mangle -A INPUT -p udp --sport 53 -j NFLOG --nflog-group $GROUP"
        }
        return r
    }

    private fun teardownRules() {
        val cmds = ArrayList<String>()
        for (cmd in listOf("iptables", "ip6tables")) {
            cmds += "$cmd -t mangle -D OUTPUT -j NFLOG --nflog-group $GROUP 2>/dev/null"
            for (uid in selectedUids)
                cmds += "$cmd -t mangle -D OUTPUT -m owner --uid-owner $uid -j NFLOG --nflog-group $GROUP 2>/dev/null"
            cmds += "$cmd -t mangle -D OUTPUT -p udp --dport 53 -j NFLOG --nflog-group $GROUP 2>/dev/null"
            cmds += "$cmd -t mangle -D OUTPUT -p tcp --dport 53 -j NFLOG --nflog-group $GROUP 2>/dev/null"
            cmds += "$cmd -t mangle -D INPUT -p udp --sport 53 -j NFLOG --nflog-group $GROUP 2>/dev/null"
        }
        for (key in appliedDrops) {
            val (u, ip) = key.split("|")
            cmds += dropCmd(if (u == "all") null else u.toInt(), ip, add = false)
        }
        appliedDrops.clear()
        if (cmds.isNotEmpty()) Root.execAll(*cmds.toTypedArray())
    }

    private fun applyDrop(uid: Int?, ip: String) {
        val key = "${uid ?: "all"}|$ip"
        if (!appliedDrops.add(key)) return
        Root.exec(dropCmd(uid, ip, add = true))
    }
    private fun removeDrop(uid: Int?, ip: String) {
        val key = "${uid ?: "all"}|$ip"
        if (appliedDrops.remove(key)) Root.exec(dropCmd(uid, ip, add = false))
    }
    private fun dropCmd(uid: Int?, ip: String, add: Boolean): String {
        val bin = if (ip.contains(":")) "ip6tables" else "iptables"
        val op = if (add) "-A" else "-D"
        val owner = if (uid == null) "" else "-m owner --uid-owner $uid "
        return "$bin $op OUTPUT ${owner}-d $ip -j DROP 2>/dev/null"
    }

    // ---- read + parse loop ----
    private fun readLoop(proc: Process) {
        try {
            val sink = pcapSink
            val stream = if (sink != null) TeeInputStream(proc.inputStream, sink) else proc.inputStream
            val pcap = PcapStream(stream)
            if (!pcap.readHeader()) return
            while (running.get()) {
                val frame = pcap.next() ?: break
                val nf = NflogParser.parse(frame) ?: continue
                val info = PacketParser.parse(nf.l3, nf.l3Off, nf.l3Len) ?: continue
                handle(nf.uid, info)
            }
        } catch (_: Exception) {
        }
    }

    private val inScope = { uid: Int -> fullDevice || uid in selectedUids }

    private fun handle(uid: Int, info: L4Info) {
        val dns = info.dns
        if (dns != null && dns.isResponse) {
            val qn = dns.qname
            if (qn != null) {
                val set = hostToIps.getOrPut(qn) { ConcurrentHashMap.newKeySet() }
                for (ip in dns.answers) {
                    set.add(ip); ipToHost[ip] = qn
                    if (blockedHosts.contains(qn)) dropTargets().forEach { applyDrop(it, ip) }
                }
            }
            emit(-1, EventKind.DNS_REPLY, Direction.IN, info.proto, qn, info.srcIp, info.srcPort, dns.qtype, dns.answers)
            return
        }
        if (dns != null) {
            val duid = if (!fullDevice && uid in selectedUids) uid else -1
            emit(duid, EventKind.DNS_QUERY, Direction.OUT, info.proto, dns.qname, info.dstIp, info.dstPort, dns.qtype)
            return
        }
        if (!inScope(uid)) return
        if (info.sni != null) {
            emit(uid, EventKind.TLS_SNI, Direction.OUT, info.proto, info.sni, info.dstIp, info.dstPort)
        } else {
            val key = "$uid|${info.dstIp}|${info.dstPort}"
            if (seenConn.add(key)) {
                emit(uid, EventKind.CONN, Direction.OUT, info.proto, ipToHost[info.dstIp], info.dstIp, info.dstPort)
            }
        }
    }

    private fun emit(
        uid: Int, kind: EventKind, dir: Direction, proto: String,
        host: String?, ip: String?, port: Int, qtype: String? = null, answers: List<String> = emptyList(),
    ) {
        val label = appLabels[uid] ?: if (uid < 0) "resolver" else "uid $uid"
        onEvent(
            NetEvent(
                id = ids.incrementAndGet(),
                timeMs = System.currentTimeMillis(),
                uid = uid, appLabel = label, kind = kind, direction = dir, proto = proto,
                host = host, remoteIp = ip, port = port, qtype = qtype, answers = answers,
                hostClass = TrackerDb.classify(host), blocked = host != null && blockedHosts.contains(host),
            )
        )
    }
}
