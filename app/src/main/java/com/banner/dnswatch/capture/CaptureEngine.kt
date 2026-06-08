package com.banner.dnswatch.capture

import com.banner.dnswatch.data.Direction
import com.banner.dnswatch.data.EventKind
import com.banner.dnswatch.data.HostClass
import com.banner.dnswatch.data.NetEvent
import com.banner.dnswatch.data.TrackerDb
import com.banner.dnswatch.root.Root
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Root capture engine.
 *
 *  - Per selected app uid: an iptables owner-match rule mirrors the app's
 *    outbound packets to NFLOG group [GROUP]  ->  we see its TLS SNI + dst IPs.
 *  - Global :53 rules mirror the system resolver's DNS queries/replies to the
 *    same group  ->  we build an IP->host map and show resolver activity.
 *  - A single `tcpdump -i nflog:GROUP` pipe feeds the pure-Kotlin parser.
 *
 * Android routes app DNS through netd, so raw :53 queries aren't owner-tagged;
 * per-app hostnames therefore come from TLS SNI + the IP->host map (correct and
 * encryption-proof for SNI).
 */
class CaptureEngine(
    private val onEvent: (NetEvent) -> Unit,
    private val appLabels: Map<Int, String>,
) {
    companion object { const val GROUP = 30; const val MARK = "0xD0" }

    private val running = AtomicBoolean(false)
    private val ids = AtomicLong(0)
    private var tcpdump: Process? = null
    private var thread: Thread? = null

    private val selectedUids = HashSet<Int>()
    private val ipToHost = ConcurrentHashMap<String, String>()
    private val hostToIps = ConcurrentHashMap<String, MutableSet<String>>()
    private val blockedHosts = ConcurrentHashMap.newKeySet<String>()
    private val appliedDrops = ConcurrentHashMap.newKeySet<String>() // "uid|ip"
    private val seenConn = ConcurrentHashMap.newKeySet<String>()     // "uid|ip|port"

    val isRunning get() = running.get()

    fun start(uids: Collection<Int>): String? {
        if (running.get()) return "already running"
        if (!Root.isAvailable()) return "root (su) not available"
        selectedUids.clear(); selectedUids.addAll(uids)

        teardownRules() // clean any stale rules first
        val (code, out) = Root.execAll(*buildSetupRules().toTypedArray())
        if (code != 0) return "iptables setup failed: ${out.take(160)}"

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
        tcpdump = null
        seenConn.clear()
    }

    // ---- blocking (per-app DNS-domain firewall) ----
    fun block(host: String) {
        blockedHosts.add(host)
        hostToIps[host]?.forEach { ip -> selectedUids.forEach { uid -> applyDrop(uid, ip) } }
    }
    fun unblock(host: String) {
        blockedHosts.remove(host)
        hostToIps[host]?.forEach { ip -> selectedUids.forEach { uid -> removeDrop(uid, ip) } }
    }
    fun blockedHosts(): Set<String> = blockedHosts.toSet()

    // ---- rule construction ----
    private fun buildSetupRules(): List<String> {
        val r = ArrayList<String>()
        for (uid in selectedUids) {
            r += "iptables -t mangle -A OUTPUT -m owner --uid-owner $uid -j NFLOG --nflog-group $GROUP"
            r += "ip6tables -t mangle -A OUTPUT -m owner --uid-owner $uid -j NFLOG --nflog-group $GROUP"
        }
        for (cmd in listOf("iptables", "ip6tables")) {
            r += "$cmd -t mangle -A OUTPUT -p udp --dport 53 -j NFLOG --nflog-group $GROUP"
            r += "$cmd -t mangle -A INPUT -p udp --sport 53 -j NFLOG --nflog-group $GROUP"
            r += "$cmd -t mangle -A OUTPUT -p tcp --dport 53 -j NFLOG --nflog-group $GROUP"
        }
        return r
    }

    private fun teardownRules() {
        val cmds = ArrayList<String>()
        // Delete owner rules for the union of all uids we might have set (try a few times).
        for (uid in selectedUids) {
            cmds += "iptables -t mangle -D OUTPUT -m owner --uid-owner $uid -j NFLOG --nflog-group $GROUP 2>/dev/null"
            cmds += "ip6tables -t mangle -D OUTPUT -m owner --uid-owner $uid -j NFLOG --nflog-group $GROUP 2>/dev/null"
        }
        for (cmd in listOf("iptables", "ip6tables")) {
            cmds += "$cmd -t mangle -D OUTPUT -p udp --dport 53 -j NFLOG --nflog-group $GROUP 2>/dev/null"
            cmds += "$cmd -t mangle -D INPUT -p udp --sport 53 -j NFLOG --nflog-group $GROUP 2>/dev/null"
            cmds += "$cmd -t mangle -D OUTPUT -p tcp --dport 53 -j NFLOG --nflog-group $GROUP 2>/dev/null"
        }
        // drop rules
        for (key in appliedDrops) {
            val (uid, ip) = key.split("|")
            cmds += dropCmd(uid.toInt(), ip, add = false)
        }
        appliedDrops.clear()
        if (cmds.isNotEmpty()) Root.execAll(*cmds.toTypedArray())
    }

    private fun applyDrop(uid: Int, ip: String) {
        val key = "$uid|$ip"
        if (!appliedDrops.add(key)) return
        Root.exec(dropCmd(uid, ip, add = true))
    }
    private fun removeDrop(uid: Int, ip: String) {
        val key = "$uid|$ip"
        if (appliedDrops.remove(key)) Root.exec(dropCmd(uid, ip, add = false))
    }
    private fun dropCmd(uid: Int, ip: String, add: Boolean): String {
        val bin = if (ip.contains(":")) "ip6tables" else "iptables"
        val op = if (add) "-A" else "-D"
        return "$bin $op OUTPUT -m owner --uid-owner $uid -d $ip -j DROP 2>/dev/null"
    }

    // ---- read + parse loop ----
    private fun readLoop(proc: Process) {
        try {
            val pcap = PcapStream(proc.inputStream)
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

    private fun handle(uid: Int, info: L4Info) {
        val dns = info.dns
        // DNS not owned by a selected app belongs to the system-resolver lane (uid -1).
        val duid = if (uid in selectedUids) uid else -1
        // DNS reply -> learn IP->host, maybe apply pending blocks, emit resolver event
        if (dns != null && dns.isResponse) {
            val qn = dns.qname
            if (qn != null) {
                val set = hostToIps.getOrPut(qn) { ConcurrentHashMap.newKeySet() }
                for (ip in dns.answers) {
                    set.add(ip); ipToHost[ip] = qn
                    if (blockedHosts.contains(qn)) selectedUids.forEach { applyDrop(it, ip) }
                }
            }
            emit(duid, EventKind.DNS_REPLY, Direction.IN, info.proto, qn, info.srcIp, info.srcPort, dns.qtype, dns.answers)
            return
        }
        // DNS query (resolver or, rarely, app's own)
        if (dns != null) {
            emit(duid, EventKind.DNS_QUERY, Direction.OUT, info.proto, dns.qname, info.dstIp, info.dstPort, dns.qtype)
            return
        }
        // Non-DNS app traffic (owner-matched)
        if (uid !in selectedUids) return
        if (info.sni != null) {
            emit(uid, EventKind.TLS_SNI, Direction.OUT, info.proto, info.sni, info.dstIp, info.dstPort)
        } else {
            val key = "$uid|${info.dstIp}|${info.dstPort}"
            if (seenConn.add(key)) {
                val host = ipToHost[info.dstIp]
                emit(uid, EventKind.CONN, Direction.OUT, info.proto, host, info.dstIp, info.dstPort)
            }
        }
    }

    private fun emit(
        uid: Int, kind: EventKind, dir: Direction, proto: String,
        host: String?, ip: String?, port: Int, qtype: String? = null, answers: List<String> = emptyList(),
    ) {
        val cls = TrackerDb.classify(host)
        val label = appLabels[uid] ?: if (uid < 0) "resolver" else "uid $uid"
        onEvent(
            NetEvent(
                id = ids.incrementAndGet(),
                timeMs = System.currentTimeMillis(),
                uid = uid, appLabel = label, kind = kind, direction = dir, proto = proto,
                host = host, remoteIp = ip, port = port, qtype = qtype, answers = answers,
                hostClass = cls, blocked = host != null && blockedHosts.contains(host),
            )
        )
    }
}
