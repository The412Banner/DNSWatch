package com.banner.dnswatch.capture

data class DnsInfo(
    val isResponse: Boolean,
    val qname: String?,
    val qtype: String?,
    val answers: List<String>,
)

data class L4Info(
    val ipVersion: Int,
    val proto: String,        // "TCP" / "UDP"
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val tcpSyn: Boolean,
    val tcpAck: Boolean,
    val dns: DnsInfo?,
    val sni: String?,
)

/** Pure-Kotlin parse of an IPv4/IPv6 packet down to DNS qnames and TLS SNI. */
object PacketParser {

    fun parse(b: ByteArray, off: Int, len: Int): L4Info? = try {
        if (len < 20) null else {
            val ver = (b[off].toInt() and 0xF0) ushr 4
            when (ver) {
                4 -> parseV4(b, off, off + len)
                6 -> parseV6(b, off, off + len)
                else -> null
            }
        }
    } catch (e: Exception) { null }

    private fun parseV4(b: ByteArray, off: Int, end: Int): L4Info? {
        val ihl = (b[off].toInt() and 0x0F) * 4
        if (ihl < 20 || off + ihl > end) return null
        val proto = b[off + 9].toInt() and 0xFF
        val src = ipv4(b, off + 12)
        val dst = ipv4(b, off + 16)
        return parseL4(b, off + ihl, end, proto, 4, src, dst)
    }

    private fun parseV6(b: ByteArray, off: Int, end: Int): L4Info? {
        if (off + 40 > end) return null
        val next = b[off + 6].toInt() and 0xFF
        val src = ipv6(b, off + 8)
        val dst = ipv6(b, off + 24)
        return parseL4(b, off + 40, end, next, 6, src, dst)
    }

    private fun parseL4(
        b: ByteArray, l4: Int, end: Int, proto: Int, ipVer: Int, src: String, dst: String,
    ): L4Info? {
        when (proto) {
            17 -> { // UDP
                if (l4 + 8 > end) return null
                val sp = be16(b, l4); val dp = be16(b, l4 + 2)
                val pay = l4 + 8
                if (sp == 53 || dp == 53) {
                    return L4Info(ipVer, "UDP", src, dst, sp, dp, false, false, parseDns(b, pay, end), null)
                }
                if (dp == 443 || sp == 443) { // QUIC / HTTP-3
                    val sni = if (dp == 443 && pay < end) QuicParser.extractSni(b, pay, end - pay) else null
                    return L4Info(ipVer, "QUIC", src, dst, sp, dp, false, false, null, sni)
                }
                return L4Info(ipVer, "UDP", src, dst, sp, dp, false, false, null, null)
            }
            6 -> { // TCP
                if (l4 + 20 > end) return null
                val sp = be16(b, l4); val dp = be16(b, l4 + 2)
                val dataOff = ((b[l4 + 12].toInt() and 0xF0) ushr 4) * 4
                val flags = b[l4 + 13].toInt() and 0xFF
                val syn = flags and 0x02 != 0
                val ack = flags and 0x10 != 0
                val pay = l4 + dataOff
                val sni = if (dp == 443 && pay < end) TlsSni.fromRecord(b, pay, end) else null
                val dns = if (sp == 53 || dp == 53) parseDns(b, pay + 2, end) else null // TCP DNS len-prefixed
                return L4Info(ipVer, "TCP", src, dst, sp, dp, syn, ack, dns, sni)
            }
            else -> return null
        }
    }

    // ---- DNS ----
    private fun parseDns(b: ByteArray, start: Int, end: Int): DnsInfo? {
        if (start + 12 > end) return null
        val flags = be16(b, start + 2)
        val qr = (flags ushr 15) and 1
        val qd = be16(b, start + 4)
        val an = be16(b, start + 6)
        if (qd < 1) return null
        var pos = start + 12
        val (qname, after) = readName(b, pos, start, end)
        pos = after
        if (pos + 4 > end) return DnsInfo(qr == 1, qname.ifEmpty { null }, null, emptyList())
        val qtype = be16(b, pos); pos += 4
        // skip extra questions
        var q = 1
        while (q < qd && pos < end) {
            val (_, a2) = readName(b, pos, start, end); pos = a2 + 4; q++
        }
        val answers = ArrayList<String>()
        if (qr == 1) {
            var i = 0
            while (i < an && pos + 10 <= end) {
                val (_, a2) = readName(b, pos, start, end); pos = a2
                if (pos + 10 > end) break
                val type = be16(b, pos)
                val rdlen = be16(b, pos + 8)
                val rdata = pos + 10
                if (rdata + rdlen > end) break
                when {
                    type == 1 && rdlen == 4 -> answers.add(ipv4(b, rdata))
                    type == 28 && rdlen == 16 -> answers.add(ipv6(b, rdata))
                }
                pos = rdata + rdlen
                i++
            }
        }
        return DnsInfo(qr == 1, qname.ifEmpty { null }, qtypeStr(qtype), answers)
    }

    private fun readName(b: ByteArray, posIn: Int, msgStart: Int, msgEnd: Int): Pair<String, Int> {
        val sb = StringBuilder()
        var pos = posIn
        var jumped = false
        var after = -1
        var guard = 0
        while (pos in 0 until msgEnd && guard++ < 128) {
            val lb = b[pos].toInt() and 0xFF
            if (lb == 0) { pos++; if (!jumped) after = pos; break }
            if (lb and 0xC0 == 0xC0) {
                if (pos + 1 >= msgEnd) break
                val ptr = ((lb and 0x3F) shl 8) or (b[pos + 1].toInt() and 0xFF)
                if (!jumped) after = pos + 2
                pos = msgStart + ptr
                jumped = true
                continue
            }
            if (pos + 1 + lb > msgEnd) break
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until lb) sb.append((b[pos + 1 + i].toInt() and 0xFF).toChar())
            pos += 1 + lb
        }
        return sb.toString() to (if (after >= 0) after else pos)
    }

    private fun qtypeStr(t: Int) = when (t) { 1 -> "A"; 28 -> "AAAA"; 5 -> "CNAME"; 65 -> "HTTPS"; else -> "T$t" }

    // ---- helpers ----
    private fun be16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    private fun ipv4(b: ByteArray, o: Int) =
        "${b[o].toInt() and 0xFF}.${b[o + 1].toInt() and 0xFF}.${b[o + 2].toInt() and 0xFF}.${b[o + 3].toInt() and 0xFF}"
    private fun ipv6(b: ByteArray, o: Int): String {
        val sb = StringBuilder()
        for (i in 0 until 8) {
            if (i > 0) sb.append(':')
            sb.append(Integer.toHexString(((b[o + i * 2].toInt() and 0xFF) shl 8) or (b[o + i * 2 + 1].toInt() and 0xFF)))
        }
        return sb.toString()
    }
}
