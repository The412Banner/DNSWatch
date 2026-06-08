package com.banner.dnswatch.capture

import java.io.InputStream

/**
 * Reads a live pcap stream (as produced by `tcpdump -U -w -`) record by record.
 * Handles endianness from the global-header magic. Each [next] call returns the
 * raw link-layer frame bytes (for our captures: an NFLOG-wrapped packet).
 */
class PcapStream(private val input: InputStream) {

    private var littleEndian = true
    var linkType: Int = 0
        private set

    /** Reads and validates the 24-byte global header. Returns false on EOF/bad magic. */
    fun readHeader(): Boolean {
        val h = readN(24) ?: return false
        val m0 = h[0].toInt() and 0xFF
        val m1 = h[1].toInt() and 0xFF
        val m2 = h[2].toInt() and 0xFF
        val m3 = h[3].toInt() and 0xFF
        littleEndian = when {
            m0 == 0xD4 && m1 == 0xC3 && m2 == 0xB2 && m3 == 0xA1 -> true   // LE us
            m0 == 0x4D && m1 == 0x3C && m2 == 0xB2 && m3 == 0xA1 -> true   // LE ns
            m0 == 0xA1 && m1 == 0xB2 && m2 == 0xC3 && m3 == 0xD4 -> false  // BE us
            m0 == 0xA1 && m1 == 0xB2 && m2 == 0x3C && m3 == 0x4D -> false  // BE ns
            else -> return false
        }
        // bytes 20..23 = network (link type)
        linkType = u32(h, 20).toInt()
        return true
    }

    /** Returns the next packet's raw bytes, or null on EOF. */
    fun next(): ByteArray? {
        val rec = readN(16) ?: return null
        val inclLen = u32(rec, 8).toInt()
        if (inclLen <= 0 || inclLen > 262144) return null
        return readN(inclLen)
    }

    private fun u32(b: ByteArray, off: Int): Long {
        val a = b[off].toLong() and 0xFF
        val c = b[off + 1].toLong() and 0xFF
        val d = b[off + 2].toLong() and 0xFF
        val e = b[off + 3].toLong() and 0xFF
        return if (littleEndian) (a or (c shl 8) or (d shl 16) or (e shl 24))
        else (e or (d shl 8) or (c shl 16) or (a shl 24))
    }

    private fun readN(n: Int): ByteArray? {
        val buf = ByteArray(n)
        var read = 0
        while (read < n) {
            val r = try { input.read(buf, read, n - read) } catch (e: Exception) { return null }
            if (r < 0) return null
            read += r
        }
        return buf
    }
}
