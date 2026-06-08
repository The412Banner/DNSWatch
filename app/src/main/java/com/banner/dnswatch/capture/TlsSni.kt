package com.banner.dnswatch.capture

/** Shared TLS ClientHello SNI extraction, used by both the TCP/TLS path and the
 *  QUIC path (which hands us the decrypted ClientHello handshake bytes). */
object TlsSni {

    /** [off] points at a TLS *record* (0x16 handshake …). Returns SNI or null. */
    fun fromRecord(b: ByteArray, off: Int, end: Int): String? {
        if (off + 5 > end) return null
        if (b[off].toInt() and 0xFF != 0x16) return null
        return fromHandshake(b, off + 5, end)
    }

    /** [hs] points at a handshake message (0x01 client_hello, 3-byte len, body…). */
    fun fromHandshake(b: ByteArray, hs: Int, end: Int): String? {
        try {
            if (hs + 4 > end || b[hs].toInt() and 0xFF != 0x01) return null
            var p = hs + 4
            p += 2 + 32                                   // client_version + random
            if (p >= end) return null
            val sidLen = b[p].toInt() and 0xFF; p += 1 + sidLen
            if (p + 2 > end) return null
            val cipherLen = be16(b, p); p += 2 + cipherLen
            if (p + 1 > end) return null
            val compLen = b[p].toInt() and 0xFF; p += 1 + compLen
            if (p + 2 > end) return null
            val extTotal = be16(b, p); p += 2
            val extEnd = minOf(p + extTotal, end)
            while (p + 4 <= extEnd) {
                val extType = be16(b, p)
                val extLen = be16(b, p + 2)
                val extData = p + 4
                if (extType == 0) {
                    var q = extData
                    if (q + 2 <= end) {
                        q += 2                            // server_name_list length
                        if (q + 3 <= end) {
                            val nameLen = be16(b, q + 1)
                            val nameOff = q + 3
                            if (nameOff + nameLen <= end) return ascii(b, nameOff, nameLen)
                        }
                    }
                }
                p = extData + extLen
            }
            return null
        } catch (e: Exception) { return null }
    }

    private fun be16(b: ByteArray, o: Int) = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    private fun ascii(b: ByteArray, o: Int, n: Int): String {
        val sb = StringBuilder()
        for (i in 0 until n) sb.append((b[o + i].toInt() and 0xFF).toChar())
        return sb.toString()
    }
}
