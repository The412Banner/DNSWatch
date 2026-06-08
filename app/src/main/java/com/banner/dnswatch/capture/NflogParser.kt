package com.banner.dnswatch.capture

/** Result of unwrapping one DLT_NFLOG frame. */
data class NflogFrame(
    val family: Int,        // 2 = IPv4, 10 = IPv6
    val uid: Int,           // -1 if not present (inbound packets carry no owner uid)
    val l3: ByteArray,      // the raw IP packet
    val l3Off: Int,
    val l3Len: Int,
)

/**
 * Parses the LINKTYPE_NFLOG (239) pseudo-header + TLVs.
 *   byte0 = address family, byte1 = version, byte2..3 = res_id (BE)
 *   then TLVs: u16 len (incl 4-byte hdr), u16 type, value, padded to 4 bytes.
 * TLV len/type are in host byte order (capture device is little-endian).
 * Interesting attrs: NFULA_PAYLOAD=9 (the IP packet), NFULA_UID=14 (u32 BE).
 */
object NflogParser {

    private const val NFULA_PAYLOAD = 9
    private const val NFULA_UID = 14

    fun parse(frame: ByteArray): NflogFrame? {
        if (frame.size < 4) return null
        val family = frame[0].toInt() and 0xFF
        var p = 4
        var payloadOff = -1
        var payloadLen = 0
        var uid = -1

        while (p + 4 <= frame.size) {
            val len = le16(frame, p)
            val type = le16(frame, p + 2) and 0x3FFF // strip NLA nested + net-byteorder flags
            if (len < 4 || p + len > frame.size) break
            val vOff = p + 4
            val vLen = len - 4
            when (type) {
                NFULA_PAYLOAD -> { payloadOff = vOff; payloadLen = vLen }
                NFULA_UID -> if (vLen >= 4) uid = be32(frame, vOff)
            }
            // advance with 4-byte alignment
            p += (len + 3) and 3.inv()
        }
        if (payloadOff < 0) return null
        return NflogFrame(family, uid, frame, payloadOff, payloadLen)
    }

    private fun le16(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

    private fun be32(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)
}
