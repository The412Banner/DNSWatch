package com.banner.dnswatch.capture

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Best-effort QUIC-v1 (RFC 9001) Initial-packet SNI extractor.
 *
 * QUIC's ClientHello is encrypted, but the Initial packet keys are derived from
 * the (cleartext) Destination Connection ID with a well-known salt, so we can
 * decrypt it: HKDF → AES-128-GCM. We undo header protection, AEAD-decrypt the
 * payload, reassemble CRYPTO frames, and parse the TLS ClientHello SNI.
 *
 * Entirely fail-safe: any parse/crypto hiccup (v2, retry, fragmented CH, etc.)
 * returns null and the caller falls back to the DNS IP→host map.
 */
object QuicParser {

    // RFC 9001 §5.2 initial salt (QUIC v1).
    private val V1_SALT = hex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")

    /** [off]..[off+len) is the UDP payload. Returns SNI or null. */
    fun extractSni(b: ByteArray, off: Int, len: Int): String? = try {
        decode(b, off, off + len)
    } catch (e: Exception) { null }

    private fun decode(b: ByteArray, start: Int, end: Int): String? {
        var p = start
        if (p + 7 > end) return null
        val first = b[p].toInt() and 0xFF
        // Long header (0x80) + fixed bit (0x40) + Initial type (bits 5-4 == 00).
        if (first and 0xC0 != 0xC0) return null
        p += 1
        val version = be32(b, p); p += 4
        if (version != 0x00000001) return null            // only v1
        val dcidLen = b[p].toInt() and 0xFF; p += 1
        if (p + dcidLen > end) return null
        val dcid = b.copyOfRange(p, p + dcidLen); p += dcidLen
        val scidLen = b[p].toInt() and 0xFF; p += 1
        p += scidLen
        val (tokenLen, p1) = varint(b, p, end) ?: return null
        p = p1 + tokenLen.toInt()
        val (length, p2) = varint(b, p, end) ?: return null
        p = p2
        val pnOffset = p
        if (pnOffset + 4 + 16 > end) return null

        // ---- derive Initial keys from DCID ----
        val initialSecret = hkdfExtract(V1_SALT, dcid)
        val clientSecret = expandLabel(initialSecret, "client in", 32)
        val key = expandLabel(clientSecret, "quic key", 16)
        val iv = expandLabel(clientSecret, "quic iv", 12)
        val hp = expandLabel(clientSecret, "quic hp", 16)

        // ---- remove header protection ----
        val sample = b.copyOfRange(pnOffset + 4, pnOffset + 4 + 16)
        val mask = aesEcb(hp, sample)
        val unmaskedFirst = first xor (mask[0].toInt() and 0x0F)
        val pnLen = (unmaskedFirst and 0x03) + 1
        val pnBytes = ByteArray(pnLen)
        for (i in 0 until pnLen) pnBytes[i] = (b[pnOffset + i].toInt() xor (mask[1 + i].toInt())).toByte()

        // packet number (truncated is fine for nonce since CH is the first packet, pn small)
        var pn = 0L
        for (i in 0 until pnLen) pn = (pn shl 8) or (pnBytes[i].toLong() and 0xFF)

        // ---- AEAD decrypt ----
        val payloadStart = pnOffset + pnLen
        val payloadEnd = pnOffset + length.toInt()        // Length covers pn + payload
        if (payloadEnd > end || payloadEnd - payloadStart < 16) return null

        // AAD = header bytes with unprotected first byte + packet number.
        val aad = b.copyOfRange(start, payloadStart)
        aad[0] = unmaskedFirst.toByte()
        for (i in 0 until pnLen) aad[(pnOffset - start) + i] = pnBytes[i]

        // nonce = iv XOR left-padded packet number.
        val nonce = iv.copyOf()
        for (i in 0 until 8) {
            nonce[11 - i] = (nonce[11 - i].toInt() xor ((pn ushr (8 * i)) and 0xFF).toInt()).toByte()
        }

        val plain = aesGcmDecrypt(key, nonce, aad, b, payloadStart, payloadEnd - payloadStart) ?: return null
        val crypto = reassembleCrypto(plain) ?: return null
        return TlsSni.fromHandshake(crypto, 0, crypto.size)
    }

    /** Walk QUIC frames, collecting CRYPTO (0x06) data starting at offset 0. */
    private fun reassembleCrypto(f: ByteArray): ByteArray? {
        var i = 0
        var out: ByteArray? = null
        while (i < f.size) {
            val type = f[i].toInt() and 0xFF
            when (type) {
                0x00 -> { i++ }                                   // PADDING
                0x01 -> { i++ }                                   // PING
                0x06 -> {                                         // CRYPTO
                    val (off, a) = varint(f, i + 1, f.size) ?: return out
                    val (ln, b2) = varint(f, a, f.size) ?: return out
                    val dataOff = b2
                    val dataLen = ln.toInt()
                    if (dataOff + dataLen > f.size) return out
                    if (off == 0L) out = f.copyOfRange(dataOff, dataOff + dataLen)
                    i = dataOff + dataLen
                }
                else -> return out                               // unknown frame → stop
            }
        }
        return out
    }

    // ---- HKDF (RFC 5869) + TLS1.3 Expand-Label (RFC 8446) ----
    private fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray = hmac(salt, ikm)

    private fun expandLabel(secret: ByteArray, label: String, length: Int): ByteArray {
        val full = "tls13 $label".toByteArray(Charsets.US_ASCII)
        val info = ByteArray(2 + 1 + full.size + 1)
        info[0] = (length ushr 8).toByte(); info[1] = (length and 0xFF).toByte()
        info[2] = full.size.toByte()
        System.arraycopy(full, 0, info, 3, full.size)
        info[3 + full.size] = 0                                   // empty context
        // HKDF-Expand, single block (length ≤ 32).
        val t = hmac(secret, info + byteArrayOf(0x01))
        return t.copyOf(length)
    }

    private fun hmac(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        return mac.doFinal(msg)
    }

    private fun aesEcb(key: ByteArray, data: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/ECB/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
        return c.doFinal(data)
    }

    private fun aesGcmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ct: ByteArray, off: Int, len: Int): ByteArray? = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        c.doFinal(ct, off, len)
    } catch (e: Exception) { null }

    // ---- helpers ----
    private fun varint(b: ByteArray, o: Int, end: Int): Pair<Long, Int>? {
        if (o >= end) return null
        val b0 = b[o].toInt() and 0xFF
        val n = 1 shl (b0 ushr 6)
        if (o + n > end) return null
        var v = (b0 and 0x3F).toLong()
        for (i in 1 until n) v = (v shl 8) or (b[o + i].toLong() and 0xFF)
        return v to (o + n)
    }
    private fun be32(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)
    private fun hex(s: String): ByteArray {
        val out = ByteArray(s.length / 2)
        for (i in out.indices) out[i] = ((Character.digit(s[i * 2], 16) shl 4) or Character.digit(s[i * 2 + 1], 16)).toByte()
        return out
    }
}
