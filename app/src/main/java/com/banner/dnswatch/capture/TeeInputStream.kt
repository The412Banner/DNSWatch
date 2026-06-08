package com.banner.dnswatch.capture

import java.io.InputStream
import java.io.OutputStream

/** Passes reads through while copying every byte to [sink] (for raw .pcap export). */
class TeeInputStream(private val src: InputStream, private val sink: OutputStream) : InputStream() {
    override fun read(): Int {
        val b = src.read()
        if (b >= 0) sink.write(b)
        return b
    }
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        val n = src.read(b, off, len)
        if (n > 0) { runCatching { sink.write(b, off, n); sink.flush() } }
        return n
    }
    override fun close() {
        runCatching { src.close() }
        runCatching { sink.close() }
    }
}
