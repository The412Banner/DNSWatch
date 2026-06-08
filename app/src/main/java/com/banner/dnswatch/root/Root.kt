package com.banner.dnswatch.root

import java.io.BufferedReader
import java.io.InputStreamReader

/** Thin wrapper around the Magisk `su` binary. No external dependencies. */
object Root {

    /** Runs a command as root, returns (exitCode, combinedOutput). Blocking. */
    fun exec(cmd: String): Pair<Int, String> {
        return try {
            val p = ProcessBuilder("su", "-c", cmd)
                .redirectErrorStream(true)
                .start()
            val out = BufferedReader(InputStreamReader(p.inputStream)).readText()
            val code = p.waitFor()
            code to out
        } catch (e: Exception) {
            -1 to (e.message ?: "su exec failed")
        }
    }

    /** Runs several commands in one root shell (semicolon-joined). */
    fun execAll(vararg cmds: String): Pair<Int, String> = exec(cmds.joinToString("; "))

    /** True if we can obtain uid 0. */
    fun isAvailable(): Boolean {
        val (code, out) = exec("id -u")
        return code == 0 && out.trim() == "0"
    }

    /** Spawns a long-running root process and hands back the live Process so the
     *  caller can stream its stdout (used for the tcpdump pcap pipe). */
    fun spawn(cmd: String): Process =
        ProcessBuilder("su", "-c", cmd).start()
}
