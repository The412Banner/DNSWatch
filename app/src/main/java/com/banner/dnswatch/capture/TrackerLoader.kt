package com.banner.dnswatch.capture

import com.banner.dnswatch.data.TrackerDb
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * Fetches/parses/caches the external tracker catalogs and merges them into one
 * domain set (Exodus ∪ DDG Tracker Radar ∪ Hosts blocklist). The built-in list is
 * always applied on top of this in [TrackerDb.classify].
 *
 * Always fail-safe: a source that errors contributes nothing (caller still has the
 * built-in list + whatever else loaded). Each source caches to
 * [cacheDir]/tracker_<source>.txt so it loads offline; "Update" force-refreshes all.
 */
object TrackerLoader {

    private val EXTERNAL = listOf(TrackerDb.Source.EXODUS, TrackerDb.Source.DDG, TrackerDb.Source.HOSTS)

    private fun urlFor(s: TrackerDb.Source) = when (s) {
        TrackerDb.Source.DDG -> "https://staticcdn.duckduckgo.com/trackerblocking/v5/current/extension-tds.json"
        TrackerDb.Source.EXODUS -> "https://reports.exodus-privacy.eu.org/api/trackers"
        TrackerDb.Source.HOSTS -> "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
    }

    /** Merged set of all external catalogs. [force] re-downloads (else uses cache). */
    fun loadMerged(cacheDir: File, force: Boolean): Set<String> {
        val out = HashSet<String>()
        for (s in EXTERNAL) out += if (force) refresh(s, cacheDir) else load(s, cacheDir)
        return out
    }

    private fun load(source: TrackerDb.Source, cacheDir: File): Set<String> {
        val cache = File(cacheDir, "tracker_${source.name.lowercase()}.txt")
        if (cache.exists() && cache.length() > 0) {
            return runCatching { cache.readLines().filter { it.isNotBlank() }.toHashSet() }.getOrDefault(emptySet())
        }
        val domains = runCatching { download(source) }.getOrDefault(emptySet())
        if (domains.isNotEmpty()) runCatching { cache.writeText(domains.joinToString("\n")) }
        return domains
    }

    private fun refresh(source: TrackerDb.Source, cacheDir: File): Set<String> {
        File(cacheDir, "tracker_${source.name.lowercase()}.txt").delete()
        return load(source, cacheDir)
    }

    private fun download(source: TrackerDb.Source): Set<String> {
        val text = fetch(urlFor(source))
        return when (source) {
            TrackerDb.Source.DDG -> parseDdg(text)
            TrackerDb.Source.EXODUS -> parseExodus(text)
            TrackerDb.Source.HOSTS -> parseHosts(text)
        }
    }

    private fun fetch(url: String): String {
        val c = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000; readTimeout = 30000
            setRequestProperty("User-Agent", "DNSWatch")
        }
        return c.inputStream.bufferedReader().use { it.readText() }
    }

    private fun parseDdg(text: String): Set<String> {
        val out = HashSet<String>()
        val trackers = JSONObject(text).optJSONObject("trackers") ?: return out
        val keys = trackers.keys()
        while (keys.hasNext()) out.add(keys.next().lowercase())
        return out
    }

    private fun parseExodus(text: String): Set<String> {
        val out = HashSet<String>()
        val trackers = JSONObject(text).optJSONObject("trackers") ?: return out
        val keys = trackers.keys()
        while (keys.hasNext()) {
            val sig = trackers.getJSONObject(keys.next()).optString("network_signature", "")
            if (sig.isBlank()) continue
            for (raw in sig.split("|")) {
                val d = raw.replace("\\", "").trim().trimStart('^').trimEnd('$')
                if (d.contains('.') && d.all { it.isLetterOrDigit() || it == '.' || it == '-' }) out.add(d.lowercase())
            }
        }
        return out
    }

    private fun parseHosts(text: String): Set<String> {
        val out = HashSet<String>()
        for (raw in text.lineSequence()) {
            val l = raw.trim()
            if (l.isEmpty() || l.startsWith("#")) continue
            val parts = l.split(Regex("\\s+"))
            val d = (if (parts.size >= 2) parts[1] else parts[0]).lowercase()
            if (d.contains('.') && d != "localhost") out.add(d)
        }
        return out
    }
}
