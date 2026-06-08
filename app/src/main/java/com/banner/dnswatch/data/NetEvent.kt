package com.banner.dnswatch.data

enum class EventKind { DNS_QUERY, DNS_REPLY, TLS_SNI, CONN, BLOCKED }
enum class Direction { OUT, IN }

/** Classification of a host for colour-coding. */
enum class HostClass { TRACKER, FIRSTPARTY, NEUTRAL }

data class NetEvent(
    val id: Long,
    val timeMs: Long,
    val uid: Int,
    val appLabel: String,
    val kind: EventKind,
    val direction: Direction,
    val proto: String,          // "UDP" / "TCP"
    val host: String?,          // domain (from DNS qname / SNI / IP->host map)
    val remoteIp: String?,      // destination/source IP
    val port: Int,
    val qtype: String? = null,  // A / AAAA for DNS
    val answers: List<String> = emptyList(),
    val hostClass: HostClass = HostClass.NEUTRAL,
    val blocked: Boolean = false,
)

object TrackerDb {
    // Substring matches against the host. Used only for colour-coding / quick triage,
    // never to drop traffic (blocking is explicit + per-app).
    private val tracker = listOf(
        "app-measurement.com", "firebaseinstallations.googleapis.com",
        "firebase-settings.crashlytics.com", "crashlytics", "firebaselogging",
        "google-analytics.com", "googleadservices.com", "doubleclick.net",
        "googlesyndication.com", "admob", "adservice.google", "app-analytics",
        "umeng", "umengcloud", "cn.fly", "mob.com", "mobid", "talkingdata",
        "appsflyer", "adjust.com", "branch.io", "flurry", "sensorsdata",
        "vgabc.com", "jpush", "getui", "igexin", "xiaomi.*push", "hicloud",
    )
    private val firstParty = listOf(
        "vgabc.com", "xiaoji", "gamehub", "banner.hub",
    )

    /** Where the tracker catalog comes from. BUILT_IN is the offline default. */
    enum class Source(val label: String) {
        BUILT_IN("Built-in"), EXODUS("Exodus"), DDG("DDG Radar"), HOSTS("Hosts list")
    }

    @Volatile var source: Source = Source.BUILT_IN
    /** Domain set for the active external catalog (suffix-matched). Empty until loaded. */
    @Volatile var external: Set<String> = emptySet()

    fun classify(host: String?): HostClass {
        if (host == null) return HostClass.NEUTRAL
        val h = host.lowercase()
        if (firstParty.any { h.contains(it) }) return HostClass.FIRSTPARTY
        val isTracker = if (source == Source.BUILT_IN || external.isEmpty()) {
            tracker.any { h.contains(it.replace(".*", "")) }
        } else {
            domainMatches(h, external)
        }
        return if (isTracker) HostClass.TRACKER else HostClass.NEUTRAL
    }

    /** True if [host] or any parent domain is in [set] (e.g. a.b.doubleclick.net ∈ {doubleclick.net}). */
    private fun domainMatches(host: String, set: Set<String>): Boolean {
        var h = host
        while (true) {
            if (set.contains(h)) return true
            val dot = h.indexOf('.')
            if (dot < 0) return false
            h = h.substring(dot + 1)
        }
    }
}
