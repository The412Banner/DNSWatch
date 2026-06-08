package com.banner.dnswatch.data

/** Aggregated per-host rollup for the summary view (not capped like the live list). */
data class HostStat(
    val host: String,
    val count: Int,
    val hostClass: HostClass,
    val lastMs: Long,
    val proto: String,
)
