package com.banner.dnswatch.data

/** A user-selectable installed app. [uid] is the Linux uid used for iptables owner matching. */
data class AppInfo(
    val packageName: String,
    val label: String,
    val uid: Int,
    val isSystem: Boolean,
)
