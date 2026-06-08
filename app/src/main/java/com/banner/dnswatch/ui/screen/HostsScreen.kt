package com.banner.dnswatch.ui.screen

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.banner.dnswatch.data.HostClass
import com.banner.dnswatch.data.HostStat
import com.banner.dnswatch.ui.theme.BlockedAmber
import com.banner.dnswatch.ui.theme.FirstParty
import com.banner.dnswatch.ui.theme.OnSurfaceMuted
import com.banner.dnswatch.ui.theme.TrackerRed
import com.banner.dnswatch.viewmodel.MonitorViewModel

@Composable
fun HostsScreen(vm: MonitorViewModel) {
    val hosts = vm.hostSummary()
    val trackerCount = hosts.count { it.hostClass == HostClass.TRACKER }
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("${hosts.size} hosts · $trackerCount trackers",
                color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
            Button(
                enabled = trackerCount > 0,
                onClick = { vm.blockAllTrackers() },
                colors = ButtonDefaults.buttonColors(containerColor = TrackerRed),
            ) { Text("Block all trackers") }
        }
        HorizontalDivider()
        LazyColumn(Modifier.fillMaxSize()) {
            items(hosts, key = { it.host }) { h -> HostRow(h, vm) }
        }
    }
}

@Composable
private fun HostRow(h: HostStat, vm: MonitorViewModel) {
    val isBlocked = vm.blocked.contains(h.host)
    val col: Color = when {
        isBlocked -> BlockedAmber
        h.hostClass == HostClass.TRACKER -> TrackerRed
        h.hostClass == HostClass.FIRSTPARTY -> FirstParty
        else -> MaterialTheme.colorScheme.onBackground
    }
    Column(
        Modifier.fillMaxWidth().clickable { vm.toggleBlock(h.host) }
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(h.host + if (isBlocked) "  ⛔" else "", color = col,
                fontSize = 14.sp, fontWeight = FontWeight.SemiBold, fontFamily = FontFamily.Monospace,
                modifier = Modifier.weight(1f))
            Text("×${h.count}", color = OnSurfaceMuted, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
        }
        Text(
            (if (h.hostClass == HostClass.TRACKER) "tracker · " else "") + h.proto +
                if (isBlocked) " · blocked" else "  (tap to ${if (isBlocked) "unblock" else "block"})",
            color = OnSurfaceMuted, fontSize = 11.sp,
        )
    }
    HorizontalDivider(color = Color(0x14FFFFFF))
}
