package com.banner.dnswatch.ui.screen

import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.core.content.FileProvider
import java.io.File
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.foundation.rememberScrollState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.banner.dnswatch.data.Direction
import com.banner.dnswatch.data.EventKind
import com.banner.dnswatch.data.HostClass
import com.banner.dnswatch.data.NetEvent
import com.banner.dnswatch.ui.theme.BlockedAmber
import com.banner.dnswatch.ui.theme.DnsPurple
import com.banner.dnswatch.ui.theme.FirstParty
import com.banner.dnswatch.ui.theme.OnSurfaceMuted
import com.banner.dnswatch.ui.theme.TrackerRed
import com.banner.dnswatch.viewmodel.MonitorViewModel
import java.text.SimpleDateFormat
import java.util.Locale

private val timeFmt = SimpleDateFormat("HH:mm:ss", Locale.US)

@Composable
fun MonitorScreen(vm: MonitorViewModel) {
    val ctx = LocalContext.current
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())
                .padding(horizontal = 12.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (vm.running) {
                Button(onClick = { vm.stop() },
                    colors = ButtonDefaults.buttonColors(containerColor = TrackerRed)) { Text("Stop") }
            } else {
                Button(onClick = { vm.start() }, enabled = vm.fullDevice || vm.selected.isNotEmpty()) { Text("Start") }
            }
            if (vm.recording) {
                Button(onClick = { vm.toggleRecord() },
                    colors = ButtonDefaults.buttonColors(containerColor = TrackerRed)) { Text("● REC") }
            } else {
                OutlinedButton(onClick = { vm.toggleRecord() }) { Text("Record") }
            }
            OutlinedButton(onClick = { vm.clear() }) { Text("Clear") }
            OutlinedButton(onClick = { shareFile(ctx, vm.export()) }) { Text("Export / Share") }
            vm.pcapFile()?.let { pf ->
                OutlinedButton(onClick = { shareFile(ctx, pf) }) { Text("Share .pcap") }
            }
        }
        if (vm.recording) {
            Text("● recording ${vm.recordCount} events → ${vm.recordPath ?: ""}",
                color = TrackerRed, fontSize = 11.sp,
                modifier = Modifier.padding(horizontal = 12.dp))
        }
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Switch(checked = vm.showResolver, onCheckedChange = { vm.showResolver = it })
            Text("resolver", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Switch(checked = vm.onlyTrackers, onCheckedChange = { vm.onlyTrackers = it })
            Text("trackers", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        OutlinedTextField(
            value = vm.query, onValueChange = { vm.query = it },
            label = { Text("Filter host / ip / app") }, singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp),
        )
        if (vm.status.isNotEmpty()) {
            Text(vm.status, color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 12.dp), fontSize = 11.sp)
        }
        HorizontalDivider()
        val list = vm.filtered()
        LazyColumn(Modifier.fillMaxSize()) {
            items(list, key = { it.id }) { e -> EventRow(e, vm) }
        }
    }
}

@Composable
private fun EventRow(e: NetEvent, vm: MonitorViewModel) {
    val isBlocked = e.host != null && vm.blocked.contains(e.host)
    val hostColor: Color = when {
        isBlocked -> BlockedAmber
        e.hostClass == HostClass.TRACKER -> TrackerRed
        e.hostClass == HostClass.FIRSTPARTY -> FirstParty
        e.kind == EventKind.DNS_QUERY || e.kind == EventKind.DNS_REPLY -> DnsPurple
        else -> MaterialTheme.colorScheme.onBackground
    }
    Column(
        Modifier.fillMaxWidth()
            .clickable(enabled = e.host != null) { e.host?.let { vm.toggleBlock(it) } }
            .padding(horizontal = 12.dp, vertical = 6.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(timeFmt.format(e.timeMs), color = OnSurfaceMuted, fontSize = 11.sp,
                fontFamily = FontFamily.Monospace)
            Text("  ${arrow(e.direction)} ${kindLabel(e.kind)}", color = OnSurfaceMuted, fontSize = 11.sp)
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                Text(e.appLabel, color = OnSurfaceMuted, fontSize = 11.sp, fontWeight = FontWeight.Medium)
            }
        }
        Text(
            (e.host ?: e.remoteIp ?: "?") + if (isBlocked) "  ⛔ blocked" else "",
            color = hostColor, fontSize = 14.sp, fontWeight = FontWeight.SemiBold,
            fontFamily = FontFamily.Monospace,
        )
        val sub = buildString {
            if (e.remoteIp != null && e.host != null) append("${e.remoteIp}:${e.port}")
            else if (e.host != null) append(":${e.port}")
            if (e.qtype != null) append("  ${e.qtype}")
            if (e.answers.isNotEmpty()) append("  → ${e.answers.joinToString(", ")}")
        }
        if (sub.isNotBlank()) {
            Text(sub, color = OnSurfaceMuted, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
        }
    }
    HorizontalDivider(color = Color(0x14FFFFFF))
}

private fun shareFile(ctx: Context, f: File) {
    runCatching {
        val uri = FileProvider.getUriForFile(ctx, ctx.packageName + ".fileprovider", f)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = if (f.name.endsWith(".pcap")) "application/octet-stream" else "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        ctx.startActivity(Intent.createChooser(send, "Share ${f.name}").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }.onFailure { Toast.makeText(ctx, "Saved ${f.absolutePath}", Toast.LENGTH_LONG).show() }
}

private fun arrow(d: Direction) = if (d == Direction.OUT) "↑" else "↓"
private fun kindLabel(k: EventKind) = when (k) {
    EventKind.DNS_QUERY -> "DNS?"
    EventKind.DNS_REPLY -> "DNS✓"
    EventKind.TLS_SNI -> "SNI"
    EventKind.CONN -> "CONN"
    EventKind.BLOCKED -> "BLOCK"
}
