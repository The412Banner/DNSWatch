package com.banner.dnswatch

import android.Manifest
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.banner.dnswatch.ui.screen.AppPickerScreen
import com.banner.dnswatch.ui.screen.MonitorScreen
import com.banner.dnswatch.ui.theme.DNSWatchTheme
import com.banner.dnswatch.viewmodel.MonitorViewModel

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 33) {
            runCatching { requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1) }
        }
        setContent {
            DNSWatchTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    val vm: MonitorViewModel = viewModel()
                    AppRoot(vm)
                }
            }
        }
    }
}

@Composable
private fun AppRoot(vm: MonitorViewModel) {
    var tab by remember { mutableIntStateOf(0) }
    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = tab == 0, onClick = { tab = 0 },
                    icon = { Icon(Icons.Filled.Apps, null) }, label = { Text("Apps") },
                )
                NavigationBarItem(
                    selected = tab == 1, onClick = { tab = 1 },
                    icon = { Icon(Icons.Filled.Timeline, null) },
                    label = { Text("Live${if (vm.running) " ●" else ""}") },
                )
            }
        }
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad)) {
            Header(vm)
            Box(Modifier.fillMaxSize()) {
                when (tab) {
                    0 -> AppPickerScreen(vm) { tab = 1 }
                    else -> MonitorScreen(vm)
                }
            }
        }
    }
}

@Composable
private fun Header(vm: MonitorViewModel) {
    Row(
        Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text("DNSWatch", fontSize = 22.sp, fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground)
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.CenterEnd) {
            val (txt, col) = when (vm.rootOk) {
                true -> "root ✓" to MaterialTheme.colorScheme.primary
                false -> "no root ✗" to MaterialTheme.colorScheme.error
                else -> "checking…" to MaterialTheme.colorScheme.onSurfaceVariant
            }
            Text(txt, color = col, fontSize = 13.sp, fontWeight = FontWeight.Medium)
        }
    }
}
