package com.banner.dnswatch.ui.screen

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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.banner.dnswatch.data.AppInfo
import com.banner.dnswatch.data.TrackerDb
import com.banner.dnswatch.viewmodel.MonitorViewModel

@Composable
fun AppPickerScreen(vm: MonitorViewModel, onStarted: () -> Unit) {
    var q by remember { mutableStateOf("") }
    val ql = q.trim().lowercase()
    val list = vm.apps.filter {
        ql.isEmpty() || it.label.lowercase().contains(ql) || it.packageName.lowercase().contains(ql)
    }
    Column(Modifier.fillMaxSize()) {
        OutlinedTextField(
            value = q, onValueChange = { q = it },
            label = { Text("Search apps") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp),
        )
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Switch(checked = vm.fullDevice, onCheckedChange = { vm.fullDevice = it }, enabled = !vm.running)
            Text("Whole device", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Switch(checked = vm.savePcap, onCheckedChange = { vm.savePcap = it }, enabled = !vm.running)
            Text(".pcap", fontSize = 13.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Column(Modifier.padding(horizontal = 12.dp, vertical = 2.dp)) {
            Text("Tracker source — ${vm.trackerStatus}", fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                TrackerDb.Source.entries.forEach { s ->
                    if (vm.trackerSource == s) Button(onClick = { vm.selectTrackerSource(s) }) { Text(s.label) }
                    else OutlinedButton(onClick = { vm.selectTrackerSource(s) }) { Text(s.label) }
                }
            }
        }
        Row(
            Modifier.fillMaxWidth().padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(if (vm.fullDevice) "whole device" else "${vm.selected.size} selected",
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Button(
                enabled = (vm.fullDevice || vm.selected.isNotEmpty()) && !vm.running,
                onClick = { vm.start(); if (vm.running) onStarted() },
            ) { Text(if (vm.running) "Monitoring" else "Start monitoring") }
        }
        if (vm.status.isNotEmpty()) {
            Text(vm.status, color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(horizontal = 12.dp), fontSize = 12.sp)
        }
        HorizontalDivider()
        LazyColumn(Modifier.fillMaxSize()) {
            items(list, key = { it.packageName }) { app -> AppRow(app, vm) }
        }
    }
}

@Composable
private fun AppRow(app: AppInfo, vm: MonitorViewModel) {
    val checked = vm.selected.containsKey(app.packageName)
    Row(
        Modifier.fillMaxWidth().clickable { vm.toggle(app) }.padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Checkbox(checked = checked, onCheckedChange = { vm.toggle(app) })
        Column(Modifier.padding(start = 8.dp)) {
            Text(app.label, color = MaterialTheme.colorScheme.onBackground,
                fontWeight = FontWeight.Medium, fontSize = 15.sp)
            Text(
                "${app.packageName}  ·  uid ${app.uid}${if (app.isSystem) "  · system" else ""}",
                color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 11.sp,
            )
        }
    }
}
