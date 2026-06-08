package com.banner.dnswatch.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColors = darkColorScheme(
    primary          = Accent,
    onPrimary        = SurfaceDark,
    primaryContainer = AccentDark,
    secondary        = DnsPurple,
    background       = SurfaceDark,
    surface          = SurfaceDark,
    surfaceVariant   = SurfaceVariant,
    onBackground     = OnSurface,
    onSurface        = OnSurface,
    onSurfaceVariant = OnSurfaceMuted,
    outline          = Color(0xFF2A3340),
)

@Composable
fun DNSWatchTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = DarkColors, content = content)
}
