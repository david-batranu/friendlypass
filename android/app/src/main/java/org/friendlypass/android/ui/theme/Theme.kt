package org.friendlypass.android.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Colours sampled from branding/friendlypass-logo.jpg (soft green artwork, dark green shield).
private val BrandGreen = Color(0xFF3E6B38)
private val BrandGreenLight = Color(0xFFA9D39B)
private val BrandGreenMid = Color(0xFF699767)
private val BrandGreenDeep = Color(0xFF507846)

private val LightColors = lightColorScheme(
    primary = BrandGreen,
    onPrimary = Color.White,
    primaryContainer = BrandGreenLight,
    onPrimaryContainer = Color(0xFF12200F),
    secondary = BrandGreenMid,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFDCEBD2),
    onSecondaryContainer = Color(0xFF12200F),
    tertiary = BrandGreenDeep,
    background = Color(0xFFF7F9F3),
    onBackground = Color(0xFF1A1C18),
    surface = Color(0xFFF7F9F3),
    onSurface = Color(0xFF1A1C18),
    surfaceVariant = Color(0xFFE4E9DD),
    onSurfaceVariant = Color(0xFF43483F),
    error = Color(0xFFB3261E),
)

private val DarkColors = darkColorScheme(
    primary = BrandGreenLight,
    onPrimary = Color(0xFF10200D),
    primaryContainer = Color(0xFF2A4B26),
    onPrimaryContainer = Color(0xFFD0E8C4),
    secondary = Color(0xFFB7CCAF),
    onSecondary = Color(0xFF22351F),
    background = Color(0xFF11140F),
    onBackground = Color(0xFFE2E4DC),
    surface = Color(0xFF11140F),
    onSurface = Color(0xFFE2E4DC),
    surfaceVariant = Color(0xFF43483F),
    onSurfaceVariant = Color(0xFFC4C8BC),
    error = Color(0xFFF2B8B5),
)

@Composable
fun FriendlypassTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = if (darkTheme) DarkColors else LightColors,
        content = content,
    )
}
