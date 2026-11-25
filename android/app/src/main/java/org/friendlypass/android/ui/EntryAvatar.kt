package org.friendlypass.android.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlin.math.absoluteValue

/** Deterministic colour for a title, mirroring the desktop's letter avatars. */
fun avatarColor(title: String, dark: Boolean = false): Color {
    val hue = (title.hashCode() * 31).absoluteValue % 360
    return if (dark) {
        Color.hsv(hue.toFloat(), 0.45f, 0.55f)
    } else {
        Color.hsv(hue.toFloat(), 0.42f, 0.62f)
    }
}

/** Circular avatar with the first letter of [title] on a deterministic colour. */
@Composable
fun EntryAvatar(title: String, size: Dp = 40.dp, modifier: Modifier = Modifier) {
    val color = avatarColor(title)
    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(color),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = title.trim().firstOrNull()?.uppercase() ?: "?",
            color = Color.White,
            fontWeight = FontWeight.SemiBold,
            fontSize = (size.value * 0.42f).sp,
            style = MaterialTheme.typography.titleMedium,
        )
    }
}
