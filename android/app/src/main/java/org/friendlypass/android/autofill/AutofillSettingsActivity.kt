package org.friendlypass.android.autofill

import android.content.Intent
import android.os.Bundle
import android.provider.Settings
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import org.friendlypass.android.R
import org.friendlypass.android.ui.theme.FriendlypassTheme

/**
 * Autofill status screen: shows whether friendlypass is the active autofill service and offers the
 * system "choose autofill service" picker. Opened from the keyboard chip's attribution action; the
 * service metadata points its `settingsActivity` at [org.friendlypass.android.MainActivity] as agreed
 * in the contract, so the main settings screen stays the single entry point.
 */
class AutofillSettingsActivity : FragmentActivity() {

    private var active by mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        active = AutofillStatus.isActiveService(this)
        setContent {
            FriendlypassTheme {
                AutofillSettingsScreen(
                    active = active,
                    statusText = AutofillStatus.statusText(this),
                    onChooseService = { chooseService() },
                    onBack = { finish() },
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        active = AutofillStatus.isActiveService(this)
    }

    private fun chooseService() {
        val intent = Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE)
        if (runCatching { startActivity(intent) }.isFailure) {
            runCatching { startActivity(Intent(Settings.ACTION_SETTINGS)) }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AutofillSettingsScreen(
    active: Boolean,
    statusText: String,
    onChooseService: () -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(context.getString(R.string.autofill_settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("autofill-settings-back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 20.dp, vertical = 8.dp),
        ) {
            Text(
                if (active) context.getString(R.string.autofill_status_active) else statusText,
                style = MaterialTheme.typography.titleMedium,
                color = if (active) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.testTag("autofill-status"),
            )
            Spacer(Modifier.height(8.dp))
            Text(
                context.getString(R.string.autofill_settings_explainer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = onChooseService,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("autofill-choose-service"),
            ) {
                Text(context.getString(R.string.autofill_settings_choose))
            }
        }
    }
}
