package org.friendlypass.android.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuAnchorType
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.friendlypass.android.FriendlypassApp
import org.friendlypass.android.vault.PasswordGenerator
import org.friendlypass.android.vault.model.EntryField
import org.friendlypass.android.vault.model.EntryInput
import org.friendlypass.android.vault.model.VaultException
import kotlin.math.roundToInt

/**
 * Full-featured entry creator and editor. Protected by `FLAG_SECURE` via [org.friendlypass.android.MainActivity].
 *
 * When [entryUuid] is null, creates a new entry inside [initialGroupUuid] (or root).
 * When [entryUuid] is non-null, loads and edits that entry in place.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EntryEditorScreen(
    entryUuid: String?,
    initialGroupUuid: String?,
    onSaved: (String) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }

    val existing = remember(entryUuid) {
        entryUuid?.let { uuid ->
            runCatching { app.vault.entry(uuid) }.getOrNull()
        }
    }
    val groups = remember { runCatching { app.vault.groups() }.getOrDefault(emptyList()) }
    val rootUuid = remember { runCatching { app.vault.rootGroupUuid() }.getOrDefault("") }

    var selectedGroupUuid by remember {
        mutableStateOf(
            existing?.groupUuid?.takeIf { it.isNotBlank() }
                ?: initialGroupUuid?.takeIf { it.isNotBlank() }
                ?: rootUuid,
        )
    }
    var groupMenuExpanded by remember { mutableStateOf(false) }

    var title by remember { mutableStateOf(existing?.summary?.title.orEmpty()) }
    var username by remember { mutableStateOf(existing?.summary?.username.orEmpty()) }
    var password by remember { mutableStateOf(existing?.password.orEmpty()) }
    var showPassword by remember { mutableStateOf(false) }
    var url by remember { mutableStateOf(existing?.urls?.firstOrNull().orEmpty()) }
    var totp by remember { mutableStateOf(existing?.otpUri.orEmpty()) }
    var androidAppsText by remember { mutableStateOf(existing?.androidApps?.joinToString(", ").orEmpty()) }
    var notes by remember { mutableStateOf(existing?.notes.orEmpty()) }
    var tagsText by remember { mutableStateOf(existing?.tags?.joinToString(", ").orEmpty()) }

    val customFields = remember {
        mutableStateListOf<EditableField>().apply {
            existing?.customFields
                ?.filterNot { it.name.startsWith("KPEX_PASSKEY_") || it.name == "AndroidApp" || it.name.startsWith("AndroidApp_") }
                ?.forEach { add(EditableField(it.name, it.value, it.protected)) }
        }
    }

    var showGenerator by remember { mutableStateOf(false) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val strength = remember(password) { PasswordGenerator.evaluateStrength(password) }
    val selectedGroupName = groups.firstOrNull { it.uuid == selectedGroupUuid }?.name ?: "Root"

    fun save() {
        if (busy) return
        val trimmedTitle = title.trim()
        if (trimmedTitle.isEmpty()) {
            error = "Title is required"
            return
        }
        busy = true
        error = null
        val input = EntryInput(
            groupUuid = selectedGroupUuid,
            title = trimmedTitle,
            username = username.trim(),
            password = password,
            url = url.trim(),
            notes = notes,
            totp = totp.trim().takeIf { it.isNotEmpty() },
            androidApps = androidAppsText.split(',').map { it.trim() }.filter { it.isNotEmpty() },
            customFields = customFields
                .map { EntryField(it.name.trim(), it.value, it.protected) }
                .filter { it.name.isNotEmpty() },
            tags = tagsText.split(',').map { it.trim() }.filter { it.isNotEmpty() },
        )
        scope.launch {
            try {
                val savedUuid = if (entryUuid == null) {
                    app.vault.createEntry(input)
                } else {
                    app.vault.updateEntry(entryUuid, input)
                    entryUuid
                }
                onSaved(savedUuid)
            } catch (e: VaultException) {
                error = e.message ?: "Could not save entry"
            } catch (e: Exception) {
                error = e.message ?: "Could not save entry"
            } finally {
                busy = false
            }
        }
    }

    if (showGenerator) {
        PasswordGeneratorDialog(
            onDismiss = { showGenerator = false },
            onUsePassword = { generated ->
                password = generated
                showPassword = true
                showGenerator = false
            },
            onCopy = { generated ->
                SecureClipboard.copySecret(context, "Generated password", generated)
                scope.launch { snackbar.showSnackbar("Password copied — clipboard clears in 30 s") }
            },
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (entryUuid == null) "New entry" else "Edit entry") },
                navigationIcon = {
                    IconButton(onClick = onBack, enabled = !busy) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (busy) {
                        CircularProgressIndicator(
                            modifier = Modifier
                                .padding(end = 16.dp)
                                .size(22.dp),
                            strokeWidth = 2.dp,
                        )
                    } else {
                        TextButton(
                            onClick = { save() },
                            modifier = Modifier.testTag("editor-save"),
                        ) {
                            Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Save")
                        }
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .imePadding()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            error?.let { message ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(
                        text = message,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier
                            .padding(12.dp)
                            .testTag("editor-error"),
                    )
                }
            }

            OutlinedTextField(
                value = title,
                onValueChange = { title = it; error = null },
                label = { Text("Title *") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("editor-title"),
            )

            if (groups.size > 1) {
                ExposedDropdownMenuBox(
                    expanded = groupMenuExpanded,
                    onExpandedChange = { groupMenuExpanded = !groupMenuExpanded },
                ) {
                    OutlinedTextField(
                        value = selectedGroupName,
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Group") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = groupMenuExpanded) },
                        modifier = Modifier
                            .menuAnchor(ExposedDropdownMenuAnchorType.PrimaryNotEditable)
                            .fillMaxWidth(),
                    )
                    ExposedDropdownMenu(
                        expanded = groupMenuExpanded,
                        onDismissRequest = { groupMenuExpanded = false },
                    ) {
                        for (group in groups) {
                            DropdownMenuItem(
                                text = { Text(group.name) },
                                onClick = {
                                    selectedGroupUuid = group.uuid
                                    groupMenuExpanded = false
                                },
                            )
                        }
                    }
                }
            }

            OutlinedTextField(
                value = username,
                onValueChange = { username = it },
                label = { Text("Username") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("editor-username"),
            )

            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password") },
                    singleLine = true,
                    visualTransformation = if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    trailingIcon = {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            TextButton(onClick = { showPassword = !showPassword }) {
                                Text(if (showPassword) "Hide" else "Show")
                            }
                            IconButton(
                                onClick = { showGenerator = true },
                                modifier = Modifier.testTag("editor-generate-password"),
                            ) {
                                Icon(Icons.Filled.Refresh, contentDescription = "Generate password")
                            }
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("editor-password"),
                )
                if (password.isNotEmpty()) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        LinearProgressIndicator(
                            progress = { strength.progress },
                            modifier = Modifier.weight(1f),
                        )
                        Text(
                            text = "${strength.label} (${strength.entropyBits} bits)",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text("Website URL") },
                placeholder = { Text("https://example.com") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("editor-url"),
            )

            OutlinedTextField(
                value = totp,
                onValueChange = { totp = it; error = null },
                label = { Text("TOTP secret or otpauth:// URI") },
                placeholder = { Text("Base32 secret or otpauth://totp/…") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("editor-totp"),
            )

            OutlinedTextField(
                value = androidAppsText,
                onValueChange = { androidAppsText = it },
                label = { Text("Android app package(s)") },
                placeholder = { Text("com.example.app, …") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = tagsText,
                onValueChange = { tagsText = it },
                label = { Text("Tags") },
                placeholder = { Text("work, finance, …") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )

            OutlinedTextField(
                value = notes,
                onValueChange = { notes = it },
                label = { Text("Notes") },
                minLines = 3,
                maxLines = 8,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("editor-notes"),
            )

            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text("Custom fields", style = MaterialTheme.typography.titleSmall)
                TextButton(
                    onClick = { customFields.add(EditableField("", "", false)) },
                    modifier = Modifier.testTag("editor-add-field"),
                ) {
                    Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Add field")
                }
            }

            customFields.forEachIndexed { index, field ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerLow),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            OutlinedTextField(
                                value = field.name,
                                onValueChange = { customFields[index] = field.copy(name = it) },
                                label = { Text("Field name") },
                                singleLine = true,
                                modifier = Modifier.weight(1f),
                            )
                            IconButton(onClick = { customFields.removeAt(index) }) {
                                Icon(Icons.Filled.Delete, contentDescription = "Remove field")
                            }
                        }
                        OutlinedTextField(
                            value = field.value,
                            onValueChange = { customFields[index] = field.copy(value = it) },
                            label = { Text("Value") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(
                                checked = field.protected,
                                onCheckedChange = { customFields[index] = field.copy(protected = it) },
                            )
                            Text("Protect value", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            Spacer(Modifier.height(8.dp))
            Button(
                onClick = { save() },
                enabled = !busy,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("editor-save-button"),
            ) {
                Text(if (entryUuid == null) "Create entry" else "Save changes")
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

private data class EditableField(
    val name: String,
    val value: String,
    val protected: Boolean,
)

/**
 * Interactive password generator dialog usable from both the entry editor and settings.
 */
@Composable
fun PasswordGeneratorDialog(
    onDismiss: () -> Unit,
    onUsePassword: ((String) -> Unit)? = null,
    onCopy: (String) -> Unit,
) {
    var length by remember { mutableIntStateOf(20) }
    var uppercase by remember { mutableStateOf(true) }
    var lowercase by remember { mutableStateOf(true) }
    var digits by remember { mutableStateOf(true) }
    var symbols by remember { mutableStateOf(true) }

    fun nextPassword(): String = PasswordGenerator.generate(
        PasswordGenerator.Options(length, uppercase, lowercase, digits, symbols),
    )

    var preview by remember { mutableStateOf(nextPassword()) }
    val strength = remember(preview) { PasswordGenerator.evaluateStrength(preview) }

    fun regenerate() {
        if (!uppercase && !lowercase && !digits && !symbols) return
        preview = nextPassword()
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Password generator") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            text = preview,
                            fontFamily = FontFamily.Monospace,
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier
                                .weight(1f)
                                .testTag("generator-preview"),
                        )
                        IconButton(onClick = { regenerate() }, modifier = Modifier.testTag("generator-refresh")) {
                            Icon(Icons.Filled.Refresh, contentDescription = "Regenerate")
                        }
                    }
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    LinearProgressIndicator(progress = { strength.progress }, modifier = Modifier.weight(1f))
                    Text(
                        "${strength.label} · ${strength.entropyBits}b",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                Column {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text("Length", style = MaterialTheme.typography.labelLarge)
                        Text("$length", style = MaterialTheme.typography.labelLarge)
                    }
                    Slider(
                        value = length.toFloat(),
                        onValueChange = {
                            length = it.roundToInt()
                            regenerate()
                        },
                        valueRange = 8f..64f,
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    FilterChip(
                        selected = uppercase,
                        onClick = {
                            if (!uppercase || lowercase || digits || symbols) {
                                uppercase = !uppercase
                                regenerate()
                            }
                        },
                        label = { Text("A-Z") },
                    )
                    FilterChip(
                        selected = lowercase,
                        onClick = {
                            if (!lowercase || uppercase || digits || symbols) {
                                lowercase = !lowercase
                                regenerate()
                            }
                        },
                        label = { Text("a-z") },
                    )
                    FilterChip(
                        selected = digits,
                        onClick = {
                            if (!digits || uppercase || lowercase || symbols) {
                                digits = !digits
                                regenerate()
                            }
                        },
                        label = { Text("0-9") },
                    )
                    FilterChip(
                        selected = symbols,
                        onClick = {
                            if (!symbols || uppercase || lowercase || digits) {
                                symbols = !symbols
                                regenerate()
                            }
                        },
                        label = { Text("!@#") },
                    )
                }
            }
        },
        confirmButton = {
            if (onUsePassword != null) {
                Button(
                    onClick = { onUsePassword(preview) },
                    modifier = Modifier.testTag("generator-use"),
                ) {
                    Text("Use password")
                }
            } else {
                Button(
                    onClick = {
                        onCopy(preview)
                        onDismiss()
                    },
                    modifier = Modifier.testTag("generator-copy"),
                ) {
                    Text("Copy")
                }
            }
        },
        dismissButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                if (onUsePassword != null) {
                    OutlinedButton(onClick = { onCopy(preview) }) {
                        Text("Copy")
                    }
                }
                TextButton(onClick = onDismiss) { Text("Close") }
            }
        },
    )
}
