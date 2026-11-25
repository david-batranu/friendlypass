package org.friendlypass.android

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.friendlypass.android.ui.BrowserScreen
import org.friendlypass.android.ui.EntryDetailScreen
import org.friendlypass.android.ui.SettingsScreen
import org.friendlypass.android.ui.theme.FriendlypassTheme
import org.friendlypass.android.unlock.UnlockGate
import org.friendlypass.android.vault.FakeVaultRepository
import org.friendlypass.android.vault.model.VaultState

/**
 * Single Compose activity: gate (picker/unlock) → browser → entry detail/settings.
 *
 * `FLAG_SECURE` is applied while the unlock screen or an entry detail is showing. Debug builds accept
 * [EXTRA_ALLOW_CAPTURE] so emulator screenshots of those screens can be taken; release builds always keep it.
 */
class MainActivity : FragmentActivity() {

    private val app: FriendlypassApp get() = application as FriendlypassApp

    private val allowScreenCapture: Boolean by lazy {
        BuildConfig.DEBUG && intent.getBooleanExtra(EXTRA_ALLOW_CAPTURE, false)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        if (BuildConfig.DEBUG && intent.getBooleanExtra(EXTRA_DEMO_DATABASE, false)) {
            app.store.remember(FakeVaultRepository.DEMO_DATABASE)
            app.vault.selectDatabase(FakeVaultRepository.DEMO_DATABASE)
        }
        // Debug-only: open a file:// database copied into app-private storage (instrumented tests and
        // manual emulator checks; the storage gateway only accepts file:// in debug builds).
        if (BuildConfig.DEBUG) {
            intent.getStringExtra(EXTRA_DEBUG_DATABASE_FILE)?.takeIf { it.isNotBlank() }?.let { path ->
                val file = java.io.File(path)
                val ref = org.friendlypass.android.vault.model.DatabaseRef(
                    android.net.Uri.fromFile(file).toString(),
                    file.name,
                )
                app.store.remember(ref)
                app.vault.selectDatabase(ref)
            }
        }

        setContent {
            FriendlypassTheme {
                FriendlypassRoot(allowScreenCapture = allowScreenCapture)
            }
        }

        lifecycleScope.launch {
            while (isActive) {
                delay(IDLE_CHECK_INTERVAL_MS)
                app.autoLock.checkIdle()
            }
        }
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        app.autoLock.touch()
    }

    companion object {
        private const val IDLE_CHECK_INTERVAL_MS = 10_000L

        /** Debug-only: skip `FLAG_SECURE` so `adb screencap` works for development screenshots. */
        const val EXTRA_ALLOW_CAPTURE = "org.friendlypass.android.ALLOW_CAPTURE"

        /** Debug-only: open the built-in sample database instead of showing the file picker. */
        const val EXTRA_DEMO_DATABASE = "org.friendlypass.android.DEMO_DATABASE"

        /** Debug-only: open a KDBX file path (used with a fixture copied into app-private storage). */
        const val EXTRA_DEBUG_DATABASE_FILE = "org.friendlypass.android.DEBUG_DATABASE_FILE"
    }
}

@Composable
private fun FriendlypassRoot(allowScreenCapture: Boolean) {
    val context = LocalContext.current
    val app = context.applicationContext as FriendlypassApp
    val navController = rememberNavController()
    val state by app.vault.state.collectAsStateWithLifecycle()
    val backStackEntry by navController.currentBackStackEntryAsState()
    val route = backStackEntry?.destination?.route

    val secureScreen = route?.startsWith("entry/") == true ||
        (route == "gate" && state is VaultState.Locked)
    SecureFlag(secure = secureScreen && !allowScreenCapture)

    LaunchedEffect(state, route) {
        if (state !is VaultState.Unlocked && route != null && route != "gate") {
            navController.navigate("gate") {
                popUpTo(navController.graph.id) { inclusive = true }
                launchSingleTop = true
            }
        }
    }

    NavHost(navController = navController, startDestination = "gate") {
        composable("gate") {
            UnlockGate(
                onUnlocked = {
                    navController.navigate("browser") {
                        popUpTo("gate") { inclusive = true }
                    }
                },
                onCancel = { context.findActivity()?.finish() },
            )
        }
        composable("browser") {
            if (state is VaultState.Unlocked) {
                BrowserScreen(
                    onOpenEntry = { uuid -> navController.navigate("entry/$uuid") },
                    onOpenSettings = { navController.navigate("settings") },
                )
            } else {
                Box(Modifier.fillMaxSize())
            }
        }
        composable(
            route = "entry/{uuid}",
            arguments = listOf(navArgument("uuid") { type = NavType.StringType }),
        ) { entry ->
            if (state is VaultState.Unlocked) {
                EntryDetailScreen(
                    entryUuid = entry.arguments?.getString("uuid").orEmpty(),
                    onBack = { navController.popBackStack() },
                )
            } else {
                Box(Modifier.fillMaxSize())
            }
        }
        composable("settings") {
            if (state is VaultState.Unlocked) {
                SettingsScreen(onBack = { navController.popBackStack() })
            } else {
                Box(Modifier.fillMaxSize())
            }
        }
    }
}

@Composable
private fun SecureFlag(secure: Boolean) {
    val view = LocalView.current
    DisposableEffect(secure) {
        val window = view.context.findActivity()?.window
        if (secure) {
            window?.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        onDispose {
            if (secure) window?.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}

private fun Context.findActivity(): Activity? {
    var current: Context = this
    while (current is ContextWrapper) {
        if (current is Activity) return current
        current = current.baseContext
    }
    return null
}
