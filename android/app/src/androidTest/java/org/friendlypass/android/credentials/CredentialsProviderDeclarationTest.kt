package org.friendlypass.android.credentials

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.friendlypass.android.R
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.xmlpull.v1.XmlPullParser

/** The provider is only useful if the system can discover it with the right permission and capabilities. */
@RunWith(AndroidJUnit4::class)
class CredentialsProviderDeclarationTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val packageManager: PackageManager = context.packageManager

    @Test
    fun providerServiceIsDeclaredEnabledAndAdvertisesCapabilities() {
        assumeTrue(Build.VERSION.SDK_INT >= 34)

        val services = packageManager.queryIntentServices(
            Intent("android.service.credentials.CredentialProviderService").setPackage(context.packageName),
            PackageManager.GET_META_DATA,
        )
        val info = services
            .map { it.serviceInfo }
            .firstOrNull { it.name == FriendlypassCredentialProviderService::class.java.name }

        assertNotNull("credential provider service is not declared", info)
        assertEquals("android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE", info!!.permission)
        assertTrue("provider must be enabled on API 34+", info.enabled)
        assertEquals(context.getString(R.string.credentials_provider_label), info.loadLabel(packageManager).toString())

        val parser = info.loadXmlMetaData(packageManager, "android.credentials.provider")
        assertNotNull("provider.xml meta-data is missing", parser)
        val capabilities = mutableSetOf<String>()
        var event = parser!!.eventType
        while (event != XmlPullParser.END_DOCUMENT) {
            if (event == XmlPullParser.START_TAG && parser.name == "capability") {
                parser.getAttributeValue(null, "name")?.let(capabilities::add)
            }
            event = parser.next()
        }
        parser.close()

        assertTrue(capabilities.contains("android.credentials.TYPE_PASSWORD_CREDENTIAL"))
        assertTrue(capabilities.any { it.endsWith("TYPE_PUBLIC_KEY_CREDENTIAL") })
    }

    @Test
    fun credentialActivitiesAreNotExported() {
        for (activity in listOf(CredentialsGetActivity::class.java, CredentialsCreateActivity::class.java)) {
            val info = packageManager.getActivityInfo(ComponentName(context, activity), 0)
            assertFalse("$activity must only be launchable through its PendingIntent", info.exported)
        }
    }
}
