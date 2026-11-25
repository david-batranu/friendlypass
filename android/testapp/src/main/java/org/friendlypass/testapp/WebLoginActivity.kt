package org.friendlypass.testapp

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat

/**
 * WebView login form served from `https://appassets.androidplatform.net/assets/<page>.html` through
 * [WebViewAssetLoader], so autofill sees a real web origin (webDomain `appassets.androidplatform.net`)
 * with HTML autocomplete attributes instead of a native form.
 *
 * [PAGE_LOGIN] is the username/password page; [PAGE_OTP] a single one-time-code input and
 * [PAGE_OTP_SPLIT] six single-character boxes.
 */
class WebLoginActivity : Activity() {

    private lateinit var webView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_web)
        webView = findViewById(R.id.web_view)

        val assetLoader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        webView.webViewClient = object : WebViewClientCompat() {
            override fun shouldInterceptRequest(
                view: WebView,
                request: WebResourceRequest,
            ): WebResourceResponse? = assetLoader.shouldInterceptRequest(request.url)
        }
        webView.settings.javaScriptEnabled = false
        webView.loadUrl("https://appassets.androidplatform.net/assets/${page(intent)}.html")
    }

    override fun onDestroy() {
        webView.destroy()
        super.onDestroy()
    }

    private fun page(intent: Intent): String =
        intent.getStringExtra(EXTRA_PAGE)?.takeIf { it in PAGES } ?: PAGE_LOGIN

    companion object {
        const val EXTRA_PAGE = "org.friendlypass.testapp.PAGE"
        const val PAGE_LOGIN = "login"
        const val PAGE_OTP = "otp"
        const val PAGE_OTP_SPLIT = "otp-split"
        const val PAGE_OTP_COMBINED = "otp-combined"
        private val PAGES = setOf(PAGE_LOGIN, PAGE_OTP, PAGE_OTP_SPLIT, PAGE_OTP_COMBINED)

        fun intent(context: Context, page: String): Intent =
            Intent(context, WebLoginActivity::class.java).putExtra(EXTRA_PAGE, page)
    }
}
