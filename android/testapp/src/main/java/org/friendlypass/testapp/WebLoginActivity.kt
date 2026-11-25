package org.friendlypass.testapp

import android.app.Activity
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewClientCompat

/**
 * WebView login form served from `https://appassets.androidplatform.net/assets/login.html` through
 * [WebViewAssetLoader], so autofill sees a real web origin (webDomain `appassets.androidplatform.net`)
 * with HTML autocomplete attributes instead of a native form.
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
        webView.loadUrl("https://appassets.androidplatform.net/assets/login.html")
    }

    override fun onDestroy() {
        webView.destroy()
        super.onDestroy()
    }
}
