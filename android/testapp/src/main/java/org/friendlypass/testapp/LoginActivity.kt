package org.friendlypass.testapp

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillManager
import android.widget.Button
import android.widget.EditText

/**
 * Native login form for autofill end-to-end tests: username + password fields with standard
 * `autofillHints`. "Sign in" commits the form so the framework fires a save request, then finishes.
 *
 * With the username `otp-user` the flow continues to [OtpActivity], like a real two-step login where the
 * password page is followed by a one-time-code page.
 */
class LoginActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        findViewById<Button>(R.id.sign_in).setOnClickListener {
            val username = findViewById<EditText>(R.id.username).text.toString().trim()
            getSystemService(AutofillManager::class.java)?.commit()
            if (username == OTP_USERNAME) {
                startActivity(Intent(this, OtpActivity::class.java))
            } else {
                finish()
            }
        }
        findViewById<Button>(R.id.open_web_login).setOnClickListener {
            startActivity(WebLoginActivity.intent(this, WebLoginActivity.PAGE_LOGIN))
        }
    }

    companion object {
        const val OTP_USERNAME = "otp-user"
    }
}
