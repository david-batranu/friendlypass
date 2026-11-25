package org.friendlypass.testapp

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.autofill.AutofillManager
import android.widget.Button

/**
 * Native login form for autofill end-to-end tests: username + password fields with standard
 * `autofillHints`. "Sign in" commits the form so the framework fires a save request, then finishes.
 */
class LoginActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        findViewById<Button>(R.id.sign_in).setOnClickListener {
            getSystemService(AutofillManager::class.java)?.commit()
            finish()
        }
        findViewById<Button>(R.id.open_web_login).setOnClickListener {
            startActivity(Intent(this, WebLoginActivity::class.java))
        }
    }
}
