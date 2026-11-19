// Settings → Tools → PATHOS: server URL, API token (PasswordSafe), refresh
// interval and the maximum number of findings.

package io.github.quditmind.pathos.settings

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.application.ModalityState
import com.intellij.openapi.options.ConfigurationException
import com.intellij.openapi.options.SearchableConfigurable
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import com.intellij.ui.components.JBTextField
import com.intellij.ui.dsl.builder.AlignX
import com.intellij.ui.dsl.builder.panel
import com.intellij.util.ui.JBUI
import io.github.quditmind.pathos.api.PathosConfigException
import io.github.quditmind.pathos.api.validateBaseUrl
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JSpinner
import javax.swing.SpinnerNumberModel

class PathosConfigurable : SearchableConfigurable {
    private val urlField = JBTextField()
    private val tokenField = JBPasswordField()
    private val tokenStatus = JBLabel()
    private val clearButton = JButton("Clear Stored Token")
    private val intervalSpinner = JSpinner(SpinnerNumberModel(0, 0, 1440, 1))
    private val maxSpinner = JSpinner(SpinnerNumberModel(PathosSettings.DEFAULT_MAX_FINDINGS, 1, PathosSettings.MAX_FINDINGS_LIMIT, 100))

    @Volatile
    private var clearRequested = false

    override fun getId(): String = ID

    override fun getDisplayName(): String = "PATHOS"

    override fun createComponent(): JComponent {
        tokenField.emptyText.text = "pathos_pat_…  (leave empty to keep the stored token)"
        clearButton.addActionListener {
            clearRequested = true
            tokenField.text = ""
            tokenStatus.text = "The stored token will be removed when you apply."
        }
        return panel {
            row("Server URL:") {
                cell(urlField).align(AlignX.FILL)
                    .comment("For example https://pathos.example.com. https is required; plain http only for localhost.")
            }
            row("API token:") {
                cell(tokenField).align(AlignX.FILL)
                    .comment(
                        "Create it in PATHOS: user menu → API tokens (MCP). \"REST API: read\" shows findings; " +
                            "\"REST API: read and write\" also changes statuses and requests reviews. " +
                            "Stored in the IDE password safe for this URL only, never in settings files.",
                    )
            }
            row("") {
                cell(tokenStatus)
                cell(clearButton)
            }
            row("Refresh every:") {
                cell(intervalSpinner)
                label("minutes (0 = only on startup and on Refresh)")
            }
            row("Max findings:") {
                cell(maxSpinner)
                label("open findings loaded for the repository, highest severity first")
            }
        }.also { it.border = JBUI.Borders.empty(4) }
    }

    override fun isModified(): Boolean {
        val s = PathosSettings.getInstance()
        return urlField.text.trim() != s.url ||
            tokenField.password.isNotEmpty() ||
            clearRequested ||
            intervalSpinner.value != s.refreshIntervalMinutes ||
            maxSpinner.value != s.maxFindings
    }

    override fun apply() {
        val url = urlField.text.trim()
        val base = if (url.isEmpty()) {
            null
        } else {
            try {
                validateBaseUrl(url)
            } catch (e: PathosConfigException) {
                throw ConfigurationException(e.message, "PATHOS")
            }
        }
        val token = String(tokenField.password).trim()
        if (token.isNotEmpty() && base == null) throw ConfigurationException("Set the server URL before the API token.", "PATHOS")
        if (token.any { it.isWhitespace() }) throw ConfigurationException("The token must not contain spaces.", "PATHOS")
        val clear = clearRequested
        val oldBase = currentBase()
        // Keychain writes happen off the EDT; the settings change is published afterwards.
        ApplicationManager.getApplication().executeOnPooledThread {
            if (clear) (oldBase ?: base)?.let { TokenStore.clear(it) }
            if (token.isNotEmpty() && base != null) TokenStore.set(base, token)
            ApplicationManager.getApplication().invokeLater({
                PathosSettings.getInstance().update(url, intervalSpinner.value as Int, maxSpinner.value as Int)
            }, ModalityState.any())
        }
        tokenField.text = ""
        clearRequested = false
        loadTokenStatus(base)
    }

    override fun reset() {
        val s = PathosSettings.getInstance()
        urlField.text = s.url
        tokenField.text = ""
        clearRequested = false
        intervalSpinner.value = s.refreshIntervalMinutes
        maxSpinner.value = s.maxFindings
        loadTokenStatus(currentBase())
    }

    private fun currentBase(): String? = try {
        validateBaseUrl(PathosSettings.getInstance().url)
    } catch (_: PathosConfigException) {
        null
    }

    private fun loadTokenStatus(base: String?) {
        if (base == null) {
            tokenStatus.text = "No token stored (set the server URL first)."
            clearButton.isEnabled = false
            return
        }
        tokenStatus.text = "Checking the password safe…"
        ApplicationManager.getApplication().executeOnPooledThread {
            val has = TokenStore.get(base) != null
            ApplicationManager.getApplication().invokeLater({
                tokenStatus.text = if (has) "A token is stored for $base." else "No token is stored for $base."
                clearButton.isEnabled = has
            }, ModalityState.any())
        }
    }

    companion object {
        const val ID = "io.github.quditmind.pathos.settings"
    }
}
