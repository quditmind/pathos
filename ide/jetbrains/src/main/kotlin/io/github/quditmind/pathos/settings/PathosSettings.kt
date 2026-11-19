// Application-level settings (like VS Code's application-scope pathos.url):
// a project cannot change where the API token is sent. The token itself is
// never stored here; see TokenStore.

package io.github.quditmind.pathos.settings

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.util.messages.Topic

@Service(Service.Level.APP)
@State(name = "PathosSettings", storages = [Storage("pathos.xml")])
class PathosSettings : PersistentStateComponent<PathosSettings.State> {
    class State {
        /** Raw server URL (validated when used). */
        var url: String = ""
        var refreshIntervalMinutes: Int = 0
        var maxFindings: Int = DEFAULT_MAX_FINDINGS
    }

    private var state = State()

    override fun getState(): State = state

    override fun loadState(state: State) {
        this.state = state
    }

    val url: String get() = state.url.trim()

    /** 0 = automatic refresh off; at most 1440 minutes. */
    val refreshIntervalMinutes: Int get() = state.refreshIntervalMinutes.let { if (it > 0) minOf(it, 1440) else 0 }

    /** 1 to 20,000; default 5,000. */
    val maxFindings: Int get() = state.maxFindings.let { if (it > 0) minOf(it, MAX_FINDINGS_LIMIT) else DEFAULT_MAX_FINDINGS }

    fun update(url: String, refreshIntervalMinutes: Int, maxFindings: Int) {
        val urlChanged = url.trim() != state.url.trim()
        val intervalChanged = refreshIntervalMinutes != state.refreshIntervalMinutes
        state.url = url.trim()
        state.refreshIntervalMinutes = refreshIntervalMinutes
        state.maxFindings = maxFindings
        ApplicationManager.getApplication().messageBus.syncPublisher(PathosSettingsListener.TOPIC)
            .settingsChanged(urlChanged = urlChanged, intervalChanged = intervalChanged)
    }

    companion object {
        const val DEFAULT_MAX_FINDINGS = 5000
        const val MAX_FINDINGS_LIMIT = 20_000

        fun getInstance(): PathosSettings = ApplicationManager.getApplication().getService(PathosSettings::class.java)
    }
}

fun interface PathosSettingsListener {
    /** Settings or the stored token changed. */
    fun settingsChanged(urlChanged: Boolean, intervalChanged: Boolean)

    companion object {
        @JvmField
        val TOPIC: Topic<PathosSettingsListener> = Topic.create("PATHOS settings", PathosSettingsListener::class.java)
    }
}
