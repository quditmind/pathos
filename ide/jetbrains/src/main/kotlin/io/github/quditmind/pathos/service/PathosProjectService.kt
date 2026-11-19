// Loads the open findings of the project's PATHOS repository and holds them
// for the editor annotator and the tool window. Network calls and the
// keychain run on background threads; listeners are notified on the EDT.

package io.github.quditmind.pathos.service

import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.Disposable
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.diagnostic.logger
import com.intellij.openapi.options.ShowSettingsUtil
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.util.Computable
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.roots.ProjectRootManager
import com.intellij.openapi.vcs.ProjectLevelVcsManager
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.util.concurrency.AppExecutorUtil
import com.intellij.util.messages.Topic
import com.intellij.util.net.JdkProxyProvider
import com.intellij.xml.util.XmlStringUtil
import io.github.quditmind.pathos.api.ApiErrorKind
import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.api.JdkTransport
import io.github.quditmind.pathos.api.PathosApiException
import io.github.quditmind.pathos.api.PathosClient
import io.github.quditmind.pathos.api.PathosConfigException
import io.github.quditmind.pathos.api.Repository
import io.github.quditmind.pathos.api.describeError
import io.github.quditmind.pathos.api.validateBaseUrl
import io.github.quditmind.pathos.core.GitConfig
import io.github.quditmind.pathos.core.GroupingMode
import io.github.quditmind.pathos.core.MatchedBy
import io.github.quditmind.pathos.core.findingPathSegments
import io.github.quditmind.pathos.core.matchRepositories
import io.github.quditmind.pathos.settings.PathosConfigurable
import io.github.quditmind.pathos.settings.PathosSettings
import io.github.quditmind.pathos.settings.PathosSettingsListener
import io.github.quditmind.pathos.settings.TokenStore
import io.github.quditmind.pathos.ui.RepositoryChooser
import org.jetbrains.annotations.TestOnly
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.time.Duration
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** What the tool window shows. */
enum class ViewState { NOT_CONFIGURED, NO_REPOSITORY, LOADED, ERROR }

data class Snapshot(
    val state: ViewState,
    val findings: List<Finding> = emptyList(),
    /** Local file of each finding that exists in the checkout, by finding id. */
    val files: Map<String, VirtualFile> = emptyMap(),
    val byFile: Map<VirtualFile, List<Finding>> = emptyMap(),
    val baseUrl: String? = null,
    val repository: String? = null,
    /** Extra line above the tree, for example "Showing the first N findings". */
    val note: String? = null,
    /** Last loading error, already explained for the user. */
    val error: String? = null,
) {
    companion object {
        val NOT_CONFIGURED = Snapshot(ViewState.NOT_CONFIGURED)
    }
}

fun interface PathosFindingsListener {
    fun findingsChanged(snapshot: Snapshot)

    companion object {
        @JvmField
        val TOPIC: Topic<PathosFindingsListener> = Topic.create("PATHOS findings", PathosFindingsListener::class.java)
    }
}

/** A local git checkout and its remote URLs. */
data class GitCheckout(val root: Path, val remotes: List<String>)

data class RepositoryCandidates(
    val client: PathosClient,
    val repositories: List<Repository>,
    /** Detected repositories with the checkout they matched. */
    val matches: List<Pair<Repository, GitCheckout>>,
    val checkouts: List<GitCheckout>,
)

@Service(Service.Level.PROJECT)
class PathosProjectService(private val project: Project) : Disposable {
    private val log = logger<PathosProjectService>()

    @Volatile
    var snapshot: Snapshot = Snapshot.NOT_CONFIGURED
        private set

    private val refreshing = AtomicBoolean(false)
    private val refreshAgain = AtomicBoolean(false)
    private val started = AtomicBoolean(false)

    @Volatile
    private var timer: ScheduledFuture<*>? = null

    val grouping: GroupingMode
        get() = if (PathosProjectState.getInstance(project).state.grouping == "file") GroupingMode.FILE else GroupingMode.SEVERITY

    fun toggleGrouping() {
        val st = PathosProjectState.getInstance(project).state
        st.grouping = if (grouping == GroupingMode.SEVERITY) "file" else "severity"
        fire()
    }

    /** Called once per project after startup. */
    fun start() {
        if (!started.compareAndSet(false, true)) return
        ApplicationManager.getApplication().messageBus.connect(this).subscribe(
            PathosSettingsListener.TOPIC,
            PathosSettingsListener { urlChanged, intervalChanged ->
                if (intervalChanged) scheduleRefresh()
                if (urlChanged) publish(Snapshot.NOT_CONFIGURED)
                refresh(false)
            },
        )
        scheduleRefresh()
        refresh(false)
    }

    override fun dispose() {
        timer?.cancel(false)
        timer = null
    }

    // -------------------------------------------------------------------------
    // Configuration

    /** Validated base URL, or null. */
    fun baseUrlOrNull(): String? = try {
        validateBaseUrl(PathosSettings.getInstance().url)
    } catch (_: PathosConfigException) {
        null
    }

    /**
     * A client, or null (with a notification when [interactive]) if the URL or
     * the token is missing. Reads the keychain: background threads only.
     */
    fun client(interactive: Boolean): PathosClient? {
        val url = PathosSettings.getInstance().url
        val base = try {
            validateBaseUrl(url)
        } catch (e: PathosConfigException) {
            if (interactive || url.isNotEmpty()) notifyWithSettings(describeError(e), NotificationType.WARNING)
            return null
        }
        val token = TokenStore.get(base)
        if (token == null) {
            if (interactive) notifyWithSettings("No PATHOS API token is set for $base.", NotificationType.WARNING)
            return null
        }
        return try {
            // The IDE's HTTP proxy settings; no Authenticator, so no credentials are offered to PATHOS or a proxy.
            PathosClient(base, token, JdkTransport(JdkProxyProvider.getInstance().proxySelector), Duration.ofSeconds(30))
        } catch (e: PathosConfigException) {
            if (interactive) notify(describeError(e), NotificationType.ERROR)
            null
        }
    }

    // -------------------------------------------------------------------------
    // Repository selection

    private fun storedRepositoryId(baseUrl: String): String? {
        val st = PathosProjectState.getInstance(project).state
        return if (st.baseUrl == baseUrl && st.repositoryId.isNotEmpty()) st.repositoryId else null
    }

    fun rememberRepository(baseUrl: String, repo: Repository, root: Path?) {
        val st = PathosProjectState.getInstance(project).state
        st.baseUrl = baseUrl
        st.repositoryId = repo.id
        st.repositoryFullName = repo.fullName
        st.rootPath = root?.toString() ?: ""
    }

    private fun forgetRepository() {
        val st = PathosProjectState.getInstance(project).state
        st.repositoryId = ""
        st.repositoryFullName = ""
        st.rootPath = ""
    }

    /** Git checkouts of the project: the IDE's VCS roots and content roots with a .git. */
    fun gitCheckouts(): List<GitCheckout> {
        val dirs = ApplicationManager.getApplication().runReadAction(Computable<List<String>> {
            if (project.isDisposed) return@Computable emptyList()
            val out = LinkedHashSet<String>()
            for (root in ProjectLevelVcsManager.getInstance(project).getAllVcsRoots()) {
                if (root.path.isInLocalFileSystem) out.add(root.path.path)
            }
            for (root in ProjectRootManager.getInstance(project).contentRoots) {
                if (root.isInLocalFileSystem) out.add(root.path)
            }
            project.basePath?.let { out.add(it) }
            out.toList()
        })
        return dirs.mapNotNull { runCatching { Paths.get(it) }.getOrNull() }
            .filter { GitConfig.isGitRoot(it) }
            .distinct()
            .map { GitCheckout(it, GitConfig.remotesOf(it)) }
    }

    /** Loads the repositories and matches them with the git remotes. Background thread. */
    fun loadCandidates(client: PathosClient): RepositoryCandidates {
        val repos = client.listRepositories()
        val checkouts = gitCheckouts()
        val matches = ArrayList<Pair<Repository, GitCheckout>>()
        for (c in checkouts) {
            log.debug("${c.root}: ${c.remotes.size} git remote(s)")
            for (m in matchRepositories(c.remotes, repos)) {
                if (matches.none { it.first.id == m.repository.id }) matches.add(m.repository to c)
                if (m.by == MatchedBy.NAME) log.debug("${m.repository.fullName} matched by name")
            }
        }
        return RepositoryCandidates(client, repos, matches, checkouts)
    }

    private fun rootFor(): Path? {
        val st = PathosProjectState.getInstance(project).state
        if (st.rootPath.isNotEmpty()) {
            val p = runCatching { Paths.get(st.rootPath) }.getOrNull()
            if (p != null && Files.isDirectory(p)) return p
        }
        val checkouts = gitCheckouts()
        if (checkouts.size == 1) return checkouts[0].root
        return project.basePath?.let { runCatching { Paths.get(it) }.getOrNull() }
    }

    // -------------------------------------------------------------------------
    // Refresh

    fun scheduleRefresh() {
        timer?.cancel(false)
        timer = null
        val minutes = PathosSettings.getInstance().refreshIntervalMinutes.toLong()
        if (minutes > 0 && !project.isDisposed) {
            timer = AppExecutorUtil.getAppScheduledExecutorService()
                .scheduleWithFixedDelay({ refresh(false) }, minutes, minutes, TimeUnit.MINUTES)
        }
    }

    /** Reloads the findings in the background; concurrent calls are coalesced. */
    fun refresh(interactive: Boolean) {
        if (project.isDisposed) return
        if (!refreshing.compareAndSet(false, true)) {
            refreshAgain.set(true)
            return
        }
        ApplicationManager.getApplication().invokeLater({
            ProgressManager.getInstance().run(object : Task.Backgroundable(project, "PATHOS: loading findings", true) {
                override fun run(indicator: ProgressIndicator) {
                    doRefresh(interactive)
                }

                override fun onFinished() {
                    refreshing.set(false)
                    if (refreshAgain.getAndSet(false)) refresh(false)
                }
            })
        }, project.disposed)
    }

    private fun doRefresh(interactive: Boolean) {
        val client = client(interactive)
        if (client == null) {
            publish(Snapshot.NOT_CONFIGURED)
            return
        }
        var repoId = storedRepositoryId(client.baseUrl)
        if (repoId == null) {
            repoId = detectRepository(client)
            if (repoId == null) {
                if (interactive) {
                    notify(
                        "No PATHOS repository is selected for this project.",
                        NotificationType.INFORMATION,
                        NotificationAction.createSimpleExpiring("Select repository") { RepositoryChooser.choose(project) },
                    )
                }
                return
            }
        }
        val name = PathosProjectState.getInstance(project).state.repositoryFullName
        try {
            val page = client.listOpenFindings(repoId, PathosSettings.getInstance().maxFindings)
            val note = if (page.truncated) "Showing the first ${page.items.size} findings (Max findings setting)." else null
            val root = rootFor()?.let { LocalFileSystem.getInstance().refreshAndFindFileByNioFile(it) }
            publish(buildSnapshot(page.items, root, client.baseUrl, name, note))
            log.info("Loaded ${page.items.size} open finding(s) of $name${if (page.truncated) " (truncated)" else ""}")
        } catch (e: PathosApiException) {
            if (e.kind == ApiErrorKind.NOT_FOUND) {
                // Repository deleted or no longer visible: forget it.
                forgetRepository()
                publish(Snapshot(ViewState.NO_REPOSITORY, baseUrl = client.baseUrl, error = describeError(e, "Loading findings")))
            } else {
                publish(snapshot.copy(state = ViewState.ERROR, baseUrl = client.baseUrl, repository = name, error = describeError(e, "Loading findings")))
            }
            reportError(e, "Loading findings", interactive)
        }
    }

    /** Auto-detects the repository (exactly one match); returns its id or null. */
    private fun detectRepository(client: PathosClient): String? {
        val candidates = try {
            loadCandidates(client)
        } catch (e: PathosApiException) {
            publish(Snapshot(ViewState.ERROR, baseUrl = client.baseUrl, error = describeError(e, "Loading repositories")))
            reportError(e, "Loading repositories", false)
            return null
        }
        val m = candidates.matches
        if (m.size == 1) {
            log.info("Detected PATHOS repository ${m[0].first.fullName}")
            rememberRepository(client.baseUrl, m[0].first, m[0].second.root)
            return m[0].first.id
        }
        val note = when {
            m.size > 1 -> "Several PATHOS repositories match this project. Use “Select repository”."
            candidates.repositories.isNotEmpty() && candidates.checkouts.isNotEmpty() ->
                "No PATHOS repository matches this project's git remote. Use “Select repository”."
            else -> null
        }
        publish(Snapshot(ViewState.NO_REPOSITORY, baseUrl = client.baseUrl, note = note))
        return null
    }

    /** Maps findings to files of the checkout [root] that exist. */
    private fun buildSnapshot(findings: List<Finding>, root: VirtualFile?, baseUrl: String, repository: String, note: String?): Snapshot {
        val files = HashMap<String, VirtualFile>()
        if (root != null && root.isValid) {
            val cache = HashMap<String, VirtualFile?>()
            for (f in findings) {
                val rel = findingPathSegments(f.filePath)?.joinToString("/") ?: continue
                val vf = cache.getOrPut(rel) { root.findFileByRelativePath(rel)?.takeIf { it.isValid && !it.isDirectory } }
                if (vf != null) files[f.id] = vf
            }
        }
        val byFile = LinkedHashMap<VirtualFile, MutableList<Finding>>()
        for (f in findings) files[f.id]?.let { byFile.getOrPut(it) { ArrayList() }.add(f) }
        return Snapshot(ViewState.LOADED, findings, files, byFile, baseUrl, repository, note)
    }

    fun findingsFor(file: VirtualFile): List<Finding> = snapshot.byFile[file].orEmpty()

    private fun publish(s: Snapshot) {
        snapshot = s
        fire()
    }

    private fun fire() {
        ApplicationManager.getApplication().invokeLater({
            val s = snapshot
            project.messageBus.syncPublisher(PathosFindingsListener.TOPIC).findingsChanged(s)
            DaemonCodeAnalyzer.getInstance(project).restart("PATHOS findings changed")
        }, project.disposed)
    }

    /** Sets findings directly (tests of the annotator). */
    @TestOnly
    fun setFindingsForTests(findings: List<Finding>, root: VirtualFile, baseUrl: String = "https://pathos.example.com") {
        snapshot = buildSnapshot(findings, root, baseUrl, "test/repo", null)
    }

    // -------------------------------------------------------------------------
    // Messages

    fun reportError(e: Throwable, action: String, interactive: Boolean) {
        val msg = describeError(e, action)
        val rid = (e as? PathosApiException)?.requestId?.let { " (request $it)" } ?: ""
        // Messages never contain the token: it is only in the Authorization header.
        log.warn("$action: ${e.message}$rid")
        val kind = (e as? PathosApiException)?.kind
        val unauthorized = kind == ApiErrorKind.UNAUTHORIZED
        if (!interactive && !unauthorized && e !is PathosConfigException) return
        if (unauthorized || kind == ApiErrorKind.READ_ONLY) {
            notifyWithSettings(msg, NotificationType.ERROR)
            return
        }
        notify(msg + rid, NotificationType.ERROR)
    }

    fun notify(message: String, type: NotificationType, vararg actions: NotificationAction) {
        val n = NotificationGroupManager.getInstance().getNotificationGroup(NOTIFICATION_GROUP)
            // Notification content is HTML; messages can contain server text.
            .createNotification("PATHOS", XmlStringUtil.escapeString(message), type)
        for (a in actions) n.addAction(a)
        n.notify(project)
    }

    private fun notifyWithSettings(message: String, type: NotificationType) {
        notify(
            message,
            type,
            NotificationAction.createSimpleExpiring("Open PATHOS settings") {
                ShowSettingsUtil.getInstance().showSettingsDialog(project, PathosConfigurable::class.java)
            },
        )
    }

    companion object {
        const val NOTIFICATION_GROUP = "PATHOS"

        fun getInstance(project: Project): PathosProjectService = project.getService(PathosProjectService::class.java)
    }
}
