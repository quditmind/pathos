// Actions of the tool window toolbar, the finding context menu and
// Tools → PATHOS (also reachable through Find Action).

package io.github.quditmind.pathos.actions

import com.intellij.openapi.actionSystem.ActionUpdateThread
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.options.ShowSettingsUtil
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.InputValidatorEx
import com.intellij.openapi.ui.Messages
import com.intellij.notification.NotificationType
import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.service.PathosProjectService
import io.github.quditmind.pathos.settings.PathosConfigurable
import io.github.quditmind.pathos.settings.PathosSettingsListener
import io.github.quditmind.pathos.settings.TokenStore
import io.github.quditmind.pathos.ui.FindingUi
import io.github.quditmind.pathos.ui.RepositoryChooser

abstract class PathosAction : AnAction(), DumbAware {
    override fun getActionUpdateThread(): ActionUpdateThread = ActionUpdateThread.BGT

    override fun update(e: AnActionEvent) {
        e.presentation.isEnabledAndVisible = e.project != null
    }
}

class RefreshAction : PathosAction() {
    override fun actionPerformed(e: AnActionEvent) {
        e.project?.let { PathosProjectService.getInstance(it).refresh(true) }
    }
}

class ToggleGroupingAction : PathosAction() {
    override fun actionPerformed(e: AnActionEvent) {
        e.project?.let { PathosProjectService.getInstance(it).toggleGrouping() }
    }
}

class SelectRepositoryAction : PathosAction() {
    override fun actionPerformed(e: AnActionEvent) {
        e.project?.let { RepositoryChooser.choose(it) }
    }
}

class OpenSettingsAction : PathosAction() {
    override fun update(e: AnActionEvent) {
        e.presentation.isEnabledAndVisible = true
    }

    override fun actionPerformed(e: AnActionEvent) {
        ShowSettingsUtil.getInstance().showSettingsDialog(e.project, PathosConfigurable::class.java)
    }
}

class SetTokenAction : PathosAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        setToken(project)
    }

    companion object {
        fun setToken(project: Project) {
            val service = PathosProjectService.getInstance(project)
            val base = service.baseUrlOrNull()
            if (base == null) {
                Messages.showWarningDialog(project, "Set the PATHOS server URL in Settings → Tools → PATHOS first.", "PATHOS")
                ShowSettingsUtil.getInstance().showSettingsDialog(project, PathosConfigurable::class.java)
                return
            }
            val token = Messages.showPasswordDialog(
                project,
                "Paste a PATHOS REST API token for $base (user menu → API tokens (MCP): \"REST API: read\" to view findings, " +
                    "\"read and write\" to change status or request reviews). It is stored in the IDE password safe.",
                "PATHOS API Token",
                null,
                object : InputValidatorEx {
                    override fun getErrorText(inputString: String): String? = when {
                        inputString.isBlank() -> "Enter the token"
                        inputString.trim().any { it.isWhitespace() } -> "The token must not contain spaces"
                        else -> null
                    }
                },
            )?.trim()
            if (token.isNullOrEmpty()) return
            ApplicationManager.getApplication().executeOnPooledThread {
                TokenStore.set(base, token)
                ApplicationManager.getApplication().messageBus.syncPublisher(PathosSettingsListener.TOPIC)
                    .settingsChanged(urlChanged = false, intervalChanged = false)
            }
        }
    }
}

class ClearTokenAction : PathosAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val service = PathosProjectService.getInstance(project)
        val base = service.baseUrlOrNull()
        if (base == null) {
            service.notify("The PATHOS server URL is not set; there is no token to clear.", NotificationType.INFORMATION)
            return
        }
        ApplicationManager.getApplication().executeOnPooledThread {
            TokenStore.clear(base)
            service.notify("PATHOS API token for $base removed.", NotificationType.INFORMATION)
            ApplicationManager.getApplication().messageBus.syncPublisher(PathosSettingsListener.TOPIC)
                .settingsChanged(urlChanged = false, intervalChanged = false)
        }
    }
}

/** Actions on one finding: the tree selection, or a popup to pick one. */
abstract class FindingAction(private val title: String) : PathosAction() {
    abstract fun run(project: Project, finding: Finding)

    override fun actionPerformed(e: AnActionEvent) = FindingUi.withFinding(e, title) { p, f -> run(p, f) }
}

class OpenFindingAction : FindingAction("PATHOS: Open Finding") {
    override fun run(project: Project, finding: Finding) = FindingUi.openFinding(project, finding)
}

class ShowDetailsAction : FindingAction("PATHOS: Finding Details") {
    override fun run(project: Project, finding: Finding) = FindingUi.showDetails(project, finding)
}

class OpenInPathosAction : FindingAction("PATHOS: Open Finding in PATHOS") {
    override fun run(project: Project, finding: Finding) = FindingUi.openInPathos(project, finding)
}

class ChangeStatusAction : FindingAction("PATHOS: Change Finding Status") {
    override fun run(project: Project, finding: Finding) = FindingUi.changeStatus(project, finding)
}

class RequestReviewAction : FindingAction("PATHOS: Request Human Eye Review") {
    override fun run(project: Project, finding: Finding) = FindingUi.requestReview(project, finding)
}
