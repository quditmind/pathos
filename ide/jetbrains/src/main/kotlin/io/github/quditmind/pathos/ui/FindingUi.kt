// Finding commands: open location, open in PATHOS, details, change status,
// request a Human Eye review. Network calls run in background tasks.

package io.github.quditmind.pathos.ui

import com.intellij.ide.BrowserUtil
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.actionSystem.DataKey
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.InputValidatorEx
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.ui.popup.JBPopupFactory
import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.api.FindingStatus
import io.github.quditmind.pathos.api.PathosApiException
import io.github.quditmind.pathos.api.PathosClient
import io.github.quditmind.pathos.api.findingWebUrl
import io.github.quditmind.pathos.core.MAX_REVIEW_REASON_LENGTH
import io.github.quditmind.pathos.core.allowedStatusTargets
import io.github.quditmind.pathos.core.displayPath
import io.github.quditmind.pathos.core.severityLabel
import io.github.quditmind.pathos.core.zeroBasedLine
import io.github.quditmind.pathos.service.PathosProjectService

object FindingUi {
    @JvmField
    val FINDING: DataKey<Finding> = DataKey.create("pathos.finding")

    /** The finding of the tree selection or annotation, or a popup to pick one. */
    fun withFinding(e: AnActionEvent, title: String, action: (Project, Finding) -> Unit) {
        val project = e.project ?: return
        e.getData(FINDING)?.let {
            action(project, it)
            return
        }
        val service = PathosProjectService.getInstance(project)
        val s = service.snapshot
        if (s.findings.isEmpty()) {
            service.notify("No PATHOS findings are loaded. Refresh the findings first.", NotificationType.INFORMATION)
            return
        }
        val active = e.getData(CommonDataKeys.VIRTUAL_FILE)
        val list = s.findings.sortedByDescending { active != null && s.files[it.id] == active }
        JBPopupFactory.getInstance().createPopupChooserBuilder(list)
            .setTitle(title)
            .setRenderer(plainTextRenderer<Finding> { label(it) })
            .setNamerForFiltering { label(it) }
            .setVisibleRowCount(15)
            .setItemChosenCallback { action(project, it) }
            .createPopup()
            .showCenteredInCurrentWindow(project)
    }

    private fun label(f: Finding): String {
        val p = displayPath(f.filePath)
        val loc = if (p.isEmpty()) "" else " · $p" + (f.startLine?.let { ":$it" } ?: "")
        return "${f.title.ifEmpty { "Untitled finding" }}  (${severityLabel(f.severity)}$loc)"
    }

    /** Opens the finding's file at its line, or its details when the file is not in the checkout. */
    fun openFinding(project: Project, f: Finding) {
        val file = PathosProjectService.getInstance(project).snapshot.files[f.id]
        if (file == null || !file.isValid) {
            showDetails(project, f)
            return
        }
        OpenFileDescriptor(project, file, zeroBasedLine(f.startLine), 0).navigate(true)
    }

    fun openInPathos(project: Project, f: Finding) {
        val base = PathosProjectService.getInstance(project).baseUrlOrNull() ?: return
        BrowserUtil.browse(findingWebUrl(base, f.id))
    }

    /** Loads the full finding (with the code snippet) and shows the details dialog. */
    fun showDetails(project: Project, f: Finding) {
        val service = PathosProjectService.getInstance(project)
        val base = service.baseUrlOrNull() ?: return
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, "PATHOS: loading finding", true) {
            override fun run(indicator: ProgressIndicator) {
                var full = f
                val client = service.client(false)
                if (client != null) {
                    try {
                        full = client.getFinding(f.id)
                    } catch (e: PathosApiException) {
                        // Show what is loaded; the details dialog does not need the snippet.
                        service.reportError(e, "Loading the finding details", false)
                    }
                }
                ApplicationManager.getApplication().invokeLater({ FindingDetailsDialog(project, full, base).show() }, project.disposed)
            }
        })
    }

    fun changeStatus(project: Project, f: Finding) {
        val service = PathosProjectService.getInstance(project)
        if (allowedStatusTargets(f.status).isEmpty()) {
            service.notify(
                if (f.status == "accepted_risk") {
                    "Accepted risk can only be changed through a risk acceptance in PATHOS."
                } else {
                    "The status ${f.status} cannot be changed manually."
                },
                NotificationType.INFORMATION,
            )
            return
        }
        val dialog = ChangeStatusDialog(project, f)
        if (!dialog.showAndGet()) return
        val target = dialog.selectedStatus
        val reason = dialog.reason
        runWrite(project, "PATHOS: changing status", "Changing the status") { client ->
            client.changeStatus(f.id, target, reason)
            "Status changed to ${target.label.lowercase()}."
        }
    }

    fun requestReview(project: Project, f: Finding) {
        val reason = Messages.showInputDialog(
            project,
            "Optional reason for the reviewers:",
            "Request a Human Eye Review of “${f.title.take(60)}”",
            null,
            "",
            object : InputValidatorEx {
                override fun getErrorText(inputString: String): String? =
                    if (inputString.length > MAX_REVIEW_REASON_LENGTH) "At most $MAX_REVIEW_REASON_LENGTH characters" else null
            },
        ) ?: return
        runWrite(project, "PATHOS: requesting review", "Requesting a review") { client ->
            val res = client.requestHumanReview(f.id, reason)
            if (res.created.isNotEmpty()) "Human Eye review requested." else "This finding already has a Human Eye review."
        }
    }

    private fun runWrite(project: Project, title: String, action: String, call: (PathosClient) -> String) {
        val service = PathosProjectService.getInstance(project)
        ProgressManager.getInstance().run(object : Task.Backgroundable(project, title, false) {
            override fun run(indicator: ProgressIndicator) {
                val client = service.client(true) ?: return
                try {
                    val message = call(client)
                    service.notify(message, NotificationType.INFORMATION)
                    service.refresh(false)
                } catch (e: PathosApiException) {
                    service.reportError(e, action, true)
                }
            }
        })
    }

    /** Status targets offered for a finding (used by the dialog). */
    fun targets(f: Finding): List<FindingStatus> = allowedStatusTargets(f.status)
}
