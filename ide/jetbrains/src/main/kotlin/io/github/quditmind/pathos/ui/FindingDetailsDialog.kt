package io.github.quditmind.pathos.ui

import com.intellij.ide.BrowserUtil
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.ui.components.JBScrollPane
import com.intellij.util.ui.HTMLEditorKitBuilder
import com.intellij.util.ui.JBUI
import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.api.findingWebUrl
import io.github.quditmind.pathos.core.buildDetailsHtml
import java.awt.event.ActionEvent
import javax.swing.AbstractAction
import javax.swing.Action
import javax.swing.JComponent
import javax.swing.JEditorPane
import javax.swing.event.HyperlinkEvent

/**
 * Finding details (non-modal). All scanner text is HTML-escaped by
 * buildDetailsHtml; the only link opened is the finding's PATHOS URL.
 */
class FindingDetailsDialog(
    private val project: Project,
    private val finding: Finding,
    baseUrl: String,
) : DialogWrapper(project, null, false, IdeModalityType.MODELESS, true) {
    private val webUrl = findingWebUrl(baseUrl, finding.id)

    init {
        title = "PATHOS: ${finding.title.ifEmpty { "finding" }.take(60)}"
        setCancelButtonText("Close")
        init()
    }

    override fun createCenterPanel(): JComponent {
        val pane = JEditorPane().apply {
            editorKit = HTMLEditorKitBuilder.simple()
            isEditable = false
            text = buildDetailsHtml(finding, webUrl)
            caretPosition = 0
            addHyperlinkListener { e ->
                if (e.eventType == HyperlinkEvent.EventType.ACTIVATED && e.description == webUrl) BrowserUtil.browse(webUrl)
            }
        }
        return JBScrollPane(pane).apply { preferredSize = JBUI.size(640, 560) }
    }

    override fun createActions(): Array<Action> = arrayOf(
        action("Open in PATHOS") { BrowserUtil.browse(webUrl) },
        action("Change Status…") { FindingUi.changeStatus(project, finding) },
        action("Request Human Eye Review…") { FindingUi.requestReview(project, finding) },
        cancelAction,
    )

    private fun action(name: String, run: () -> Unit): Action = object : AbstractAction(name) {
        override fun actionPerformed(e: ActionEvent?) = run()
    }
}
