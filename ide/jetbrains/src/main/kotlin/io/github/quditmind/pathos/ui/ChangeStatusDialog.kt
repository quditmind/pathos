package io.github.quditmind.pathos.ui

import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.ComboBox
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.ui.ValidationInfo
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.ui.dsl.builder.Align
import com.intellij.ui.dsl.builder.panel
import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.api.FindingStatus
import io.github.quditmind.pathos.core.MAX_STATUS_REASON_LENGTH
import io.github.quditmind.pathos.core.MIN_REASON_LENGTH
import io.github.quditmind.pathos.core.allowedStatusTargets
import io.github.quditmind.pathos.core.statusNeedsReason
import io.github.quditmind.pathos.core.swingPlain
import javax.swing.JComponent

/** Target status and reason; false positive and fixed need a reason of at least 5 characters. */
class ChangeStatusDialog(project: Project, private val finding: Finding) : DialogWrapper(project) {
    private val combo = ComboBox(allowedStatusTargets(finding.status).toTypedArray()).apply {
        renderer = plainTextRenderer<FindingStatus> { s ->
            s.label + if (statusNeedsReason(s)) " (reason required)" else ""
        }
    }
    private val reasonArea = JBTextArea(4, 50).apply { lineWrap = true; wrapStyleWord = true }

    val selectedStatus: FindingStatus get() = combo.item
    val reason: String get() = reasonArea.text.trim()

    init {
        title = "Change Status of “${finding.title.take(60)}”"
        setOKButtonText("Change Status")
        init()
    }

    override fun createCenterPanel(): JComponent = panel {
        row("Current status:") { label(swingPlain(finding.status.replace('_', ' '))) }
        row("New status:") { cell(combo) }
        row { label("Reason (recorded in the status history; required for false positive and fixed):") }
        row { cell(JBScrollPane(reasonArea)).align(Align.FILL) }
    }

    override fun getPreferredFocusedComponent(): JComponent = combo

    override fun doValidate(): ValidationInfo? {
        val r = reasonArea.text.trim()
        if (statusNeedsReason(selectedStatus) && r.length < MIN_REASON_LENGTH) {
            return ValidationInfo("Enter at least $MIN_REASON_LENGTH characters", reasonArea)
        }
        if (reasonArea.text.length > MAX_STATUS_REASON_LENGTH) {
            return ValidationInfo("At most $MAX_STATUS_REASON_LENGTH characters", reasonArea)
        }
        return null
    }
}
