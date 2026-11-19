// "PATHOS" tool window: severity → file → finding, or file → finding.

package io.github.quditmind.pathos.ui

import com.intellij.icons.AllIcons
import com.intellij.openapi.actionSystem.ActionGroup
import com.intellij.openapi.actionSystem.ActionManager
import com.intellij.openapi.actionSystem.ActionPlaces
import com.intellij.openapi.actionSystem.DataSink
import com.intellij.openapi.actionSystem.UiDataProvider
import com.intellij.openapi.fileTypes.FileTypeManager
import com.intellij.openapi.options.ShowSettingsUtil
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.SimpleToolWindowPanel
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.ColoredTreeCellRenderer
import com.intellij.ui.PopupHandler
import com.intellij.ui.ScrollPaneFactory
import com.intellij.ui.SimpleTextAttributes
import com.intellij.ui.components.JBLabel
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.treeStructure.Tree
import com.intellij.util.ui.JBUI
import com.intellij.util.ui.tree.TreeUtil
import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.core.GroupingMode
import io.github.quditmind.pathos.core.displayPath
import io.github.quditmind.pathos.core.escapeHtml
import io.github.quditmind.pathos.core.swingPlain
import io.github.quditmind.pathos.core.groupByFile
import io.github.quditmind.pathos.core.groupBySeverity
import io.github.quditmind.pathos.core.roundHalfUp
import io.github.quditmind.pathos.core.severityLabel
import io.github.quditmind.pathos.service.PathosFindingsListener
import io.github.quditmind.pathos.service.PathosProjectService
import io.github.quditmind.pathos.service.Snapshot
import io.github.quditmind.pathos.service.ViewState
import io.github.quditmind.pathos.settings.PathosConfigurable
import java.awt.BorderLayout
import java.awt.event.KeyAdapter
import java.awt.event.KeyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.Icon
import javax.swing.JPanel
import javax.swing.JTree
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel

class PathosToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = FindingsPanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "Findings", false)
        content.setDisposer(panel)
        toolWindow.contentManager.addContent(content)
        panel.render(PathosProjectService.getInstance(project).snapshot)
    }
}

/** Tree node payloads. */
sealed interface PathosNode {
    data class Severity(val severity: String, val count: Int) : PathosNode
    data class File(val path: String, val count: Int, val sample: Finding?) : PathosNode
    data class Item(val finding: Finding) : PathosNode
}

fun severityIcon(severity: String): Icon = when (severity.lowercase()) {
    "critical", "high" -> AllIcons.General.Error
    "medium" -> AllIcons.General.Warning
    "low" -> AllIcons.General.Information
    else -> AllIcons.General.Note
}

class FindingsPanel(private val project: Project) : SimpleToolWindowPanel(true, true), UiDataProvider, com.intellij.openapi.Disposable {
    private val root = DefaultMutableTreeNode()
    private val model = DefaultTreeModel(root)
    private val tree = Tree(model)
    private val header = JBLabel().apply { border = JBUI.Borders.empty(4, 8) }
    private var lastMode: GroupingMode? = null

    init {
        tree.isRootVisible = false
        tree.showsRootHandles = true
        tree.cellRenderer = Renderer()
        val group = ActionManager.getInstance().getAction("Pathos.ToolWindow.Toolbar") as ActionGroup
        val toolbar = ActionManager.getInstance().createActionToolbar(ActionPlaces.TOOLWINDOW_TOOLBAR_BAR, group, true)
        toolbar.targetComponent = this
        setToolbar(toolbar.component)
        val body = JPanel(BorderLayout())
        body.add(header, BorderLayout.NORTH)
        body.add(ScrollPaneFactory.createScrollPane(tree, true), BorderLayout.CENTER)
        setContent(body)
        PopupHandler.installPopupMenu(tree, "Pathos.FindingPopup", "PathosFindingsTree")
        tree.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && e.button == MouseEvent.BUTTON1) selected()?.let { FindingUi.openFinding(project, it) }
            }
        })
        tree.addKeyListener(object : KeyAdapter() {
            override fun keyPressed(e: KeyEvent) {
                if (e.keyCode == KeyEvent.VK_ENTER) selected()?.let { FindingUi.openFinding(project, it); e.consume() }
            }
        })
        project.messageBus.connect(this).subscribe(PathosFindingsListener.TOPIC, PathosFindingsListener { render(it) })
    }

    override fun dispose() = Unit

    private fun selected(): Finding? =
        ((tree.selectionPath?.lastPathComponent as? DefaultMutableTreeNode)?.userObject as? PathosNode.Item)?.finding

    override fun uiDataSnapshot(sink: DataSink) {
        sink[FindingUi.FINDING] = selected()
    }

    fun render(s: Snapshot) {
        val mode = PathosProjectService.getInstance(project).grouping
        val selectedId = selected()?.id
        root.removeAllChildren()
        when (mode) {
            GroupingMode.SEVERITY -> for (g in groupBySeverity(s.findings)) {
                val sev = DefaultMutableTreeNode(PathosNode.Severity(g.severity, g.count))
                for (fg in g.files) sev.add(fileNode(fg.path, fg.findings))
                root.add(sev)
            }
            GroupingMode.FILE -> for (fg in groupByFile(s.findings)) root.add(fileNode(fg.path, fg.findings))
        }
        model.reload()
        TreeUtil.expandAll(tree)
        if (selectedId != null) {
            TreeUtil.findNode(root) { (it.userObject as? PathosNode.Item)?.finding?.id == selectedId }
                ?.let { TreeUtil.selectNode(tree, it) }
        }
        lastMode = mode
        updateTexts(s)
    }

    private fun fileNode(path: String, findings: List<Finding>): DefaultMutableTreeNode {
        val n = DefaultMutableTreeNode(PathosNode.File(path, findings.size, findings.firstOrNull()))
        for (f in findings) n.add(DefaultMutableTreeNode(PathosNode.Item(f)))
        return n
    }

    private fun updateTexts(s: Snapshot) {
        val lines = listOfNotNull(
            s.repository?.let { r ->
                if (s.state == ViewState.LOADED) "$r: ${s.findings.size} open finding(s)" else r
            },
            s.note,
            s.error,
        )
        header.text = if (lines.isEmpty()) "" else "<html>" + escapeHtml(lines.joinToString("  ·  ")) + "</html>"
        header.isVisible = lines.isNotEmpty()
        header.foreground = if (s.error != null) JBUI.CurrentTheme.Label.errorForeground() else JBUI.CurrentTheme.Label.foreground()
        header.toolTipText = s.error?.let { swingPlain(it) }

        val empty = tree.emptyText
        empty.clear()
        when (s.state) {
            ViewState.NOT_CONFIGURED -> {
                empty.appendLine("Connect to your PATHOS server to see the open findings of this repository.")
                empty.appendLine("Open PATHOS settings", SimpleTextAttributes.LINK_PLAIN_ATTRIBUTES) {
                    ShowSettingsUtil.getInstance().showSettingsDialog(project, PathosConfigurable::class.java)
                }
            }
            ViewState.NO_REPOSITORY -> {
                empty.appendLine("No PATHOS repository is selected for this project.")
                empty.appendLine("Select repository", SimpleTextAttributes.LINK_PLAIN_ATTRIBUTES) { RepositoryChooser.choose(project) }
            }
            ViewState.LOADED -> empty.appendLine("No open findings in ${s.repository ?: "this repository"}.")
            ViewState.ERROR -> {
                empty.appendLine(s.error ?: "Loading findings failed.", SimpleTextAttributes.ERROR_ATTRIBUTES, null)
                empty.appendLine("Retry", SimpleTextAttributes.LINK_PLAIN_ATTRIBUTES) {
                    PathosProjectService.getInstance(project).refresh(true)
                }
            }
        }
    }

    private inner class Renderer : ColoredTreeCellRenderer() {
        override fun customizeCellRenderer(
            tree: JTree,
            value: Any?,
            selected: Boolean,
            expanded: Boolean,
            leaf: Boolean,
            row: Int,
            hasFocus: Boolean,
        ) {
            when (val n = (value as? DefaultMutableTreeNode)?.userObject) {
                is PathosNode.Severity -> {
                    icon = severityIcon(n.severity)
                    append(severityLabel(n.severity))
                    append("  ${n.count}", SimpleTextAttributes.GRAYED_ATTRIBUTES)
                }
                is PathosNode.File -> {
                    if (n.path.isEmpty()) {
                        icon = AllIcons.Nodes.Package
                        append("(no file location)", SimpleTextAttributes.GRAYED_ATTRIBUTES)
                    } else {
                        icon = FileTypeManager.getInstance().getFileTypeByFileName(n.path.substringAfterLast('/')).icon
                            ?: AllIcons.FileTypes.Any_type
                        append(n.path)
                    }
                    append("  ${n.count}", SimpleTextAttributes.GRAYED_ATTRIBUTES)
                }
                is PathosNode.Item -> {
                    val f = n.finding
                    icon = severityIcon(f.severity)
                    append(f.title.ifEmpty { "Untitled finding" })
                    val bits = ArrayList<String>()
                    f.startLine?.let { bits.add("line $it") }
                    if (lastMode == GroupingMode.FILE) bits.add(severityLabel(f.severity))
                    f.riskScore?.let { bits.add("risk ${roundHalfUp(it)}") }
                    if (bits.isNotEmpty()) append("  " + bits.joinToString(" · "), SimpleTextAttributes.GRAYED_ATTRIBUTES)
                    // Plain text tooltip: scanner text is untrusted and is not rendered as HTML.
                    val path = displayPath(f.filePath)
                    toolTipText = "<html>" + escapeHtml(
                        listOfNotNull(
                            f.title,
                            severityLabel(f.severity) + (f.ruleId?.let { " · $it" } ?: ""),
                            path.takeIf { it.isNotEmpty() }?.let { it + (f.startLine?.let { l -> ":$l" } ?: "") },
                        ).joinToString("\n"),
                    ).replace("\n", "<br>") + "</html>"
                }
                else -> Unit
            }
        }
    }
}
