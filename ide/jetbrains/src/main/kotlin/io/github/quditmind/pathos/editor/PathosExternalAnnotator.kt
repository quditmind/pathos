// Editor annotations for the loaded PATHOS findings of a file, on the
// reported line. critical/high → error, medium → warning, low → weak warning,
// info → information (gray dotted underline). The findings are already
// in memory: the annotator makes no network calls.

package io.github.quditmind.pathos.editor

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.codeInsight.intention.preview.IntentionPreviewInfo
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.editor.Document
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.editor.markup.EffectType
import com.intellij.openapi.editor.markup.TextAttributes
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiFile
import com.intellij.ui.JBColor
import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.core.HighlightLevel
import io.github.quditmind.pathos.core.annotationMessage
import io.github.quditmind.pathos.core.highlightLevel
import io.github.quditmind.pathos.core.zeroBasedLine
import io.github.quditmind.pathos.service.PathosProjectService
import io.github.quditmind.pathos.ui.FindingUi
import java.awt.Font

class PathosExternalAnnotator : ExternalAnnotator<List<Finding>, List<Finding>>(), DumbAware {
    override fun collectInformation(file: PsiFile): List<Finding>? = collect(file)

    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): List<Finding>? = collect(file)

    private fun collect(file: PsiFile): List<Finding>? {
        val vf = file.viewProvider.virtualFile
        // Only the main PSI file of a view provider, so multi-language files are annotated once.
        if (file != file.viewProvider.allFiles.firstOrNull()) return null
        val findings = PathosProjectService.getInstance(file.project).findingsFor(vf)
        return findings.ifEmpty { null }
    }

    override fun doAnnotate(collectedInfo: List<Finding>?): List<Finding>? = collectedInfo

    override fun apply(file: PsiFile, annotationResult: List<Finding>?, holder: AnnotationHolder) {
        val findings = annotationResult ?: return
        val document = PsiDocumentManager.getInstance(file.project).getDocument(file) ?: return
        for (f in findings) {
            val range = lineRange(document, zeroBasedLine(f.startLine))
            val severity = severityOf(f.severity)
            var builder = holder.newAnnotation(severity, annotationMessage(f))
                .range(range)
                .withFix(ShowDetailsIntention(f))
                .withFix(OpenInPathosIntention(f))
            // Information has no default look: a gray dotted underline, like a VS Code hint.
            if (severity == HighlightSeverity.INFORMATION) builder = builder.enforcedTextAttributes(INFO_ATTRIBUTES)
            if (range.isEmpty) builder = builder.afterEndOfLine()
            builder.create()
        }
    }

    companion object {
        private val INFO_ATTRIBUTES = TextAttributes(null, null, JBColor.GRAY, EffectType.BOLD_DOTTED_LINE, Font.PLAIN)

        fun severityOf(severity: String): HighlightSeverity = when (highlightLevel(severity)) {
            HighlightLevel.ERROR -> HighlightSeverity.ERROR
            HighlightLevel.WARNING -> HighlightSeverity.WARNING
            HighlightLevel.WEAK_WARNING -> HighlightSeverity.WEAK_WARNING
            HighlightLevel.INFORMATION -> HighlightSeverity.INFORMATION
        }

        /** The text of a line without its leading and trailing whitespace; the last line when beyond the end. */
        fun lineRange(document: Document, line: Int): TextRange {
            if (document.lineCount == 0) return TextRange(0, 0)
            val l = line.coerceIn(0, document.lineCount - 1)
            var start = document.getLineStartOffset(l)
            var end = document.getLineEndOffset(l)
            val text = document.charsSequence
            while (start < end && text[start].isWhitespace()) start++
            while (end > start && text[end - 1].isWhitespace()) end--
            return TextRange(start, end)
        }
    }
}

private fun shortTitle(f: Finding): String = f.title.ifEmpty { "finding" }.take(60)

abstract class FindingIntention(protected val finding: Finding) : IntentionAction {
    override fun getFamilyName(): String = "PATHOS"

    override fun isAvailable(project: Project, editor: Editor?, file: PsiFile?): Boolean = true

    override fun startInWriteAction(): Boolean = false

    override fun generatePreview(project: Project, editor: Editor, file: PsiFile): IntentionPreviewInfo = IntentionPreviewInfo.EMPTY
}

class ShowDetailsIntention(finding: Finding) : FindingIntention(finding) {
    override fun getText(): String = "PATHOS: Show details of “${shortTitle(finding)}”"

    override fun invoke(project: Project, editor: Editor?, file: PsiFile?) = FindingUi.showDetails(project, finding)
}

class OpenInPathosIntention(finding: Finding) : FindingIntention(finding) {
    override fun getText(): String = "PATHOS: Open “${shortTitle(finding)}” in PATHOS"

    override fun invoke(project: Project, editor: Editor?, file: PsiFile?) = FindingUi.openInPathos(project, finding)
}
