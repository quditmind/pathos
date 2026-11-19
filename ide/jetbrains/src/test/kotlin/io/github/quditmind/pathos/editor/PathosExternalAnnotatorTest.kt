package io.github.quditmind.pathos.editor

import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.service.PathosProjectService

/**
 * The annotator in a headless IntelliJ Platform test: findings loaded for a
 * file become annotations on their lines with the mapped severity and the
 * PATHOS quick fixes; other files get none.
 */
class PathosExternalAnnotatorTest : BasePlatformTestCase() {
    private fun load(vararg findings: Finding) {
        val root = myFixture.tempDirFixture.getFile("")!!
        PathosProjectService.getInstance(project).setFindingsForTests(findings.toList(), root)
    }

    private fun f(id: String, severity: String, line: Int?, path: String = "src/app.txt", title: String = "Finding $id") =
        Finding(id = id, repositoryId = "r", title = title, severity = severity, status = "open", filePath = path, startLine = line)

    fun testFindingsBecomeAnnotationsWithMappedSeverity() {
        myFixture.addFileToProject("src/app.txt", "line one\n    line two\nline three\n\nline five\nline six\n")
        load(
            f("1", "critical", 1, title = "SQL\ninjection"),
            f("2", "high", 2),
            f("3", "medium", 3),
            f("4", "low", 5),
            f("5", "info", 6),
            f("6", "high", 2, path = "src/other.txt"),
            f("7", "high", 99),
            f("8", "high", 2),
            f("9", "info", 3),
        )
        myFixture.configureFromTempProjectFile("src/app.txt")
        val infos = myFixture.doHighlighting().filter { it.description?.startsWith("[") == true }
        val bySeverity = infos.groupBy({ it.severity }, { it.description })

        assertEquals(
            listOf("[Critical] SQL injection", "[High] Finding 2", "[High] Finding 7", "[High] Finding 8"),
            bySeverity[HighlightSeverity.ERROR]?.sorted(),
        )
        assertEquals(listOf("[Medium] Finding 3"), bySeverity[HighlightSeverity.WARNING])
        assertEquals(listOf("[Low] Finding 4"), bySeverity[HighlightSeverity.WEAK_WARNING])
        assertEquals(listOf("[Info] Finding 5", "[Info] Finding 9"), bySeverity[HighlightSeverity.INFORMATION]?.sorted())
        assertFalse("finding of another file", infos.any { it.description == "[High] Finding 6" })

        val text = myFixture.editor.document.text
        val line2 = infos.single { it.description == "[High] Finding 2" }
        assertEquals("line two", text.substring(line2.startOffset, line2.endOffset))
        val sameLine = infos.filter { it.startOffset == line2.startOffset }.map { it.description }.sorted()
        assertEquals("two findings on one line are both shown", listOf("[High] Finding 2", "[High] Finding 8"), sameLine)
        val beyondEnd = infos.single { it.description == "[High] Finding 7" }
        assertEquals("a line beyond the end is shown on the last line", text.length, beyondEnd.endOffset)
    }

    fun testQuickFixesAreOffered() {
        myFixture.addFileToProject("src/app.txt", "first\nsecond\n")
        load(f("1", "high", 2, title = "Hard-coded password"))
        myFixture.configureFromTempProjectFile("src/app.txt")
        myFixture.editor.caretModel.moveToOffset(myFixture.editor.document.getLineStartOffset(1) + 2)
        val texts = myFixture.availableIntentions.map { it.text }
        assertContainsElements(
            texts,
            "PATHOS: Show details of “Hard-coded password”",
            "PATHOS: Open “Hard-coded password” in PATHOS",
        )
    }

    fun testWorksInSourceFilesOfOtherLanguages() {
        myFixture.addFileToProject("conf/app.xml", "<config>\n  <password>x</password>\n</config>\n")
        load(f("1", "medium", 2, path = "conf/app.xml", title = "Weak secret"))
        myFixture.configureFromTempProjectFile("conf/app.xml")
        assertEquals("XML", myFixture.file.language.id)
        val infos = myFixture.doHighlighting().filter { it.description == "[Medium] Weak secret" }
        assertEquals(1, infos.size)
        assertEquals(HighlightSeverity.WARNING, infos[0].severity)
    }

    fun testNoFindingsNoAnnotations() {
        myFixture.addFileToProject("src/app.txt", "x\n")
        load()
        myFixture.configureFromTempProjectFile("src/app.txt")
        assertEmpty(myFixture.doHighlighting().filter { it.description?.startsWith("[") == true })
    }
}
