package io.github.quditmind.pathos.core

import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.api.Json
import io.github.quditmind.pathos.api.JsonException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.nio.file.Files

class DetailsAndGitTest {
    @get:Rule
    val tmp = TemporaryFolder()

    private val evil = "<script>alert(\"x\")</script><img src=http://evil.example/x.png onerror='y'>`&"

    private fun evilFinding() = Finding(
        id = "f1",
        repositoryId = "r1",
        title = evil,
        description = evil,
        severity = "high",
        status = "open",
        ruleId = evil,
        cwe = listOf(evil),
        scannerKeys = listOf(evil),
        filePath = "src/$evil.ts",
        startLine = 3,
        packageName = evil,
        fixedVersion = evil,
        snippet = evil,
        riskScore = 77.0,
    )

    @Test
    fun escapesAllHtmlSignificantCharacters() {
        assertEquals(
            "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&#96;&lt;/a&gt;",
            escapeHtml("<a href=\"x\" onclick='y'>&`</a>"),
        )
        assertEquals("", escapeHtml(null))
        assertEquals("5", escapeHtml(5))
    }

    @Test
    fun allowsOnlyHttpLinks() {
        assertEquals(
            "https://p.example.com/findings?status=all&finding=1",
            safeHttpUrl("https://p.example.com/findings?status=all&finding=1"),
        )
        assertNull(safeHttpUrl("javascript:alert(1)"))
        assertNull(safeHttpUrl("file:///etc/passwd"))
        assertNull(safeHttpUrl("not a url"))
    }

    @Test
    fun detailsContainNoScannerMarkup() {
        val html = buildDetailsHtml(evilFinding(), "https://p.example.com/findings?status=all&finding=f1")
        assertFalse(html.contains("<script"))
        assertFalse(html.contains("<img"))
        assertFalse(html.contains("onerror='"))
        assertTrue(html.contains("&lt;script&gt;"))
        assertTrue(html.contains("<a href=\"https://p.example.com/findings?status=all&amp;finding=f1\">Open in PATHOS</a>"))
        assertTrue(html.contains("77 / 100"))
        assertTrue(html.contains("<h3>Code</h3>"))
        // The only link is the PATHOS one.
        assertEquals(1, Regex("<a ").findAll(html).count())
    }

    @Test
    fun detailsShowRemediationAndDates() {
        val f = Finding(
            id = "f2", title = "Old lodash", severity = "medium", status = "open",
            packageName = "lodash", packageVersion = "4.17.15", fixedVersion = "4.17.21",
            firstSeenAt = "2026-11-18T23:30:00-02:00", kev = true, epssPercentile = 0.934,
        )
        val html = buildDetailsHtml(f, "javascript:alert(1)")
        assertTrue(html.contains("Upgrade lodash from 4.17.15 to 4.17.21 or later."))
        assertTrue(html.contains("2026-11-19"))
        assertTrue(html.contains("93%"))
        assertFalse("unsafe web URL is not linked", html.contains("<a "))
        assertTrue(html.contains("not scored"))
    }

    @Test
    fun swingPlainNeverRendersUntrustedHtml() {
        assertEquals("plain", swingPlain("plain"))
        assertEquals("<html>&lt;html&gt;&lt;img src=x&gt;</html>", swingPlain("<html><img src=x>"))
        assertEquals("", swingPlain(null))
    }

    @Test
    fun readsRemotesOfACheckoutAndOfAWorktree() {
        val main = tmp.newFolder("main").toPath()
        Files.createDirectories(main.resolve(".git/worktrees/wt"))
        Files.writeString(main.resolve(".git/config"), "[remote \"origin\"]\n\turl = git@github.com:example-org/payments-api.git\n")
        assertTrue(GitConfig.isGitRoot(main))
        assertEquals(listOf("git@github.com:example-org/payments-api.git"), GitConfig.remotesOf(main))

        val wt = tmp.newFolder("wt").toPath()
        Files.writeString(wt.resolve(".git"), "gitdir: ${main.resolve(".git/worktrees/wt")}\n")
        Files.writeString(main.resolve(".git/worktrees/wt/commondir"), "../..\n")
        assertTrue(GitConfig.isGitRoot(wt))
        assertEquals(listOf("git@github.com:example-org/payments-api.git"), GitConfig.remotesOf(wt))

        val none = tmp.newFolder("none").toPath()
        assertFalse(GitConfig.isGitRoot(none))
        assertEquals(emptyList<String>(), GitConfig.remotesOf(none))
    }

    @Test
    fun jsonRoundTripAndStrictness() {
        val v = Json.parse("""{"a":[1,-2.5e1,true,false,null,"x\"\\\/\né"],"b":{}}""")
        assertEquals(mapOf("a" to listOf(1L, -25.0, true, false, null, "x\"\\/\né"), "b" to emptyMap<String, Any?>()), v)
        assertEquals("""{"s":"a\"b\n","l":[1,"x"]}""", Json.write(mapOf("s" to "a\"b\n", "l" to listOf(1, "x"))))
        for (bad in listOf("", "{", "[1,]", "{\"a\":1,}", "01", "1.", "\"\u0001\"", "nul", "{} x", "[" .repeat(100) + "]".repeat(100))) {
            try {
                Json.parse(bad)
                fail("accepted: $bad")
            } catch (_: JsonException) {
                // expected
            }
        }
    }
}
