package io.github.quditmind.pathos.core

import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.api.FindingStatus
import io.github.quditmind.pathos.api.Repository
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Same cases as ide/vscode/test/mapping.test.ts: both IDEs must match repositories and map findings alike. */
class MappingTest {
    private fun finding(id: String, severity: String = "medium", filePath: String? = null, startLine: Int? = null) =
        Finding(id = id, repositoryId = "r", title = id, severity = severity, status = "open", filePath = filePath, startLine = startLine)

    @Test
    fun normalizesEquivalentRemotes() {
        val want = "github.com/example-org/payments-api"
        for (url in listOf(
            "https://github.com/example-org/payments-api",
            "https://github.com/example-org/payments-api.git",
            "https://github.com/Example-Org/Payments-API/",
            "https://user:secret@github.com/example-org/payments-api.git",
            "https://GitHub.com:443/example-org/payments-api",
            "http://github.com/example-org/payments-api",
            "ssh://git@github.com/example-org/payments-api.git",
            "ssh://git@ssh.github.com:443/example-org/payments-api.git",
            "git+ssh://git@github.com/example-org/payments-api",
            "git://github.com/example-org/payments-api.git",
            "git@github.com:example-org/payments-api.git",
            "git@github.com:/example-org/payments-api.git",
            "github.com:example-org/payments-api",
        )) {
            assertEquals(url, want, normalizeRemoteUrl(url))
        }
    }

    @Test
    fun handlesSelfHostedGitLabWithSubgroupsAndPorts() {
        assertEquals("gitlab.example.com/group/sub/repo", normalizeRemoteUrl("ssh://git@gitlab.example.com:2222/group/sub/repo.git"))
        assertEquals("gitlab.example.com/group/sub/repo", normalizeRemoteUrl("https://gitlab.example.com/group/sub/repo"))
    }

    @Test
    fun unifiesAzureDevOpsVariants() {
        val want = "dev.azure.com/org/project/repo"
        assertEquals(want, normalizeRemoteUrl("https://dev.azure.com/org/project/_git/repo"))
        assertEquals(want, normalizeRemoteUrl("https://org@dev.azure.com/org/project/_git/repo"))
        assertEquals(want, normalizeRemoteUrl("git@ssh.dev.azure.com:v3/org/project/repo"))
        assertEquals(want, normalizeRemoteUrl("https://org.visualstudio.com/project/_git/repo"))
        assertEquals(want, normalizeRemoteUrl("https://org.visualstudio.com/DefaultCollection/project/_git/repo"))
    }

    @Test
    fun rejectsLocalPathsAndUnknownSchemes() {
        for (bad in listOf("", "   ", "/srv/git/repo.git", "../repo", "file:///srv/git/repo.git", "C:\\repos\\x", "C:/repos/x", "https://github.com")) {
            assertNull(bad, normalizeRemoteUrl(bad))
        }
        assertNull(normalizeRemoteUrl(null))
    }

    private val repos = listOf(
        Repository(id = "1", fullName = "example-org/payments-api", url = "https://github.com/example-org/payments-api"),
        Repository(id = "2", fullName = "example-org/web", url = "https://github.com/example-org/web"),
        Repository(id = "3", fullName = "example-org/payments-api", url = "https://gitlab.example.com/example-org/payments-api"),
        Repository(id = "4", fullName = "team/uploaded", url = null, sourceType = "upload"),
    )

    @Test
    fun matchesByNormalizedUrl() {
        val m = matchRepositories(listOf("git@github.com:Example-Org/payments-api.git"), repos)
        assertEquals(listOf("1" to MatchedBy.URL), m.map { it.repository.id to it.by })
    }

    @Test
    fun fallsBackToTheFullNameWhenNoUrlMatches() {
        val m = matchRepositories(listOf("git@mirror.internal:team/uploaded.git"), repos)
        assertEquals(listOf("4" to MatchedBy.NAME), m.map { it.repository.id to it.by })
    }

    @Test
    fun returnsSeveralCandidatesForAnAmbiguousName() {
        val m = matchRepositories(listOf("https://elsewhere.example.com/example-org/payments-api"), repos)
        assertEquals(listOf("1", "3"), m.map { it.repository.id }.sorted())
    }

    @Test
    fun returnsNothingWithoutRemotesOrMatches() {
        assertEquals(emptyList<RepositoryMatch>(), matchRepositories(emptyList(), repos))
        assertEquals(emptyList<RepositoryMatch>(), matchRepositories(listOf("/local/path"), repos))
        assertEquals(emptyList<RepositoryMatch>(), matchRepositories(listOf("https://github.com/other/thing"), repos))
    }

    @Test
    fun readsUrlAndPushurlOfEveryRemote() {
        val cfg = """
            [core]
            	repositoryformatversion = 0
            	url = not-a-remote
            [remote "origin"]
            	url = git@github.com:example-org/payments-api.git
            	fetch = +refs/heads/*:refs/remotes/origin/*
            [remote "upstream"]
            	url = "https://github.com/upstream/payments-api"
            	pushurl = ssh://git@github.com/upstream/payments-api.git
            # comment
            [branch "main"]
            	remote = origin
        """.trimIndent()
        assertEquals(
            listOf(
                "git@github.com:example-org/payments-api.git",
                "https://github.com/upstream/payments-api",
                "ssh://git@github.com/upstream/payments-api.git",
            ),
            parseGitConfigRemotes(cfg),
        )
    }

    @Test
    fun mapsSeveritiesToHighlightLevels() {
        assertEquals(HighlightLevel.ERROR, highlightLevel("critical"))
        assertEquals(HighlightLevel.ERROR, highlightLevel("HIGH"))
        assertEquals(HighlightLevel.WARNING, highlightLevel("medium"))
        assertEquals(HighlightLevel.WEAK_WARNING, highlightLevel("low"))
        assertEquals(HighlightLevel.INFORMATION, highlightLevel("info"))
        assertEquals(HighlightLevel.INFORMATION, highlightLevel("weird"))
    }

    @Test
    fun ranksCriticalFirstAndUnknownLast() {
        assertEquals(
            listOf("critical", "high", "medium", "low", "info", "x"),
            listOf("info", "x", "critical", "low", "high", "medium").sortedBy { severityRank(it) },
        )
    }

    @Test
    fun formatsCwesAndMessages() {
        assertEquals(listOf("CWE-79", "CWE-89"), formatCwes(listOf("79", "CWE-79", "cwe-89: SQL injection")))
        assertEquals(emptyList<String>(), formatCwes(null))
        val f = Finding(id = "a", title = "SQL\ninjection", severity = "high", cwe = listOf("89"), riskScore = 81.6)
        assertEquals("[High] SQL injection (CWE-89) risk 82", annotationMessage(f))
        assertEquals("[Unknown] Untitled finding", annotationMessage(Finding(id = "b")))
    }

    @Test
    fun mapsFilePathsToSafeRelativeSegments() {
        assertEquals(listOf("src", "app.ts"), findingPathSegments("src/app.ts"))
        assertEquals(listOf("src", "app.ts"), findingPathSegments("./src//app.ts"))
        assertEquals(listOf("src", "app.ts"), findingPathSegments("/src/app.ts"))
        assertEquals(listOf("src", "win", "app.ts"), findingPathSegments("src\\win\\app.ts"))
        for (bad in listOf(null, "", "  ", "../etc/passwd", "src/../../x", "C:/x/y", "https://x/y", ".")) {
            assertNull(bad.toString(), findingPathSegments(bad))
        }
    }

    @Test
    fun convertsLines() {
        assertEquals(0, zeroBasedLine(1))
        assertEquals(41, zeroBasedLine(42))
        assertEquals(0, zeroBasedLine(null))
        assertEquals(0, zeroBasedLine(0))
        assertEquals(0, zeroBasedLine(-5))
    }

    @Test
    fun followsTheDocumentedStatusTransitions() {
        val s = FindingStatus.entries.associateBy { it.apiValue }
        assertEquals(listOf("in_progress", "needs_review", "false_positive", "fixed").map { s[it] }, allowedStatusTargets("open"))
        assertEquals(listOf("open", "in_progress", "false_positive", "fixed").map { s[it] }, allowedStatusTargets("needs_review"))
        assertEquals(listOf(FindingStatus.OPEN), allowedStatusTargets("fixed"))
        assertEquals(emptyList<FindingStatus>(), allowedStatusTargets("accepted_risk"))
        assertEquals(true, statusNeedsReason(FindingStatus.FALSE_POSITIVE))
        assertEquals(false, statusNeedsReason(FindingStatus.IN_PROGRESS))
    }

    private val fs = listOf(
        finding("1", "low", "b.ts", 5),
        finding("2", "critical", "a.ts", 9),
        finding("3", "critical", "./a.ts", 2),
        finding("4", "high"),
        finding("5", "low", "a.ts", 1),
    )

    @Test
    fun groupsBySeverityThenFile() {
        val g = groupBySeverity(fs)
        assertEquals(listOf("critical" to 2, "high" to 1, "low" to 2), g.map { it.severity to it.count })
        assertEquals(listOf(FileGroup("a.ts", listOf(fs[2], fs[1]))), g[0].files)
        assertEquals("", g[1].files[0].path)
        assertEquals(listOf("a.ts", "b.ts"), g[2].files.map { it.path })
    }

    @Test
    fun groupsByFileWithFindingsSortedByLineAndFilesWithoutPathLast() {
        val g = groupByFile(fs)
        assertEquals(listOf("a.ts", "b.ts", ""), g.map { it.path })
        assertEquals(listOf("5", "3", "2"), g[0].findings.map { it.id })
    }
}
