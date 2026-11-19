// Pure helpers (no IntelliJ Platform dependency): severity mapping, git
// remote normalization and repository matching, finding path mapping,
// grouping. Same rules as ide/vscode/src/mapping.ts.

package io.github.quditmind.pathos.core

import io.github.quditmind.pathos.api.Finding
import io.github.quditmind.pathos.api.FindingStatus
import io.github.quditmind.pathos.api.Repository
import io.github.quditmind.pathos.api.decodeOrSelf
import kotlin.math.roundToLong

// ---------------------------------------------------------------------------
// Severity

val SEVERITIES = listOf("critical", "high", "medium", "low", "info")

/** Editor highlighting level of a finding. */
enum class HighlightLevel { ERROR, WARNING, WEAK_WARNING, INFORMATION }

/** Rank for sorting: critical = 0 … info = 4, unknown values last. */
fun severityRank(severity: String?): Int {
    val i = SEVERITIES.indexOf(severity.orEmpty().lowercase())
    return if (i == -1) SEVERITIES.size else i
}

/** critical/high → error, medium → warning, low → weak warning, info (and unknown) → information. */
fun highlightLevel(severity: String?): HighlightLevel = when (severity.orEmpty().lowercase()) {
    "critical", "high" -> HighlightLevel.ERROR
    "medium" -> HighlightLevel.WARNING
    "low" -> HighlightLevel.WEAK_WARNING
    else -> HighlightLevel.INFORMATION
}

fun severityLabel(severity: String?): String {
    val s = severity?.takeIf { it.isNotEmpty() }?.lowercase() ?: "unknown"
    return s.replaceFirstChar { it.uppercaseChar() }
}

private val CWE_RE = Regex("^\\s*(?:cwe-?)?(\\d+)", RegexOption.IGNORE_CASE)

/** CWE identifiers as "CWE-79", de-duplicated. Accepts "79", "CWE-79", "cwe-79: XSS". */
fun formatCwes(cwe: List<String>?): List<String> {
    val out = ArrayList<String>()
    for (raw in cwe.orEmpty()) {
        val m = CWE_RE.find(raw)
        val v = if (m != null) "CWE-${m.groupValues[1]}" else raw.trim()
        if (v.isNotEmpty() && v !in out) out.add(v)
    }
    return out
}

/** Message of the editor annotation (same text as the VS Code diagnostic). */
fun annotationMessage(f: Finding): String {
    val parts = mutableListOf("[${severityLabel(f.severity)}] ${oneLine(f.title).ifEmpty { "Untitled finding" }}")
    val cwes = formatCwes(f.cwe)
    if (cwes.isNotEmpty()) parts.add("(${cwes.joinToString(", ")})")
    f.riskScore?.let { parts.add("risk ${roundHalfUp(it)}") }
    return parts.joinToString(" ")
}

/** Math.round semantics of JavaScript (half up), as the VS Code extension shows it. */
fun roundHalfUp(v: Double): Long = Math.floor(v + 0.5).roundToLong()

fun oneLine(s: String?): String = s.orEmpty().replace(Regex("\\s+"), " ").trim()

// ---------------------------------------------------------------------------
// Status changes

private val OPEN_STATUSES = listOf(FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.NEEDS_REVIEW)

/** Manual status changes allowed from a stored status (docs/api-reference/findings.md). */
fun allowedStatusTargets(from: String): List<FindingStatus> {
    if (OPEN_STATUSES.any { it.apiValue == from }) {
        return OPEN_STATUSES.filter { it.apiValue != from } + listOf(FindingStatus.FALSE_POSITIVE, FindingStatus.FIXED)
    }
    if (from == "false_positive" || from == "fixed") return listOf(FindingStatus.OPEN)
    return emptyList()
}

/** false_positive and fixed need a reason of at least 5 characters. */
fun statusNeedsReason(to: FindingStatus): Boolean = to == FindingStatus.FALSE_POSITIVE || to == FindingStatus.FIXED

const val MIN_REASON_LENGTH = 5
const val MAX_STATUS_REASON_LENGTH = 4000
const val MAX_REVIEW_REASON_LENGTH = 2000

// ---------------------------------------------------------------------------
// Git remotes and repository matching

private val SCHEME_RE = Regex("^([a-z][a-z0-9+.-]*)://(.*)$", RegexOption.IGNORE_CASE)
private val SCP_RE = Regex("^(?:[^@/\\s]+@)?([^:/\\s]+):(?!//)(.+)$")
private val ALLOWED_SCHEMES = setOf("http", "https", "ssh", "git", "git+ssh", "ssh+git")
private val VS_HOST_RE = Regex("^([a-z0-9-]+)\\.visualstudio\\.com$")

/**
 * Normalizes a git remote or repository web URL to "host/path" in lower
 * case, without credentials, port, trailing slash or ".git". Handles
 * https://, http://, ssh://, git://, scp-like "git@host:org/repo.git" and the
 * Azure DevOps URL variants. Returns null for anything unrecognized (local
 * paths, file:// URLs).
 */
fun normalizeRemoteUrl(raw: String?): String? {
    val s = raw?.trim().orEmpty()
    if (s.isEmpty()) return null
    var host: String
    var path: String
    val scheme = SCHEME_RE.find(s)
    if (scheme != null) {
        val proto = scheme.groupValues[1].lowercase()
        if (proto !in ALLOWED_SCHEMES) return null
        val rest = scheme.groupValues[2]
        val slash = rest.indexOf('/')
        var authority = if (slash == -1) rest else rest.substring(0, slash)
        path = if (slash == -1) "" else rest.substring(slash + 1)
        val at = authority.lastIndexOf('@')
        if (at != -1) authority = authority.substring(at + 1)
        host = authority.replace(Regex(":\\d*$"), "")
    } else {
        // scp-like: [user@]host:path (no scheme; a single colon not followed by "//")
        val scp = SCP_RE.find(s) ?: return null
        host = scp.groupValues[1]
        path = scp.groupValues[2]
        // "C:\repo" style Windows paths are not remotes
        if (Regex("^[a-z]$", RegexOption.IGNORE_CASE).matches(host)) return null
    }
    host = host.lowercase().removePrefix("[").removeSuffix("]")
    path = path.split('?', '#')[0]
        .replace('\\', '/')
        .trim('/')
        .replace(Regex("\\.git$", RegexOption.IGNORE_CASE), "")
        .trimEnd('/')
    path = decodeOrSelf(path).lowercase()
    if (host.isEmpty() || path.isEmpty()) return null

    // GitHub over SSH on port 443.
    if (host == "ssh.github.com") host = "github.com"

    // Azure DevOps: https://dev.azure.com/org/project/_git/repo,
    // git@ssh.dev.azure.com:v3/org/project/repo,
    // https://org.visualstudio.com/[DefaultCollection/]project/_git/repo
    if (host == "ssh.dev.azure.com" || host == "vs-ssh.visualstudio.com") {
        val p = path.removePrefix("v3/").split('/')
        if (p.size >= 3) return "dev.azure.com/${p[0]}/${p[1]}/${p.drop(2).joinToString("/")}"
    }
    if (host == "dev.azure.com") {
        val p = path.split('/')
        val git = p.indexOf("_git")
        if (git == 2 && p.size > 3) return "dev.azure.com/${p[0]}/${p[1]}/${p.drop(3).joinToString("/")}"
    }
    VS_HOST_RE.find(host)?.let { vs ->
        val p = path.split('/').filter { it != "defaultcollection" }
        val git = p.indexOf("_git")
        if (git == 1 && p.size > 2) return "dev.azure.com/${vs.groupValues[1]}/${p[0]}/${p.drop(2).joinToString("/")}"
    }
    return "$host/$path"
}

/** The "org/repo" part of a normalized remote (everything after the host). */
private fun remotePath(normalized: String): String {
    val i = normalized.indexOf('/')
    return if (i == -1) "" else normalized.substring(i + 1)
}

enum class MatchedBy { URL, NAME }

data class RepositoryMatch(val repository: Repository, val by: MatchedBy)

/**
 * Repositories matching any of the remotes. Exact URL matches win; when no
 * repository URL matches, repositories whose full_name equals the remote's
 * path (case-insensitive) are returned instead.
 */
fun matchRepositories(remotes: List<String>, repos: List<Repository>): List<RepositoryMatch> {
    val norm = remotes.mapNotNull { normalizeRemoteUrl(it) }.toSet()
    if (norm.isEmpty()) return emptyList()
    val byUrl = repos.filter { r -> normalizeRemoteUrl(r.url)?.let { it in norm } == true }
    if (byUrl.isNotEmpty()) return byUrl.map { RepositoryMatch(it, MatchedBy.URL) }
    val paths = norm.map { remotePath(it) }.toSet()
    return repos
        .filter { it.fullName.isNotEmpty() && it.fullName.lowercase().trim('/') in paths }
        .map { RepositoryMatch(it, MatchedBy.NAME) }
}

private val SECTION_RE = Regex("^\\[\\s*([^\\]\\s\"]+)(?:\\s+\"([^\"]*)\")?\\s*]")
private val URL_KV_RE = Regex("^(url|pushurl)\\s*=\\s*(.*)$", RegexOption.IGNORE_CASE)

/** Remote URLs from the text of a .git/config file. */
fun parseGitConfigRemotes(text: String): List<String> {
    val urls = ArrayList<String>()
    var inRemote = false
    for (line in text.split(Regex("\\r?\\n"))) {
        val t = line.trim()
        if (t.isEmpty() || t.startsWith("#") || t.startsWith(";")) continue
        val section = SECTION_RE.find(t)
        if (section != null) {
            inRemote = section.groupValues[1].lowercase() == "remote"
            continue
        }
        if (!inRemote) continue
        val kv = URL_KV_RE.find(t) ?: continue
        var v = kv.groupValues[2].trim()
        if (v.length >= 2 && v.startsWith("\"") && v.endsWith("\"")) v = v.substring(1, v.length - 1)
        if (v.isNotEmpty() && v !in urls) urls.add(v)
    }
    return urls
}

// ---------------------------------------------------------------------------
// Paths

private val URL_LIKE_RE = Regex("^[a-z][a-z0-9+.-]*://", RegexOption.IGNORE_CASE)
private val DRIVE_RE = Regex("^[a-z]:/", RegexOption.IGNORE_CASE)

/**
 * The finding's file path as safe, relative path segments, or null when it
 * has none or it cannot be mapped into the repository checkout (parent
 * references, drive letters, URLs).
 */
fun findingPathSegments(filePath: String?): List<String>? {
    var p = filePath?.trim()?.replace('\\', '/') ?: return null
    if (p.isEmpty() || URL_LIKE_RE.containsMatchIn(p) || DRIVE_RE.containsMatchIn(p)) return null
    p = p.replace(Regex("^(\\./)+"), "").trimStart('/')
    val segs = p.split('/').filter { it != "" && it != "." }
    if (segs.isEmpty() || segs.any { it == ".." || it.contains('\u0000') }) return null
    return segs
}

/** Normalized display path ("src/app.ts"), or "" without a mappable path. */
fun displayPath(filePath: String?): String = findingPathSegments(filePath)?.joinToString("/") ?: ""

/** Zero-based line for a 1-based start_line (missing or invalid → 0). */
fun zeroBasedLine(startLine: Int?): Int = if (startLine != null && startLine >= 1) startLine - 1 else 0

// ---------------------------------------------------------------------------
// Grouping (tool window tree)

enum class GroupingMode { SEVERITY, FILE }

data class FileGroup(
    /** Display path; "" for findings without a location. */
    val path: String,
    val findings: List<Finding>,
)

data class SeverityGroup(val severity: String, val count: Int, val files: List<FileGroup>)

val FINDING_ORDER: Comparator<Finding> = Comparator { a, b ->
    var c = severityRank(a.severity) - severityRank(b.severity)
    if (c == 0) c = (b.riskScore ?: -1.0).compareTo(a.riskScore ?: -1.0)
    if (c == 0) c = (a.startLine ?: 0) - (b.startLine ?: 0)
    if (c == 0) c = a.title.compareTo(b.title)
    c
}

private val LOCATION_ORDER: Comparator<Finding> = Comparator { a, b ->
    val c = (a.startLine ?: 0) - (b.startLine ?: 0)
    if (c != 0) c else FINDING_ORDER.compare(a, b)
}

/** Findings grouped by file, files sorted by path (findings without a path last), findings by line. */
fun groupByFile(findings: List<Finding>): List<FileGroup> {
    val map = LinkedHashMap<String, MutableList<Finding>>()
    for (f in findings) map.getOrPut(displayPath(f.filePath)) { ArrayList() }.add(f)
    return map.entries
        .sortedWith { (a, _), (b, _) ->
            when {
                a == b -> 0
                a == "" -> 1
                b == "" -> -1
                else -> a.compareTo(b)
            }
        }
        .map { (path, list) -> FileGroup(path, list.sortedWith(LOCATION_ORDER)) }
}

/** Findings grouped by severity (critical first, empty severities omitted), then by file. */
fun groupBySeverity(findings: List<Finding>): List<SeverityGroup> {
    val map = LinkedHashMap<String, MutableList<Finding>>()
    for (f in findings) map.getOrPut(f.severity.ifEmpty { "unknown" }.lowercase()) { ArrayList() }.add(f)
    return map.entries
        .sortedWith(compareBy<Map.Entry<String, MutableList<Finding>>> { severityRank(it.key) }.thenBy { it.key })
        .map { (severity, list) -> SeverityGroup(severity, list.size, groupByFile(list)) }
}
