// HTML of the finding details panel. Pure: no IntelliJ Platform dependency.
//
// Every value from PATHOS is untrusted scanner output and is HTML-escaped, so
// it cannot add markup (no images, links or forms) to the Swing HTML view.
// The only link is the PATHOS web URL of the finding, built from the
// configured base URL.

package io.github.quditmind.pathos.core

import io.github.quditmind.pathos.api.Finding
import java.net.URI
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeParseException

fun escapeHtml(value: Any?): String {
    val s = value?.toString() ?: return ""
    val sb = StringBuilder(s.length + 16)
    for (c in s) {
        when (c) {
            '&' -> sb.append("&amp;")
            '<' -> sb.append("&lt;")
            '>' -> sb.append("&gt;")
            '"' -> sb.append("&quot;")
            '\'' -> sb.append("&#39;")
            '`' -> sb.append("&#96;")
            else -> sb.append(c)
        }
    }
    return sb.toString()
}

/** Only absolute http(s) URLs are rendered as links. */
fun safeHttpUrl(url: String?): String? {
    if (url.isNullOrBlank()) return null
    return try {
        val u = URI(url)
        val scheme = u.scheme?.lowercase()
        if ((scheme == "https" || scheme == "http") && !u.host.isNullOrEmpty()) u.toString() else null
    } catch (_: Exception) {
        null
    }
}

val SEVERITY_COLORS = mapOf(
    "critical" to "#b42318",
    "high" to "#c4320a",
    "medium" to "#b54708",
    "low" to "#175cd3",
    "info" to "#475467",
)

private fun row(label: String, value: Any?): String {
    if (value == null || value == "") return ""
    return "<tr><td valign=\"top\"><b>${escapeHtml(label)}</b></td><td>${escapeHtml(value)}</td></tr>"
}

fun formatDate(v: String?): String {
    if (v.isNullOrEmpty()) return ""
    return try {
        OffsetDateTime.parse(v).withOffsetSameInstant(ZoneOffset.UTC).toLocalDate().toString()
    } catch (_: DateTimeParseException) {
        v
    }
}

private fun humanize(v: String?): String = v?.replace('_', ' ') ?: ""

fun remediationText(f: Finding): String {
    if (!f.packageName.isNullOrEmpty() && !f.fixedVersion.isNullOrEmpty()) {
        val from = if (!f.packageVersion.isNullOrEmpty()) " from ${f.packageVersion}" else ""
        return "Upgrade ${f.packageName}$from to ${f.fixedVersion} or later."
    }
    return ""
}

/** Multi-line plain text kept as lines in Swing HTML (which has no pre-wrap). */
private fun textBlock(s: String): String = escapeHtml(s).replace("\r\n", "\n").replace("\n", "<br>")

fun buildDetailsHtml(f: Finding, webUrl: String): String {
    val sev = f.severity.lowercase()
    val color = SEVERITY_COLORS[sev] ?: SEVERITY_COLORS.getValue("info")
    val link = safeHttpUrl(webUrl)
    val path = displayPath(f.filePath)
    val location = if (path.isEmpty()) "" else if (f.startLine != null) "$path:${f.startLine}" else path
    val pkg = if (f.packageName.isNullOrEmpty()) "" else f.packageName + (f.packageVersion?.takeIf { it.isNotEmpty() }?.let { "@$it" } ?: "")
    val fix = remediationText(f)
    val review = if (f.humanReviewKey.isNullOrEmpty()) {
        ""
    } else {
        f.humanReviewKey +
            (f.humanReviewStatus?.takeIf { it.isNotEmpty() }?.let { " (${humanize(it)})" } ?: "") +
            (f.humanDisposition?.takeIf { it.isNotEmpty() }?.let { ": ${humanize(it)}" } ?: "")
    }

    val rows = listOf(
        row("Severity", severityLabel(f.severity)),
        row("Status", humanize(f.lifecycleStatus?.takeIf { it.isNotEmpty() } ?: f.status)),
        row("Risk score", f.riskScore?.let { "${roundHalfUp(it)} / 100" } ?: "not scored"),
        row("CWE", formatCwes(f.cwe).joinToString(", ")),
        row("CVE", f.cve),
        row("CVSS", f.cvss?.let { String.format(java.util.Locale.ROOT, "%.1f", it) } ?: ""),
        row("EPSS percentile", f.epssPercentile?.let { "${roundHalfUp(it * 100)}%" } ?: ""),
        row("Known exploited (KEV)", if (f.kev) "yes" else ""),
        row("Reachability", if (!f.reachability.isNullOrEmpty() && f.reachability != "unknown") humanize(f.reachability) else ""),
        row("Scanner", f.scannerKeys.joinToString(", ")),
        row("Rule", f.ruleId),
        row("Category", f.category),
        row("Location", location),
        row("Package", pkg),
        row("Target", if (!f.scanTargetName.isNullOrEmpty()) "${f.scanTargetKind.orEmpty()} ${f.scanTargetName}".trim() else ""),
        row("Assignee", f.assigneeName),
        row("SLA due", formatDate(f.slaDueAt)),
        row("Human Eye review", review),
        row("Repository", f.repositoryName),
        row("First seen", formatDate(f.firstSeenAt)),
        row("Last seen", formatDate(f.lastSeenAt)),
    ).joinToString("")

    val snippet = if (f.snippet.isNullOrEmpty()) {
        ""
    } else {
        "<h3>Code</h3><pre>${escapeHtml(f.snippet)}</pre>" +
            (f.snippetStartLine?.let { "<p><i>From line ${escapeHtml(it)}</i></p>" } ?: "")
    }
    val description = if (f.description.isNullOrEmpty()) "<i>No description provided by the scanner.</i>" else textBlock(f.description)
    val remediation = if (fix.isEmpty()) "<i>See the description and PATHOS for remediation guidance.</i>" else textBlock(fix)

    return buildString {
        append("<html><body>")
        append("<h2>").append(escapeHtml(f.title.ifEmpty { "Untitled finding" })).append("</h2>")
        append("<p><font color=\"").append(color).append("\"><b>").append(escapeHtml(severityLabel(f.severity))).append("</b></font></p>")
        append("<table cellpadding=\"2\">").append(rows).append("</table>")
        if (link != null) append("<p><a href=\"").append(escapeHtml(link)).append("\">Open in PATHOS</a></p>")
        append("<h3>Description</h3><p>").append(description).append("</p>")
        append("<h3>Remediation</h3><p>").append(remediation).append("</p>")
        append(snippet)
        append("</body></html>")
    }
}

/**
 * Text for a Swing component that renders HTML when the text starts with
 * "<html>" (labels, list renderers, tooltips). Untrusted text is escaped
 * and wrapped, so it is always shown as plain text and loads nothing.
 */
fun swingPlain(s: String?): String {
    val t = s.orEmpty()
    return if (t.startsWith("<")) "<html>" + escapeHtml(t) + "</html>" else t
}
