// Shapes of the PATHOS REST API objects used by the plugin. Only the fields
// the plugin reads are declared; the API returns more.
// See docs/api-reference/findings.md and docs/api-reference/repositories.md.

package io.github.quditmind.pathos.api

data class Repository(
    val id: String,
    val fullName: String,
    val name: String? = null,
    val displayName: String? = null,
    val repositoryKey: String? = null,
    val provider: String? = null,
    val sourceType: String? = null,
    /** Web URL of the repository at its provider, for example https://github.com/org/repo. */
    val url: String? = null,
) {
    companion object {
        fun fromJson(o: Map<String, Any?>): Repository? {
            val id = o.str("id") ?: return null
            return Repository(
                id = id,
                fullName = o.str("full_name") ?: "",
                name = o.str("name"),
                displayName = o.str("display_name"),
                repositoryKey = o.str("repository_key"),
                provider = o.str("provider"),
                sourceType = o.str("source_type"),
                url = o.str("url"),
            )
        }
    }
}

data class Finding(
    val id: String,
    val repositoryId: String = "",
    val title: String = "",
    val severity: String = "",
    val status: String = "",
    val repositoryName: String? = null,
    val repositoryKey: String? = null,
    val category: String? = null,
    val scannerKeys: List<String> = emptyList(),
    val ruleId: String? = null,
    val description: String? = null,
    val cwe: List<String> = emptyList(),
    val cve: String? = null,
    val cvss: Double? = null,
    val packageName: String? = null,
    val packageVersion: String? = null,
    val fixedVersion: String? = null,
    val filePath: String? = null,
    val startLine: Int? = null,
    val lifecycleStatus: String? = null,
    val firstSeenAt: String? = null,
    val lastSeenAt: String? = null,
    val assigneeName: String? = null,
    val slaDueAt: String? = null,
    val humanReviewKey: String? = null,
    val humanReviewStatus: String? = null,
    val humanDisposition: String? = null,
    val riskScore: Double? = null,
    val confidence: String? = null,
    val epssPercentile: Double? = null,
    val kev: Boolean = false,
    val reachability: String? = null,
    val scanTargetKind: String? = null,
    val scanTargetName: String? = null,
    /** Only on GET /api/v1/findings/{id}. */
    val snippet: String? = null,
    val snippetStartLine: Int? = null,
) {
    companion object {
        fun fromJson(o: Map<String, Any?>): Finding? {
            val id = o.str("id") ?: return null
            return Finding(
                id = id,
                repositoryId = o.str("repository_id") ?: "",
                title = o.str("title") ?: "",
                severity = o.str("severity") ?: "",
                status = o.str("status") ?: "",
                repositoryName = o.str("repository_name"),
                repositoryKey = o.str("repository_key"),
                category = o.str("category"),
                scannerKeys = o.strList("scanner_keys"),
                ruleId = o.str("rule_id"),
                description = o.str("description"),
                cwe = o.strList("cwe"),
                cve = o.str("cve"),
                cvss = o.num("cvss"),
                packageName = o.str("package_name"),
                packageVersion = o.str("package_version"),
                fixedVersion = o.str("fixed_version"),
                filePath = o.str("file_path"),
                startLine = o.num("start_line")?.toInt(),
                lifecycleStatus = o.str("lifecycle_status"),
                firstSeenAt = o.str("first_seen_at"),
                lastSeenAt = o.str("last_seen_at"),
                assigneeName = o.str("assignee_name"),
                slaDueAt = o.str("sla_due_at"),
                humanReviewKey = o.str("human_review_key"),
                humanReviewStatus = o.str("human_review_status"),
                humanDisposition = o.str("human_disposition"),
                riskScore = o.num("risk_score"),
                confidence = o.str("confidence"),
                epssPercentile = o.num("epss_percentile"),
                kev = o.bool("kev") ?: false,
                reachability = o.str("reachability"),
                scanTargetKind = o.str("scan_target_kind"),
                scanTargetName = o.str("scan_target_name"),
                snippet = o.str("snippet"),
                snippetStartLine = o.num("snippet_start_line")?.toInt(),
            )
        }
    }
}

/** Stored statuses a finding can be changed to manually (docs: "Change the status"). */
enum class FindingStatus(val apiValue: String, val label: String) {
    OPEN("open", "Open"),
    IN_PROGRESS("in_progress", "In progress"),
    NEEDS_REVIEW("needs_review", "Needs review"),
    FALSE_POSITIVE("false_positive", "False positive"),
    FIXED("fixed", "Fixed"),
    ;

    companion object {
        fun fromApi(value: String): FindingStatus? = entries.firstOrNull { it.apiValue == value }
    }
}
