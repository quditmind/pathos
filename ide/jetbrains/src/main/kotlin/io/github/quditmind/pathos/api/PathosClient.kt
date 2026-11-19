// PATHOS REST API client. Pure: no IntelliJ Platform dependency, so it is
// unit-tested against a local HTTP server. The token is only ever placed in
// the Authorization header and never included in errors or logs. Redirects
// are never followed, so the token cannot be forwarded to another host.

package io.github.quditmind.pathos.api

import java.io.IOException
import java.net.ProxySelector
import java.net.URI
import java.net.URISyntaxException
import java.net.URLDecoder
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpConnectTimeoutException
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.net.http.HttpTimeoutException
import java.nio.charset.StandardCharsets
import java.time.Duration

enum class ApiErrorKind {
    /** 401: token missing, invalid, expired or revoked. */
    UNAUTHORIZED,

    /** 403 token_read_only: api:read token on a write request. */
    READ_ONLY,

    /** 403 token_not_allowed. */
    TOKEN_NOT_ALLOWED,

    /** 403: role does not permit it. */
    FORBIDDEN,

    /** 404 (also outside the caller's scope). */
    NOT_FOUND,
    CONFLICT,

    /** 400, 422. */
    INVALID,
    RATE_LIMITED,

    /** 5xx. */
    SERVER,

    /** 3xx: never followed. */
    REDIRECT,
    TIMEOUT,
    NETWORK,
    BAD_RESPONSE,
    OTHER,
}

class PathosApiException(
    val kind: ApiErrorKind,
    message: String,
    val status: Int? = null,
    val code: String? = null,
    val requestId: String? = null,
) : Exception(message)

class PathosConfigException(message: String) : Exception(message)

private val LOCAL_HOSTS = setOf("localhost", "127.0.0.1", "[::1]", "::1")

/**
 * Validates the configured PATHOS base URL and returns it without trailing
 * slash. https is required; plain http only for localhost/127.0.0.1/[::1].
 * Credentials, query and fragment are refused.
 */
fun validateBaseUrl(raw: String?): String {
    val s = raw?.trim().orEmpty()
    if (s.isEmpty()) throw PathosConfigException("The PATHOS URL is not set (Settings → Tools → PATHOS).")
    val u = try {
        URI(s)
    } catch (_: URISyntaxException) {
        throw PathosConfigException("The PATHOS URL \"$s\" is not a valid URL.")
    }
    val scheme = u.scheme?.lowercase()
    if (scheme == null || u.isOpaque || u.host.isNullOrEmpty()) {
        if (scheme == "https" || scheme == "http" || scheme == null) {
            throw PathosConfigException("The PATHOS URL \"$s\" is not a valid URL.")
        }
        throw PathosConfigException("The PATHOS URL must start with https://.")
    }
    if (scheme != "https" && scheme != "http") throw PathosConfigException("The PATHOS URL must start with https://.")
    val host = u.host.lowercase()
    if (scheme == "http" && host !in LOCAL_HOSTS) {
        throw PathosConfigException(
            "Refusing plain http:// for a remote PATHOS server: the API token would be sent unencrypted. " +
                "Use https:// (http is only allowed for localhost).",
        )
    }
    if (u.rawUserInfo != null) throw PathosConfigException("The PATHOS URL must not contain credentials.")
    if (u.rawQuery != null || u.rawFragment != null) {
        throw PathosConfigException("The PATHOS URL must not contain a query or fragment.")
    }
    val defaultPort = if (scheme == "https") 443 else 80
    val port = if (u.port == -1 || u.port == defaultPort) "" else ":${u.port}"
    val path = (u.rawPath ?: "").trimEnd('/')
    return "$scheme://$host$port$path"
}

/** Web UI link of a finding (the format used in notification e-mails). */
fun findingWebUrl(baseUrl: String, findingId: String): String =
    "$baseUrl/findings?status=all&finding=${encode(findingId)}"

private fun encode(s: String): String = URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20")

/** User-facing explanation of an error, with guidance for auth problems. */
fun describeError(err: Throwable, action: String = "The request"): String = when (err) {
    is PathosConfigException -> err.message.orEmpty()
    is PathosApiException -> when (err.kind) {
        ApiErrorKind.UNAUTHORIZED ->
            "PATHOS rejected the API token (missing, invalid, expired or revoked). Set a new token in Settings → Tools → PATHOS."
        ApiErrorKind.READ_ONLY ->
            "$action needs an API token with the api:write scope; this token only has api:read. Create a token with api:write " +
                "in PATHOS (user menu → API tokens (MCP), \"REST API: read and write\") and set it again."
        ApiErrorKind.TOKEN_NOT_ALLOWED -> "$action cannot be done with an API token; use the PATHOS web UI."
        ApiErrorKind.FORBIDDEN -> "$action was refused: your PATHOS role does not permit this."
        ApiErrorKind.NOT_FOUND -> "$action failed: not found in PATHOS, or outside your access scope."
        ApiErrorKind.CONFLICT -> "$action is not possible in the current state: ${err.message}"
        ApiErrorKind.INVALID -> "$action was rejected: ${err.message}"
        ApiErrorKind.RATE_LIMITED -> "PATHOS rate limit reached; try again in a moment."
        ApiErrorKind.TIMEOUT -> "PATHOS did not answer in time."
        ApiErrorKind.NETWORK -> "Cannot reach PATHOS: ${err.message}"
        ApiErrorKind.REDIRECT ->
            "PATHOS answered with a redirect, which is not followed so the token is not sent elsewhere. " +
                "Check the PATHOS URL (${err.message})."
        else -> "$action failed: ${err.message}"
    }
    else -> "$action failed: ${err.message ?: err.javaClass.simpleName}"
}

data class FindingsPage(
    val items: List<Finding>,
    /** True when the cap stopped the listing before the last page. */
    val truncated: Boolean,
)

data class ReviewRequestResult(val created: List<String>, val existing: List<String>)

/** HTTP transport; the default uses java.net.http with redirects disabled. */
fun interface Transport {
    /** Returns status, headers (lower-case names) and body. */
    @Throws(IOException::class, InterruptedException::class)
    fun send(request: HttpRequest): HttpResponse<String>
}

class JdkTransport(proxySelector: ProxySelector? = null, connectTimeout: Duration = Duration.ofSeconds(15)) : Transport {
    private val client: HttpClient = HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NEVER)
        .connectTimeout(connectTimeout)
        .apply { if (proxySelector != null) proxy(proxySelector) }
        .build()

    override fun send(request: HttpRequest): HttpResponse<String> =
        client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
}

class PathosClient(
    baseUrl: String,
    token: String,
    private val transport: Transport = JdkTransport(),
    private val timeout: Duration = Duration.ofSeconds(30),
) {
    val baseUrl: String = validateBaseUrl(baseUrl)
    private val token: String

    init {
        if (token.isEmpty() || token.any { it.isWhitespace() || it.isISOControl() }) {
            throw PathosConfigException("The PATHOS API token is not set.")
        }
        this.token = token
    }

    override fun toString(): String = "PathosClient($baseUrl)"

    /** Every active repository the caller can see (keyset pagination, 200 per page). */
    fun listRepositories(max: Int = 20_000): List<Repository> {
        val out = ArrayList<Repository>()
        paginate("/api/v1/repositories", linkedMapOf("limit" to "200", "sort" to "name"), max, out, Repository::fromJson)
        return out
    }

    /**
     * Open findings (stored status open, in_progress or needs_review) of one
     * repository, highest severity first, at most [max].
     */
    fun listOpenFindings(repositoryId: String, max: Int = 5000): FindingsPage {
        val items = ArrayList<Finding>()
        val truncated = paginate(
            "/api/v1/findings",
            linkedMapOf("repository_id" to repositoryId, "status" to "open", "sort" to "severity"),
            max,
            items,
            Finding::fromJson,
        )
        return FindingsPage(items, truncated)
    }

    fun getFinding(id: String): Finding {
        val o = request("GET", "/api/v1/findings/${encode(id)}").asObject()
            ?: throw PathosApiException(ApiErrorKind.BAD_RESPONSE, "unexpected response from PATHOS (no finding)")
        return Finding.fromJson(o) ?: throw PathosApiException(ApiErrorKind.BAD_RESPONSE, "unexpected response from PATHOS (no finding id)")
    }

    fun changeStatus(id: String, status: FindingStatus, reason: String? = null) {
        val body = linkedMapOf<String, Any?>("status" to status.apiValue)
        val r = reason?.trim()
        if (!r.isNullOrEmpty()) body["reason"] = r
        request("POST", "/api/v1/findings/${encode(id)}/status", body)
    }

    fun requestHumanReview(findingId: String, reason: String? = null): ReviewRequestResult {
        val body = linkedMapOf<String, Any?>("finding_ids" to listOf(findingId))
        val r = reason?.trim()
        if (!r.isNullOrEmpty()) body["reason"] = r
        val res = request("POST", "/api/v1/human-reviews", body).asObject()
        return ReviewRequestResult(res?.strList("created") ?: emptyList(), res?.strList("existing") ?: emptyList())
    }

    /** Follows next_cursor until the last page or [max] items; returns true when truncated. */
    private fun <T> paginate(
        path: String,
        params: Map<String, String>,
        max: Int,
        out: MutableList<T>,
        convert: (Map<String, Any?>) -> T?,
    ): Boolean {
        var cursor: String? = null
        val seen = HashSet<String>()
        repeat(MAX_PAGES) {
            val q = LinkedHashMap(params)
            if (cursor != null) q["cursor"] = cursor!!
            val query = q.entries.joinToString("&") { "${encode(it.key)}=${encode(it.value)}" }
            val res = request("GET", "$path?$query").asObject()
            val items = res?.get("items") as? List<*>
                ?: throw PathosApiException(ApiErrorKind.BAD_RESPONSE, "unexpected response from PATHOS (no items)")
            for (item in items) {
                if (out.size >= max) return true
                val obj = item.asObject() ?: continue
                convert(obj)?.let { out.add(it) }
            }
            cursor = res["next_cursor"] as? String
            val c = cursor
            if (c.isNullOrEmpty()) return false
            if (out.size >= max) return true
            if (!seen.add(c)) throw PathosApiException(ApiErrorKind.BAD_RESPONSE, "PATHOS returned the same page cursor twice")
        }
        return true
    }

    private fun request(method: String, path: String, body: Any? = null): Any? {
        val builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
            .timeout(timeout)
            .header("Accept", "application/json")
            .header("Authorization", "Bearer $token")
        if (body != null) {
            builder.header("Content-Type", "application/json")
            builder.method(method, HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8))
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody())
        }
        val res: HttpResponse<String> = try {
            transport.send(builder.build())
        } catch (e: HttpConnectTimeoutException) {
            throw PathosApiException(ApiErrorKind.NETWORK, "connection timed out")
        } catch (e: HttpTimeoutException) {
            throw PathosApiException(ApiErrorKind.TIMEOUT, "no answer within ${timeout.seconds} s")
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw PathosApiException(ApiErrorKind.NETWORK, "interrupted")
        } catch (e: IOException) {
            throw PathosApiException(ApiErrorKind.NETWORK, errorText(e))
        }
        val status = res.statusCode()
        if (status in 300..399) {
            throw PathosApiException(ApiErrorKind.REDIRECT, "HTTP $status", status, requestId = res.headers().firstValue("x-request-id").orElse(null))
        }
        if (status !in 200..299) throw toApiError(res)
        if (status == 204) return null
        val text = res.body().orEmpty()
        if (text.isEmpty()) return null
        return try {
            Json.parse(text)
        } catch (_: JsonException) {
            throw PathosApiException(
                ApiErrorKind.BAD_RESPONSE,
                "PATHOS returned invalid JSON (is the PATHOS URL the PATHOS address?)",
                status,
            )
        }
    }

    companion object {
        private const val MAX_PAGES = 1000

        private fun errorText(e: Throwable): String {
            val msg = e.message?.takeIf { it.isNotBlank() } ?: e.javaClass.simpleName
            val cause = e.cause
            return if (cause != null && !cause.message.isNullOrBlank() && cause.message != msg) "$msg (${cause.message})" else msg
        }

        private fun toApiError(res: HttpResponse<String>): PathosApiException {
            var code: String? = null
            var message: String? = null
            var requestId: String? = res.headers().firstValue("x-request-id").orElse(null)
            try {
                val body = Json.parse(res.body().orEmpty()).asObject()
                val error = body?.get("error").asObject()
                code = error?.str("code")
                message = error?.str("message")?.take(500)
                body?.str("request_id")?.let { requestId = it }
            } catch (_: JsonException) {
                // not JSON
            }
            val status = res.statusCode()
            val kind = when (status) {
                401 -> ApiErrorKind.UNAUTHORIZED
                403 -> when (code) {
                    "token_read_only" -> ApiErrorKind.READ_ONLY
                    "token_not_allowed" -> ApiErrorKind.TOKEN_NOT_ALLOWED
                    else -> ApiErrorKind.FORBIDDEN
                }
                404 -> ApiErrorKind.NOT_FOUND
                409 -> ApiErrorKind.CONFLICT
                400, 422 -> ApiErrorKind.INVALID
                429 -> ApiErrorKind.RATE_LIMITED
                else -> if (status >= 500) ApiErrorKind.SERVER else ApiErrorKind.OTHER
            }
            return PathosApiException(kind, message ?: "HTTP $status", status, code, requestId)
        }
    }
}

/** Decodes a percent-encoded path segment, keeping the input when it is malformed. */
internal fun decodeOrSelf(s: String): String = try {
    URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8)
} catch (_: IllegalArgumentException) {
    s
}
