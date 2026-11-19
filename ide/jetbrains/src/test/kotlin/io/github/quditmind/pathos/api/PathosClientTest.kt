package io.github.quditmind.pathos.api

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.Collections

/** The API client against a local JDK HttpServer (a real HTTP exchange, no mocks of the transport). */
class PathosClientTest {
    private data class Recorded(val method: String, val uri: URI, val headers: Map<String, List<String>>, val body: String) {
        fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, true) }?.value?.firstOrNull()
        fun query(name: String): String? = uri.rawQuery?.split('&')?.map { it.split('=', limit = 2) }
            ?.firstOrNull { it[0] == name }?.getOrNull(1)?.let { URLDecoder.decode(it, StandardCharsets.UTF_8) }
    }

    private data class Reply(val status: Int, val body: String? = null, val headers: Map<String, String> = emptyMap(), val delayMs: Long = 0)

    private class MockServer(handler: (Recorded) -> Reply) : AutoCloseable {
        val requests: MutableList<Recorded> = Collections.synchronizedList(ArrayList())
        private val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val base: String get() = "http://127.0.0.1:${server.address.port}"

        init {
            server.createContext("/") { ex: HttpExchange ->
                val rec = Recorded(
                    ex.requestMethod,
                    ex.requestURI,
                    ex.requestHeaders.toMap(),
                    String(ex.requestBody.readAllBytes(), StandardCharsets.UTF_8),
                )
                requests.add(rec)
                val r = handler(rec)
                if (r.delayMs > 0) {
                    try {
                        Thread.sleep(r.delayMs)
                    } catch (_: InterruptedException) {
                        // shutting down
                    }
                }
                for ((k, v) in r.headers) ex.responseHeaders.add(k, v)
                if (r.body != null) ex.responseHeaders.add("Content-Type", "application/json")
                val bytes = r.body?.toByteArray(StandardCharsets.UTF_8)
                ex.sendResponseHeaders(r.status, if (bytes == null) -1 else bytes.size.toLong())
                bytes?.let { ex.responseBody.write(it) }
                ex.close()
            }
            server.start()
        }

        override fun close() = server.stop(0)
    }

    private val servers = ArrayList<MockServer>()

    private fun server(handler: (Recorded) -> Reply): MockServer = MockServer(handler).also { servers.add(it) }

    private fun client(s: MockServer, timeout: Duration = Duration.ofSeconds(10)) =
        PathosClient(s.base + "/", TOKEN, JdkTransport(), timeout)

    @Before
    fun setUp() = servers.clear()

    @After
    fun tearDown() = servers.forEach { it.close() }

    private fun expectApiError(block: () -> Unit): PathosApiException {
        try {
            block()
        } catch (e: PathosApiException) {
            return e
        }
        fail("expected PathosApiException")
        throw IllegalStateException()
    }

    // -------------------------------------------------------------------------
    // Base URL

    @Test
    fun validateBaseUrlAcceptsHttpsAndStripsTrailingSlash() {
        assertEquals("https://pathos.example.com", validateBaseUrl("https://pathos.example.com/"))
        assertEquals("https://example.com/pathos", validateBaseUrl(" https://example.com/pathos/ "))
        assertEquals("https://pathos.example.com", validateBaseUrl("https://Pathos.Example.com:443"))
        assertEquals("https://pathos.example.com:8443", validateBaseUrl("https://pathos.example.com:8443"))
    }

    @Test
    fun validateBaseUrlAllowsPlainHttpOnlyForLocalhost() {
        assertEquals("http://localhost:8080", validateBaseUrl("http://localhost:8080"))
        assertEquals("http://127.0.0.1", validateBaseUrl("http://127.0.0.1"))
        assertEquals("http://[::1]:8080", validateBaseUrl("http://[::1]:8080"))
        for (bad in listOf("http://pathos.example.com", "http://localhost.evil.example", "http://10.0.0.5")) {
            try {
                validateBaseUrl(bad)
                fail(bad)
            } catch (e: PathosConfigException) {
                assertTrue(bad, e.message!!.contains("http"))
            }
        }
    }

    @Test
    fun validateBaseUrlRefusesInvalidValues() {
        for (bad in listOf(
            "", "   ", "pathos.example.com", "ftp://pathos.example.com", "javascript:alert(1)",
            "https://u:p@pathos.example.com", "https://pathos.example.com/?a=1", "https://pathos.example.com/#x", "https://",
        )) {
            try {
                validateBaseUrl(bad)
                fail("accepted: $bad")
            } catch (_: PathosConfigException) {
                // expected
            }
        }
    }

    @Test
    fun clientEnforcesUrlAndToken() {
        try {
            PathosClient("http://evil.example.com", TOKEN)
            fail()
        } catch (_: PathosConfigException) {
        }
        for (bad in listOf("", "a b", "tok\nen")) {
            try {
                PathosClient("https://ok.example.com", bad)
                fail("accepted token '$bad'")
            } catch (e: PathosConfigException) {
                assertFalse(e.message!!.contains(bad.ifEmpty { "\u0000" }))
            }
        }
        assertFalse(PathosClient("https://ok.example.com", TOKEN).toString().contains(TOKEN))
    }

    @Test
    fun findingWebUrlUsesTheNotificationLinkFormat() {
        assertEquals("https://p.example.com/findings?status=all&finding=abc", findingWebUrl("https://p.example.com", "abc"))
        assertEquals("https://p.example.com/findings?status=all&finding=a%2Fb%26c", findingWebUrl("https://p.example.com", "a/b&c"))
    }

    // -------------------------------------------------------------------------
    // Requests

    @Test
    fun sendsTheBearerTokenAndPaginatesRepositories() {
        val s = server { r ->
            if (r.query("cursor") == "c1") {
                Reply(200, """{"items":[{"id":"2","full_name":"o/b","url":null}],"next_cursor":null}""")
            } else {
                Reply(200, """{"items":[{"id":"1","full_name":"o/a","url":"https://github.com/o/a"}],"next_cursor":"c1"}""")
            }
        }
        val repos = client(s).listRepositories()
        assertEquals(listOf("1", "2"), repos.map { it.id })
        assertEquals("https://github.com/o/a", repos[0].url)
        assertEquals(2, s.requests.size)
        val first = s.requests[0]
        assertEquals("GET", first.method)
        assertEquals("/api/v1/repositories", first.uri.path)
        assertEquals("200", first.query("limit"))
        assertEquals("name", first.query("sort"))
        assertEquals("Bearer $TOKEN", first.header("Authorization"))
        assertEquals("application/json", first.header("Accept"))
        assertNull(first.header("Cookie"))
        assertEquals("c1", s.requests[1].query("cursor"))
    }

    @Test
    fun listsOpenFindingsWithCursorPaginationAndACap() {
        val pages = mapOf(
            "" to """{"items":[{"id":"a","title":"A","severity":"high","status":"open","cwe":["79"],"risk_score":81.5,"start_line":3,"file_path":"src/a.ts"},{"id":"b"}],"next_cursor":"p2"}""",
            "p2" to """{"items":[{"id":"c"},{"id":"d"}],"next_cursor":"p3"}""",
            "p3" to """{"items":[{"id":"e"}],"next_cursor":null}""",
        )
        val s = server { r ->
            assertEquals("/api/v1/findings", r.uri.path)
            assertEquals("repo-1", r.query("repository_id"))
            assertEquals("open", r.query("status"))
            assertEquals("severity", r.query("sort"))
            Reply(200, pages[r.query("cursor") ?: ""])
        }
        val all = client(s).listOpenFindings("repo-1")
        assertEquals(listOf("a", "b", "c", "d", "e"), all.items.map { it.id })
        assertFalse(all.truncated)
        val a = all.items[0]
        assertEquals("A", a.title)
        assertEquals("high", a.severity)
        assertEquals(listOf("79"), a.cwe)
        assertEquals(81.5, a.riskScore!!, 0.0)
        assertEquals(3, a.startLine)
        assertEquals("src/a.ts", a.filePath)

        s.requests.clear()
        val capped = client(s).listOpenFindings("repo-1", 3)
        assertEquals(listOf("a", "b", "c"), capped.items.map { it.id })
        assertTrue(capped.truncated)
        assertEquals(2, s.requests.size)

        assertFalse(client(s).listOpenFindings("repo-1", 5).truncated)
    }

    @Test
    fun stopsOnARepeatedCursor() {
        val s = server { Reply(200, """{"items":[{"id":"x"}],"next_cursor":"same"}""") }
        assertEquals(ApiErrorKind.BAD_RESPONSE, expectApiError { client(s).listOpenFindings("r") }.kind)
    }

    @Test
    fun postsStatusChangesAndReviewRequestsAsJson() {
        val s = server { r ->
            if (r.uri.path.endsWith("/human-reviews")) Reply(201, """{"created":["r1"],"existing":[]}""") else Reply(204)
        }
        val c = client(s)
        c.changeStatus("f/1", FindingStatus.FALSE_POSITIVE, "  test fixture ")
        val first = s.requests[0]
        assertEquals("POST", first.method)
        assertEquals("/api/v1/findings/f%2F1/status", first.uri.rawPath)
        assertEquals("application/json", first.header("Content-Type"))
        assertEquals(mapOf("status" to "false_positive", "reason" to "test fixture"), Json.parse(first.body))

        c.changeStatus("f1", FindingStatus.IN_PROGRESS, "")
        assertEquals(mapOf("status" to "in_progress"), Json.parse(s.requests[1].body))

        val res = c.requestHumanReview("f1", "please check")
        val third = s.requests[2]
        assertEquals("/api/v1/human-reviews", third.uri.path)
        assertEquals(mapOf("finding_ids" to listOf("f1"), "reason" to "please check"), Json.parse(third.body))
        assertEquals(ReviewRequestResult(listOf("r1"), emptyList()), res)
    }

    @Test
    fun getsOneFindingWithItsSnippet() {
        val s = server { Reply(200, """{"id":"f1","title":"T","severity":"low","status":"open","snippet":"x = 1\n","snippet_start_line":4,"kev":true}""") }
        val f = client(s).getFinding("f1")
        assertEquals("x = 1\n", f.snippet)
        assertEquals(4, f.snippetStartLine)
        assertTrue(f.kev)
        assertEquals("/api/v1/findings/f1", s.requests[0].uri.path)
    }

    // -------------------------------------------------------------------------
    // Errors

    @Test
    fun mapsHttpErrorsToKinds() {
        val cases = listOf(
            Triple(401, "invalid_token", ApiErrorKind.UNAUTHORIZED),
            Triple(403, "token_read_only", ApiErrorKind.READ_ONLY),
            Triple(403, "token_not_allowed", ApiErrorKind.TOKEN_NOT_ALLOWED),
            Triple(403, "forbidden", ApiErrorKind.FORBIDDEN),
            Triple(404, "not_found", ApiErrorKind.NOT_FOUND),
            Triple(409, "conflict", ApiErrorKind.CONFLICT),
            Triple(400, "invalid_request", ApiErrorKind.INVALID),
            Triple(422, "invalid_request", ApiErrorKind.INVALID),
            Triple(429, "rate_limited", ApiErrorKind.RATE_LIMITED),
            Triple(500, "internal", ApiErrorKind.SERVER),
        )
        for ((status, code, kind) in cases) {
            val s = server { Reply(status, """{"error":{"code":"$code","message":"msg"},"request_id":"rid"}""") }
            val e = expectApiError { client(s).getFinding("x") }
            assertEquals("$status $code", kind, e.kind)
            assertEquals(status, e.status)
            assertEquals(code, e.code)
            assertEquals("rid", e.requestId)
            assertEquals("msg", e.message)
        }
    }

    @Test
    fun handlesNonJsonErrorBodiesAndInvalidJson() {
        val bad = server { Reply(502, "<html>bad gateway</html>", mapOf("X-Request-Id" to "hdr-rid")) }
        val e = expectApiError { client(bad).getFinding("x") }
        assertEquals(ApiErrorKind.SERVER, e.kind)
        assertEquals(502, e.status)
        assertEquals("hdr-rid", e.requestId)

        val login = server { Reply(200, "<html>login</html>") }
        assertEquals(ApiErrorKind.BAD_RESPONSE, expectApiError { client(login).getFinding("x") }.kind)
    }

    @Test
    fun neverFollowsRedirectsSoTheTokenStaysWithTheConfiguredHost() {
        val other = server { Reply(200, """{"items":[],"next_cursor":null}""") }
        val redirecting = server { Reply(302, null, mapOf("Location" to other.base + "/api/v1/repositories")) }
        val e = expectApiError { client(redirecting).listRepositories() }
        assertEquals(ApiErrorKind.REDIRECT, e.kind)
        assertEquals(302, e.status)
        assertEquals(1, redirecting.requests.size)
        assertEquals("the redirect target must not receive any request", 0, other.requests.size)
        assertTrue(describeError(e).contains("redirect"))

        val permanent = server { Reply(308, null, mapOf("Location" to other.base + "/")) }
        assertEquals(ApiErrorKind.REDIRECT, expectApiError { client(permanent).getFinding("x") }.kind)
        assertEquals(0, other.requests.size)
    }

    @Test
    fun mapsUnreachableServersAndTimeouts() {
        // A port that was just free: nothing listens there.
        val port = ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1")).use { it.localPort }
        val unreachable = PathosClient("http://127.0.0.1:$port", TOKEN, JdkTransport(), Duration.ofSeconds(5))
        val e = expectApiError { unreachable.listRepositories() }
        assertEquals(ApiErrorKind.NETWORK, e.kind)
        assertTrue(describeError(e).startsWith("Cannot reach PATHOS"))

        val slow = server { Reply(200, """{"id":"x"}""", delayMs = 2000) }
        val t = expectApiError { client(slow, Duration.ofMillis(300)).getFinding("x") }
        assertEquals(ApiErrorKind.TIMEOUT, t.kind)
        assertEquals("PATHOS did not answer in time.", describeError(t))
    }

    @Test
    fun neverPutsTheTokenIntoErrors() {
        val s = server { Reply(401, """{"error":{"code":"invalid_token","message":"invalid token"}}""") }
        val e = expectApiError { client(s).getFinding("x") }
        assertFalse(e.message!!.contains(TOKEN))
        assertFalse(describeError(e).contains(TOKEN))
        assertFalse(e.toString().contains(TOKEN))
    }

    @Test
    fun explainsAuthProblems() {
        assertTrue(describeError(PathosApiException(ApiErrorKind.UNAUTHORIZED, "x", 401)).contains("Set a new token"))
        assertTrue(describeError(PathosApiException(ApiErrorKind.READ_ONLY, "x", 403), "Changing the status").contains("api:write"))
        assertTrue(describeError(PathosApiException(ApiErrorKind.FORBIDDEN, "x", 403)).contains("your PATHOS role does not permit this"))
        assertEquals("bad url", describeError(PathosConfigException("bad url")))
    }

    companion object {
        private const val TOKEN = "pathos_pat_test-only-not-a-secret"
    }
}
