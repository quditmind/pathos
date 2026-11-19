// Minimal JSON reader and writer for the PATHOS REST API. Kept in the plugin
// (no third-party JSON library) so it does not depend on libraries the IDE
// may or may not bundle. Strict RFC 8259 parsing with a nesting limit.

package io.github.quditmind.pathos.api

class JsonException(message: String) : Exception(message)

object Json {
    private const val MAX_DEPTH = 64

    /** Parses a JSON text to Map<String, Any?>, List<Any?>, String, Long, Double, Boolean or null. */
    fun parse(text: String): Any? {
        val p = Parser(text)
        p.skipWs()
        val v = p.value(0)
        p.skipWs()
        if (p.pos != text.length) throw JsonException("unexpected data after the JSON value at offset ${p.pos}")
        return v
    }

    fun write(value: Any?): String = StringBuilder().also { writeTo(it, value) }.toString()

    private fun writeTo(sb: StringBuilder, value: Any?) {
        when (value) {
            null -> sb.append("null")
            is String -> quote(sb, value)
            is Boolean -> sb.append(value)
            is Int, is Long -> sb.append(value)
            is Double -> {
                require(value.isFinite()) { "JSON cannot represent $value" }
                sb.append(value)
            }
            is Map<*, *> -> {
                sb.append('{')
                var first = true
                for ((k, v) in value) {
                    if (!first) sb.append(',')
                    first = false
                    quote(sb, k.toString())
                    sb.append(':')
                    writeTo(sb, v)
                }
                sb.append('}')
            }
            is Iterable<*> -> {
                sb.append('[')
                var first = true
                for (v in value) {
                    if (!first) sb.append(',')
                    first = false
                    writeTo(sb, v)
                }
                sb.append(']')
            }
            else -> throw IllegalArgumentException("unsupported JSON value type ${value::class.java.name}")
        }
    }

    private fun quote(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c < ' ' || c == ' ' || c == ' ' -> sb.append(String.format("\\u%04x", c.code))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }

    private class Parser(val s: String) {
        var pos = 0

        fun skipWs() {
            while (pos < s.length && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) pos++
        }

        fun fail(what: String): Nothing = throw JsonException("$what at offset $pos")

        fun value(depth: Int): Any? {
            if (depth > MAX_DEPTH) fail("JSON nested too deeply")
            if (pos >= s.length) fail("unexpected end of JSON")
            return when (val c = s[pos]) {
                '{' -> obj(depth)
                '[' -> arr(depth)
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c in '0'..'9') num() else fail("unexpected character '$c'")
            }
        }

        fun literal(word: String, v: Any?): Any? {
            if (!s.startsWith(word, pos)) fail("invalid literal")
            pos += word.length
            return v
        }

        fun obj(depth: Int): Map<String, Any?> {
            pos++ // {
            val out = LinkedHashMap<String, Any?>()
            skipWs()
            if (pos < s.length && s[pos] == '}') {
                pos++
                return out
            }
            while (true) {
                skipWs()
                if (pos >= s.length || s[pos] != '"') fail("expected a string key")
                val k = str()
                skipWs()
                if (pos >= s.length || s[pos] != ':') fail("expected ':'")
                pos++
                skipWs()
                out[k] = value(depth + 1)
                skipWs()
                if (pos >= s.length) fail("unexpected end of JSON")
                when (s[pos]) {
                    ',' -> pos++
                    '}' -> {
                        pos++
                        return out
                    }
                    else -> fail("expected ',' or '}'")
                }
            }
        }

        fun arr(depth: Int): List<Any?> {
            pos++ // [
            val out = ArrayList<Any?>()
            skipWs()
            if (pos < s.length && s[pos] == ']') {
                pos++
                return out
            }
            while (true) {
                skipWs()
                out.add(value(depth + 1))
                skipWs()
                if (pos >= s.length) fail("unexpected end of JSON")
                when (s[pos]) {
                    ',' -> pos++
                    ']' -> {
                        pos++
                        return out
                    }
                    else -> fail("expected ',' or ']'")
                }
            }
        }

        fun str(): String {
            pos++ // opening quote
            val sb = StringBuilder()
            while (true) {
                if (pos >= s.length) fail("unterminated string")
                val c = s[pos++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (pos >= s.length) fail("unterminated escape")
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000c')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) fail("invalid unicode escape")
                                val hex = s.substring(pos, pos + 4)
                                val code = hex.toIntOrNull(16) ?: fail("invalid unicode escape")
                                sb.append(code.toChar())
                                pos += 4
                            }
                            else -> fail("invalid escape '\\$e'")
                        }
                    }
                    c < ' ' -> fail("control character in string")
                    else -> sb.append(c)
                }
            }
        }

        fun num(): Any {
            val start = pos
            if (s[pos] == '-') pos++
            if (pos >= s.length) fail("invalid number")
            if (s[pos] == '0') {
                pos++
            } else if (s[pos] in '1'..'9') {
                while (pos < s.length && s[pos] in '0'..'9') pos++
            } else {
                fail("invalid number")
            }
            var integral = true
            if (pos < s.length && s[pos] == '.') {
                integral = false
                pos++
                if (pos >= s.length || s[pos] !in '0'..'9') fail("invalid number")
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            if (pos < s.length && (s[pos] == 'e' || s[pos] == 'E')) {
                integral = false
                pos++
                if (pos < s.length && (s[pos] == '+' || s[pos] == '-')) pos++
                if (pos >= s.length || s[pos] !in '0'..'9') fail("invalid number")
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            val text = s.substring(start, pos)
            if (integral) text.toLongOrNull()?.let { return it }
            return text.toDouble()
        }
    }
}

// Typed accessors for parsed JSON objects.

internal fun Map<String, Any?>.str(key: String): String? = this[key] as? String

internal fun Map<String, Any?>.num(key: String): Double? = (this[key] as? Number)?.toDouble()

internal fun Map<String, Any?>.bool(key: String): Boolean? = this[key] as? Boolean

internal fun Map<String, Any?>.strList(key: String): List<String> =
    (this[key] as? List<*>)?.mapNotNull { it as? String } ?: emptyList()

@Suppress("UNCHECKED_CAST")
internal fun Any?.asObject(): Map<String, Any?>? = this as? Map<String, Any?>
