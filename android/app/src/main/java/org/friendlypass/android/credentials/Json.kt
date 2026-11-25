package org.friendlypass.android.credentials

/**
 * Small, dependency-free JSON reader/writer used by the credential provider.
 *
 * The WebAuthn option/response payloads are small and fixed-shape, and keeping the parsing off `org.json`
 * lets the request/response mapping be unit tested as plain JVM code (no Robolectric, no Android stubs).
 *
 * Parsed values are `Map<String, Any?>` (objects), `List<Any?>` (arrays), `String`, `Long`, `Double`,
 * `Boolean` or `null`.
 */
internal object Json {

    fun parse(text: String): Any? = try {
        Parser(text).parseDocument()
    } catch (e: IllegalStateException) {
        throw IllegalArgumentException(e.message ?: "Malformed JSON", e)
    }

    fun write(value: Any?): String = StringBuilder().also { writeValue(it, value) }.toString()

    fun obj(vararg pairs: Pair<String, Any?>): Map<String, Any?> {
        val map = LinkedHashMap<String, Any?>(pairs.size)
        for ((key, value) in pairs) map[key] = value
        return map
    }

    fun arr(vararg values: Any?): List<Any?> = values.toList()

    private fun writeValue(out: StringBuilder, value: Any?) {
        when (value) {
            null -> out.append("null")
            is String -> writeString(out, value)
            is Boolean -> out.append(if (value) "true" else "false")
            is Int -> out.append(value.toString())
            is Long -> out.append(value.toString())
            is Double -> {
                // WebAuthn payloads only contain integral numbers; render them without an exponent/suffix.
                if (value == Math.floor(value) && !value.isInfinite()) {
                    out.append(value.toLong().toString())
                } else {
                    out.append(value.toString())
                }
            }
            is Map<*, *> -> {
                out.append('{')
                var first = true
                for ((key, item) in value) {
                    if (!first) out.append(',')
                    first = false
                    writeString(out, key as? String ?: key.toString())
                    out.append(':')
                    writeValue(out, item)
                }
                out.append('}')
            }
            is Iterable<*> -> {
                out.append('[')
                var first = true
                for (item in value) {
                    if (!first) out.append(',')
                    first = false
                    writeValue(out, item)
                }
                out.append(']')
            }
            is ByteArray -> writeString(out, B64Url.encode(value))
            else -> error("Unsupported JSON value: ${value.javaClass.name}")
        }
    }

    private fun writeString(out: StringBuilder, value: String) {
        out.append('"')
        for (c in value) {
            when (c) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                else -> if (c < ' ') {
                    out.append("\\u")
                    out.append(c.code.toString(16).padStart(4, '0'))
                } else {
                    out.append(c)
                }
            }
        }
        out.append('"')
    }

    private class Parser(private val text: String) {
        private var index = 0

        fun parseDocument(): Any? {
            val value = parseValue()
            skipWhitespace()
            require(index == text.length) { "Trailing data at $index" }
            return value
        }

        private fun parseValue(): Any? {
            skipWhitespace()
            require(index < text.length) { "Unexpected end of JSON" }
            return when (val c = text[index]) {
                '{' -> parseObject()
                '[' -> parseArray()
                '"' -> parseString()
                't' -> parseLiteral("true", true)
                'f' -> parseLiteral("false", false)
                'n' -> parseLiteral("null", null)
                else -> if (c == '-' || c in '0'..'9') parseNumber() else error("Unexpected '$c' at $index")
            }
        }

        private fun parseObject(): Map<String, Any?> {
            expect('{')
            val map = LinkedHashMap<String, Any?>()
            skipWhitespace()
            if (peek('}')) {
                index++
                return map
            }
            while (true) {
                skipWhitespace()
                val key = parseString()
                skipWhitespace()
                expect(':')
                map[key] = parseValue()
                skipWhitespace()
                when {
                    peek(',') -> index++
                    peek('}') -> {
                        index++
                        return map
                    }
                    else -> error("Expected ',' or '}' at $index")
                }
            }
        }

        private fun parseArray(): List<Any?> {
            expect('[')
            val values = ArrayList<Any?>()
            skipWhitespace()
            if (peek(']')) {
                index++
                return values
            }
            while (true) {
                values.add(parseValue())
                skipWhitespace()
                when {
                    peek(',') -> index++
                    peek(']') -> {
                        index++
                        return values
                    }
                    else -> error("Expected ',' or ']' at $index")
                }
            }
        }

        private fun parseString(): String {
            expect('"')
            val out = StringBuilder()
            while (true) {
                require(index < text.length) { "Unterminated string" }
                val c = text[index++]
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> {
                        require(index < text.length) { "Unterminated escape" }
                        when (val esc = text[index++]) {
                            '"' -> out.append('"')
                            '\\' -> out.append('\\')
                            '/' -> out.append('/')
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                require(index + 4 <= text.length) { "Bad unicode escape" }
                                val code = text.substring(index, index + 4).toInt(16)
                                index += 4
                                out.append(code.toChar())
                            }
                            else -> error("Bad escape \\$esc")
                        }
                    }
                    else -> out.append(c)
                }
            }
        }

        private fun parseNumber(): Any {
            val start = index
            if (peek('-')) index++
            while (index < text.length && text[index] in '0'..'9') index++
            var floating = false
            if (index < text.length && text[index] == '.') {
                floating = true
                index++
                while (index < text.length && text[index] in '0'..'9') index++
            }
            if (index < text.length && (text[index] == 'e' || text[index] == 'E')) {
                floating = true
                index++
                if (index < text.length && (text[index] == '+' || text[index] == '-')) index++
                while (index < text.length && text[index] in '0'..'9') index++
            }
            val raw = text.substring(start, index)
            require(raw.isNotEmpty() && raw != "-") { "Bad number at $start" }
            return if (floating) raw.toDouble() else raw.toLongOrNull() ?: raw.toDouble()
        }

        private fun <T> parseLiteral(literal: String, value: T): T {
            require(text.startsWith(literal, index)) { "Expected $literal at $index" }
            index += literal.length
            return value
        }

        private fun expect(c: Char) {
            require(peek(c)) { "Expected '$c' at $index" }
            index++
        }

        private fun peek(c: Char): Boolean = index < text.length && text[index] == c

        private fun skipWhitespace() {
            while (index < text.length && text[index].isWhitespace()) index++
        }
    }
}

internal fun Any?.asJsonObject(): Map<String, Any?>? = this as? Map<String, Any?>

internal fun Map<String, Any?>.stringField(key: String): String? = this[key] as? String

internal fun Map<String, Any?>.objectField(key: String): Map<String, Any?>? = this[key].asJsonObject()

internal fun Map<String, Any?>.arrayField(key: String): List<Any?>? = this[key] as? List<Any?>

internal fun Map<String, Any?>.longField(key: String): Long? = when (val value = this[key]) {
    is Long -> value
    is Int -> value.toLong()
    is Double -> value.toLong()
    else -> null
}
