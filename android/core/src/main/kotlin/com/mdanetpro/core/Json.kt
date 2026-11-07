package com.mdanetpro.core

/**
 * JSON that is byte-compatible with Python's
 * `json.dumps(obj, sort_keys=True, separators=(",", ":"))` (ensure_ascii=True).
 *
 * Signatures and update hashes in MDANetPro are computed over that exact text, so:
 *  - numbers keep their original lexeme ([JsonNumber.raw]); a number parsed from a Python
 *    node is written back byte-for-byte,
 *  - numbers we create are written the way Python's float/int repr would print them,
 *  - strings are escaped like Python (non-ASCII as lowercase \uXXXX, UTF-16 surrogates kept).
 *
 * Values are plain Kotlin types: Map<String, Any?>, List<Any?>, String, Boolean, null, JsonNumber.
 */
class JsonNumber(val raw: String) {
    fun toDouble(): Double = raw.toDouble()
    fun toLong(): Long = raw.toDoubleOrNull()?.toLong() ?: 0L
    fun toInt(): Int = toLong().toInt()
    override fun equals(other: Any?) = other is JsonNumber && other.raw == raw
    override fun hashCode() = raw.hashCode()
    override fun toString() = raw

    companion object {
        fun of(value: Long) = JsonNumber(value.toString())
        fun of(value: Int) = JsonNumber(value.toString())

        /** Seconds as Python's time.time() would print: "1794043339.512", "1794043339.0". */
        fun seconds(millis: Long): JsonNumber {
            val whole = millis / 1000
            var frac = (millis % 1000).toString().padStart(3, '0').trimEnd('0')
            if (frac.isEmpty()) frac = "0"
            return JsonNumber("$whole.$frac")
        }

        fun now() = seconds(System.currentTimeMillis())
    }
}

class JsonException(message: String) : Exception(message)

object Json {
    fun parse(text: String): Any? {
        val parser = Parser(text)
        parser.skipWs()
        val value = parser.value()
        parser.skipWs()
        if (parser.pos != text.length) throw JsonException("trailing data at ${parser.pos}")
        return value
    }

    fun parseObject(text: String): MutableMap<String, Any?> {
        @Suppress("UNCHECKED_CAST")
        return parse(text) as? MutableMap<String, Any?> ?: throw JsonException("not an object")
    }

    /** Canonical (sorted, compact, ASCII) text, identical to Python's output. */
    fun dumps(value: Any?): String = StringBuilder().also { write(it, value) }.toString()

    fun bytes(value: Any?): ByteArray = dumps(value).toByteArray(Charsets.US_ASCII)

    /** Deep copy (maps become LinkedHashMap, lists ArrayList). */
    fun copy(value: Any?): Any? = when (value) {
        is Map<*, *> -> LinkedHashMap<String, Any?>().also { out -> value.forEach { (k, v) -> out[k.toString()] = copy(v) } }
        is List<*> -> ArrayList<Any?>().also { out -> value.forEach { out.add(copy(it)) } }
        else -> value
    }

    private val keyOrder = Comparator<String> { a, b ->
        // Python sorts str keys by code point.
        val ia = a.codePoints().toArray()
        val ib = b.codePoints().toArray()
        for (i in 0 until minOf(ia.size, ib.size)) {
            if (ia[i] != ib[i]) return@Comparator ia[i].compareTo(ib[i])
        }
        ia.size.compareTo(ib.size)
    }

    private fun write(out: StringBuilder, value: Any?) {
        when (value) {
            null -> out.append("null")
            is Boolean -> out.append(if (value) "true" else "false")
            is JsonNumber -> out.append(value.raw)
            is Int, is Long, is Short, is Byte -> out.append(value.toString())
            is Double, is Float -> throw JsonException("use JsonNumber for non-integer numbers")
            is String -> writeString(out, value)
            is Map<*, *> -> {
                out.append('{')
                val keys = value.keys.map { it.toString() }.sortedWith(keyOrder)
                keys.forEachIndexed { i, key ->
                    if (i > 0) out.append(',')
                    writeString(out, key)
                    out.append(':')
                    write(out, value[key])
                }
                out.append('}')
            }
            is Iterable<*> -> {
                out.append('[')
                value.forEachIndexed { i, item ->
                    if (i > 0) out.append(',')
                    write(out, item)
                }
                out.append(']')
            }
            is Array<*> -> write(out, value.toList())
            else -> writeString(out, value.toString())
        }
    }

    private fun writeString(out: StringBuilder, s: String) {
        out.append('"')
        for (ch in s) {
            when {
                ch == '"' -> out.append("\\\"")
                ch == '\\' -> out.append("\\\\")
                ch == '\n' -> out.append("\\n")
                ch == '\r' -> out.append("\\r")
                ch == '\t' -> out.append("\\t")
                ch == '\b' -> out.append("\\b")
                ch == '\u000C' -> out.append("\\f")
                ch.code < 0x20 || ch.code > 0x7E && ch.code != 0x7F -> {
                    out.append("\\u").append(ch.code.toString(16).padStart(4, '0'))
                }
                else -> out.append(ch)
            }
        }
        out.append('"')
    }

    private class Parser(val s: String) {
        var pos = 0

        fun skipWs() {
            while (pos < s.length && s[pos] in " \t\r\n") pos++
        }

        fun value(): Any? {
            skipWs()
            if (pos >= s.length) throw JsonException("unexpected end")
            return when (val c = s[pos]) {
                '{' -> obj()
                '[' -> arr()
                '"' -> str()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c.isDigit()) num() else throw JsonException("unexpected '$c' at $pos")
            }
        }

        private fun literal(word: String, v: Any?): Any? {
            if (!s.startsWith(word, pos)) throw JsonException("bad literal at $pos")
            pos += word.length
            return v
        }

        private fun obj(): MutableMap<String, Any?> {
            val map = LinkedHashMap<String, Any?>()
            pos++
            skipWs()
            if (pos < s.length && s[pos] == '}') { pos++; return map }
            while (true) {
                skipWs()
                if (pos >= s.length || s[pos] != '"') throw JsonException("expected key at $pos")
                val key = str()
                skipWs()
                if (pos >= s.length || s[pos] != ':') throw JsonException("expected ':' at $pos")
                pos++
                map[key] = value()
                skipWs()
                if (pos >= s.length) throw JsonException("unterminated object")
                if (s[pos] == ',') { pos++; continue }
                if (s[pos] == '}') { pos++; return map }
                throw JsonException("expected ',' or '}' at $pos")
            }
        }

        private fun arr(): MutableList<Any?> {
            val list = ArrayList<Any?>()
            pos++
            skipWs()
            if (pos < s.length && s[pos] == ']') { pos++; return list }
            while (true) {
                list.add(value())
                skipWs()
                if (pos >= s.length) throw JsonException("unterminated array")
                if (s[pos] == ',') { pos++; continue }
                if (s[pos] == ']') { pos++; return list }
                throw JsonException("expected ',' or ']' at $pos")
            }
        }

        private fun str(): String {
            val sb = StringBuilder()
            pos++
            while (true) {
                if (pos >= s.length) throw JsonException("unterminated string")
                val c = s[pos++]
                when (c) {
                    '"' -> return sb.toString()
                    '\\' -> {
                        if (pos >= s.length) throw JsonException("bad escape")
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"'); '\\' -> sb.append('\\'); '/' -> sb.append('/')
                            'b' -> sb.append('\b'); 'f' -> sb.append('\u000C'); 'n' -> sb.append('\n')
                            'r' -> sb.append('\r'); 't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) throw JsonException("bad \\u escape")
                                sb.append(s.substring(pos, pos + 4).toInt(16).toChar())
                                pos += 4
                            }
                            else -> throw JsonException("bad escape \\$e")
                        }
                    }
                    else -> sb.append(c)
                }
            }
        }

        private fun num(): JsonNumber {
            val start = pos
            if (s[pos] == '-') pos++
            while (pos < s.length && (s[pos].isDigit() || s[pos] in ".eE+-")) pos++
            return JsonNumber(s.substring(start, pos))
        }
    }
}

// ---- small helpers for reading loosely typed JSON maps --------------------------------------
@Suppress("UNCHECKED_CAST")
fun Any?.asMap(): MutableMap<String, Any?>? = this as? MutableMap<String, Any?>

@Suppress("UNCHECKED_CAST")
fun Any?.asList(): MutableList<Any?>? = this as? MutableList<Any?>

fun Map<String, Any?>.str(key: String, default: String = ""): String = when (val v = this[key]) {
    null -> default
    is String -> v
    else -> v.toString()
}

fun Map<String, Any?>.num(key: String, default: Double = 0.0): Double = when (val v = this[key]) {
    is JsonNumber -> v.raw.toDoubleOrNull() ?: default
    is Number -> v.toDouble()
    is String -> v.toDoubleOrNull() ?: default
    else -> default
}

fun Map<String, Any?>.int(key: String, default: Int = 0): Int = when (val v = this[key]) {
    is JsonNumber -> v.raw.toDoubleOrNull()?.toInt() ?: default
    is Number -> v.toInt()
    is String -> v.toDoubleOrNull()?.toInt() ?: default
    else -> default
}

fun Map<String, Any?>.bool(key: String, default: Boolean = false): Boolean = when (val v = this[key]) {
    is Boolean -> v
    is String -> v.lowercase() in setOf("1", "true", "yes", "on", "enabled")
    is JsonNumber -> v.raw != "0"
    else -> default
}

fun jsonObj(vararg pairs: Pair<String, Any?>): MutableMap<String, Any?> = linkedMapOf(*pairs)
