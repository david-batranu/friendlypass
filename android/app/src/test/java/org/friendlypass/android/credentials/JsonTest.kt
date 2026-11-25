package org.friendlypass.android.credentials

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class JsonTest {

    @Test
    fun `parses objects, arrays, escapes and numbers`() {
        val parsed = Json.parse(
            """{"s":"a\"b\n","i":-7,"f":1.5,"b":true,"n":null,"a":[1,{"x":"y"}]}""",
        ).asJsonObject()!!

        assertEquals("a\"b\n", parsed.stringField("s"))
        assertEquals(-7L, parsed.longField("i"))
        assertEquals(1.5, parsed["f"])
        assertEquals(true, parsed["b"])
        assertNull(parsed["n"])
        assertEquals(2, parsed.arrayField("a")!!.size)
        assertEquals("y", (parsed.arrayField("a")!![1].asJsonObject())!!.stringField("x"))
    }

    @Test
    fun `writes escaped strings and round-trips`() {
        val value = Json.obj(
            "quote" to "a\"b",
            "newline" to "a\nb",
            "control" to "\u0001",
            "list" to Json.arr("x", 1L, true),
        )
        val text = Json.write(value)
        val parsed = Json.parse(text).asJsonObject()!!
        assertEquals("a\"b", parsed.stringField("quote"))
        assertEquals("a\nb", parsed.stringField("newline"))
        assertEquals("\u0001", parsed.stringField("control"))
        assertEquals(listOf("x", 1L, true), parsed.arrayField("list"))
    }

    @Test
    fun `rejects malformed documents`() {
        assertThrows(IllegalArgumentException::class.java) { Json.parse("{") }
        assertThrows(IllegalArgumentException::class.java) { Json.parse("{\"a\":}") }
        assertThrows(IllegalArgumentException::class.java) { Json.parse("{} trailing") }
        assertThrows(IllegalArgumentException::class.java) { Json.parse("\"unterminated") }
    }

    @Test
    fun `base64url has no padding and uses the url alphabet`() {
        // 0xfb 0xff encodes as "-_8" in base64url and contains '+'/'/' in standard base64.
        val encoded = B64Url.encode(byteArrayOf(0xfb.toByte(), 0xff.toByte()))
        assertEquals("-_8", encoded)
        assertEquals(false, encoded.contains('='))
        assertArrayEquals(byteArrayOf(0xfb.toByte(), 0xff.toByte()), B64Url.decode(encoded))
    }

    @Test
    fun `base64url accepts padded input and rejects garbage`() {
        assertEquals("hello", String(B64Url.decode("aGVsbG8=")))
        assertNull(B64Url.decodeOrNull("not base64!"))
    }
}
