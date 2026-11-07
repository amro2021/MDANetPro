package com.mdanetpro.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

class CoreTest {
    private val fixtures = System.getenv("MDA_FIXTURES")?.let { File(it) }

    @Test
    fun canonicalJsonMatchesPythonRules() {
        val obj = Json.parse("""{"b": 1, "a": [1.5, 2, "x"], "nested": {"z": null, "y": true}, "t": 1794043339.5123456}""")
        assertEquals("""{"a":[1.5,2,"x"],"b":1,"nested":{"y":true,"z":null},"t":1794043339.5123456}""", Json.dumps(obj))
        assertEquals("\"H\\u00e9 \\ud83d\\ude00 \\\"q\\\" \\\\ \\n\\t\\u0001\"", Json.dumps("Hé 😀 \"q\" \\ \n\t\u0001"))
        assertEquals("1794043339.512", JsonNumber.seconds(1794043339512).raw)
        assertEquals("1794043339.5", JsonNumber.seconds(1794043339500).raw)
        assertEquals("1794043339.0", JsonNumber.seconds(1794043339000).raw)
    }

    @Test
    fun canonicalJsonMatchesPythonFixtures() {
        assumeTrue(fixtures != null)
        val lines = File(fixtures, "json_cases.txt").readLines(Charsets.UTF_8)
        for (i in lines.indices step 2) {
            assertEquals("case ${i / 2}", lines[i + 1], Json.dumps(Json.parse(lines[i])))
        }
    }

    @Test
    fun signaturesAndRecords() {
        val id = Crypto.generateIdentity()
        val data = "hello".toByteArray()
        assertTrue(Crypto.verify(id.publicKey, data, Crypto.sign(id.privateKey, data)))
        val record = jsonObj("node" to Records.nodeAddress(id.publicPem, 50404), "pubkey" to id.publicPem,
            "routes" to listOf(jsonObj("t" to "tcp", "a" to "1.2.3.4:50404", "s" to "public")), "pub_ip" to "", "nat" to "cone",
            "time" to JsonNumber.now(), "reachable" to true)
        val signed = Records.sign(record, id)
        assertTrue(Records.verify(Json.parse(Json.dumps(signed))))
        val tampered = LinkedHashMap(signed).apply { put("pub_ip", "6.6.6.6") }
        assertFalse(Records.verify(tampered))
        val other = Crypto.generateIdentity()
        assertFalse(Records.verify(LinkedHashMap(signed).apply { put("node", Records.nodeAddress(other.publicPem, 50404)) }))
    }

    @Test
    fun pythonSignedRecordVerifies() {
        assumeTrue(fixtures != null)
        val record = Json.parse(File(fixtures, "record.json").readText())
        assertTrue("record signed by Python must verify in Kotlin", Records.verify(record))
    }

    @Test
    fun pythonOnionLayerDecrypts() {
        assumeTrue(fixtures != null)
        val pem = File(fixtures, "onion_private.pem").readText()
        val layer = Json.parseObject(File(fixtures, "onion_layer.json").readText())
        val key = Crypto.privateKeyFromPem(pem)
        val hopKey = Crypto.oaepDecrypt(key, Crypto.b64d(layer.str("ek")))
        val raw = Crypto.aesGcmDecrypt(hopKey, Crypto.b64d(layer.str("nonce")), Crypto.b64d(layer.str("ct")), Crypto.b64d(layer.str("tag")))
        val inner = Json.parseObject(String(raw))
        val packed = inner["payload"].asMap()!!["packed_body"].asMap()!!
        val body = Crypto.b64d(packed.str("body_b64"))
        assertEquals("hello from python", String(body, 0, packed.int("body_len")))
    }

    @Test
    fun aesAndOaepRoundTrip() {
        val id = Crypto.generateIdentity()
        val key = Crypto.randomBytes(32)
        assertTrue(Crypto.oaepDecrypt(id.privateKey, Crypto.oaepEncrypt(id.publicKey, key)).contentEquals(key))
        val sealed = Crypto.aesGcmEncrypt(key, "secret".toByteArray())
        assertEquals("secret", String(Crypto.aesGcmDecrypt(key, sealed.nonce, sealed.ciphertext, sealed.tag)))
    }

    @Test
    fun endpoints() {
        assertEquals("2a01:4f8::1" to 50404, Endpoint.split("[2a01:4f8::1]:50404"))
        assertEquals("[2a01:4f8::1]:50404", Endpoint.format("2a01:4f8::1", 50404))
        assertTrue(Endpoint.isVirtual("0123456789abcdef0123.mda:50404"))
        assertFalse(Endpoint.isVirtual("192.168.1.5:50404"))
        assertTrue(NetInfo.inNetwork("192.168.1.77", "192.168.1.0/24"))
        assertFalse(NetInfo.inNetwork("192.168.2.77", "192.168.1.0/24"))
    }

    @Test
    fun stunCodec() {
        val (req, tx) = Stun.request()
        assertTrue(Stun.isStun(req, req.size))
        // Build an XOR-MAPPED-ADDRESS response for 31.0.0.20:61000 by hand.
        val cookie = byteArrayOf(0x21, 0x12, 0xA4.toByte(), 0x42)
        val port = 61000 xor 0x2112
        val ip = byteArrayOf(31, 0, 0, 20).mapIndexed { i, b -> (b.toInt() xor cookie[i].toInt()).toByte() }.toByteArray()
        val attr = byteArrayOf(0, 0x20, 0, 8, 0, 1, (port ushr 8).toByte(), port.toByte()) + ip
        val resp = byteArrayOf(0x01, 0x01, 0, attr.size.toByte()) + cookie + tx + attr
        val parsed = Stun.parse(resp, resp.size)!!
        assertEquals("31.0.0.20", parsed.second)
        assertEquals(61000, parsed.third)
    }
}
