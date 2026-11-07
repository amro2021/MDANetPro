package com.mdanetpro.core

import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * One MDANetPro node: accepts connections, answers protocol packets, and sends
 * onion-routed messages. Wire-compatible with mdanetwork.py.
 */
class Node(
    val identity: Crypto.Identity,
    val port: Int = PORT,
    @Volatile var host: String = NetInfo.primaryIp(),
    stunServers: List<Pair<String, Int>>? = null,
) {
    companion object {
        const val PORT = 50404
        const val REAL = "real"
        const val FAKE = "fake"
        const val CONTROL = "control"
    }

    val nodeId: String = Records.nodeAddress(identity.publicPem, port)
    val transport = Transport(this, stunServers)
    var onMessage: ((MutableMap<String, Any?>) -> Unit)? = null
    var helloProvider: (() -> List<Map<String, Any?>>)? = null
    var onionBodySize = 768
    val peers: MutableSet<String> = ConcurrentHashMap.newKeySet()

    private var server: ServerSocket? = null
    private val seenNonces = ConcurrentHashMap<String, Long>()
    private val circuits = ConcurrentHashMap<String, Circuit>()
    private var senderCounter = 0L

    private class Circuit(val id: String, val relays: List<String>, val expiresAt: Long) {
        var uses = 1
    }

    // ---------------------------------------------------------------- server
    fun start() {
        val s = ServerSocket()
        s.reuseAddress = false
        s.bind(InetSocketAddress(port), 32) // wildcard: IPv4 and IPv6 where available
        server = s
        thread("mda-accept") {
            while (!s.isClosed) {
                val conn = try { s.accept() } catch (_: Exception) { break }
                thread("mda-conn") { handleConnection(conn) }
            }
        }
        transport.start()
    }

    fun close() {
        transport.close()
        try { server?.close() } catch (_: Exception) {}
        server = null
    }

    val isRunning get() = server?.isClosed == false

    private fun plainIp(ip: String) = if (ip.startsWith("::ffff:")) ip.substring(7) else ip

    private fun handleConnection(conn: Socket) {
        try {
            conn.soTimeout = 15_000
            val ip = plainIp(conn.inetAddress?.hostAddress ?: "")
            val input = DataInputStream(conn.getInputStream())
            val packet = Frames.read(input) ?: return
            if (packet["type"] == "relay_register") {
                conn.soTimeout = 0
                transport.handleRelayRegister(conn, packet, ip)
                return
            }
            val reply = processPacket(packet, ip, conn.port)
            Frames.write(conn.getOutputStream(), reply)
        } catch (_: Exception) {
        } finally {
            try { conn.close() } catch (_: Exception) {}
        }
    }

    /** Handle one packet from TCP, a relay or UDP; returns the reply. */
    fun processPacket(packet: MutableMap<String, Any?>, ip: String, port: Int): MutableMap<String, Any?> {
        val target = packet.remove("_to")?.toString() ?: ""
        if (target.isNotEmpty() && target != nodeId) return jsonObj("status" to "wrong_node", "nodeid" to nodeId)
        if (!packet.containsKey("received_from")) packet["received_from"] = "$ip:$port"
        when (packet.str("type")) {
            "ping" -> return jsonObj("type" to "pong", "nodeid" to nodeId, "seen_ip" to ip)
            "reach_probe" -> return answerReachProbe(packet, ip)
            "hello" -> {
                packet["record"]?.let { transport.learnRecord(it) }
                val networks = try { helloProvider?.invoke() ?: emptyList() } catch (_: Exception) { emptyList() }
                return jsonObj("type" to "hello_reply", "nodeid" to nodeId, "seen_ip" to ip, "networks" to networks, "record" to transport.localRecord)
            }
            "relay_forward" -> return transport.handleRelayForward(packet)
            "punch_request" -> return transport.handlePunchRequest(packet)
            "routes_record" -> return jsonObj("status" to if (transport.learnRecord(packet["record"])) "ok" else "ignored")
        }
        val type = packet.str("type")
        if (packet["routing"] == "onion" && (type == REAL || type == FAKE)) return handleOnion(packet)
        try { onMessage?.invoke(packet) } catch (_: Exception) {}
        return jsonObj("status" to "ok", "nodeid" to nodeId)
    }

    // ---------------------------------------------------------------- sending
    fun sendTcp(host: String, port: Int, payload: Map<String, Any?>, timeoutMs: Int): MutableMap<String, Any?>? {
        Socket().use { s ->
            s.connect(InetSocketAddress(host, port), timeoutMs)
            s.soTimeout = timeoutMs
            Frames.write(s.getOutputStream(), payload)
            return Frames.read(DataInputStream(s.getInputStream()))
        }
    }

    fun send(endpoint: String, payload: Map<String, Any?>, timeoutMs: Int = 5000) = transport.send(Endpoint.normalize(endpoint), payload, timeoutMs)

    fun sendControl(endpoint: String, payload: Map<String, Any?>, timeoutMs: Int = 5000): MutableMap<String, Any?>? {
        val p = LinkedHashMap(payload)
        p["type"] = CONTROL
        p["routing"] = "direct"
        return send(endpoint, p, timeoutMs)
    }

    fun routeDescription(endpoint: String) = transport.lastRoute[endpoint] ?: ""

    fun hello(endpoint: String, timeoutMs: Int = 6000): MutableMap<String, Any?>? {
        val reply = send(endpoint, jsonObj("type" to "hello", "nodeid" to nodeId, "record" to transport.localRecord), timeoutMs)
        if (reply?.get("type") != "hello_reply") return null
        reply["record"]?.let { transport.learnRecord(it) }
        return reply
    }

    // ---------------------------------------------------------------- reachability test
    private fun answerReachProbe(packet: Map<String, Any?>, ip: String): MutableMap<String, Any?> {
        val result = jsonObj("type" to "reach_result", "nodeid" to nodeId, "seen_ip" to ip, "callback_ok" to false, "callback_error" to "")
        val callbackNode = packet.str("callback_node")
        if (callbackNode.isNotEmpty() && Endpoint.isVirtual(callbackNode)) {
            packet["record"]?.let { transport.learnRecord(it) }
            try {
                val reply = send(callbackNode, jsonObj("type" to "ping", "nodeid" to nodeId), 8000)
                result["callback_ok"] = reply?.get("type") == "pong"
                result["callback_route"] = routeDescription(callbackNode)
            } catch (e: Exception) { result["callback_error"] = e.message ?: "error" }
            return result
        }
        val cbPort = packet.int("callback_port")
        if (cbPort !in 1..65535) { result["callback_error"] = "missing callback port"; return result }
        try {
            val reply = sendTcp(ip, cbPort, jsonObj("type" to "ping", "nodeid" to nodeId), 4000)
            result["callback_ok"] = reply?.get("type") == "pong"
        } catch (e: Exception) { result["callback_error"] = e.message ?: "error" }
        return result
    }

    data class Probe(val connectOk: Boolean, val callbackOk: Boolean, val route: String, val callbackRoute: String, val seenIp: String, val error: String)

    fun probe(endpoint: String, timeoutMs: Int = 8000): Probe {
        val reply = try {
            send(endpoint, jsonObj("type" to "reach_probe", "callback_port" to port, "nodeid" to nodeId, "callback_node" to nodeId, "record" to transport.localRecord), timeoutMs)
        } catch (e: Exception) {
            return Probe(false, false, "", "", "", e.message ?: "error")
        }
        val route = routeDescription(Endpoint.normalize(endpoint))
        if (reply?.get("type") != "reach_result") return Probe(true, false, route, "", reply?.str("seen_ip") ?: "", "peer runs an older version")
        return Probe(true, reply["callback_ok"] == true, route, reply.str("callback_route"), reply.str("seen_ip"), reply.str("callback_error"))
    }

    // ---------------------------------------------------------------- onion routing
    private fun encryptLayer(layer: Map<String, Any?>, publicPem: String): Map<String, Any?> {
        val hopKey = Crypto.randomBytes(32)
        val sealed = Crypto.aesGcmEncrypt(hopKey, Json.bytes(layer))
        val ek = Crypto.oaepEncrypt(Crypto.publicKeyFromPem(publicPem), hopKey)
        return jsonObj("scheme" to "rsa-aes-gcm", "ek" to Crypto.b64(ek), "nonce" to Crypto.b64(sealed.nonce), "tag" to Crypto.b64(sealed.tag), "ct" to Crypto.b64(sealed.ciphertext))
    }

    private fun decryptLayer(layer: Map<String, Any?>): MutableMap<String, Any?> {
        val hopKey = Crypto.oaepDecrypt(identity.privateKey, Crypto.b64d(layer.str("ek")))
        val raw = Crypto.aesGcmDecrypt(hopKey, Crypto.b64d(layer.str("nonce")), Crypto.b64d(layer.str("ct")), Crypto.b64d(layer.str("tag")))
        return Json.parseObject(String(raw, Charsets.UTF_8))
    }

    private fun packBody(text: String): Map<String, Any?> {
        var body = text.toByteArray(Charsets.UTF_8)
        if (body.size > onionBodySize) body = body.copyOf(onionBodySize)
        val padded = body + Crypto.randomBytes(onionBodySize - body.size)
        return jsonObj("body_b64" to Crypto.b64(padded), "body_len" to body.size)
    }

    private fun unpackBody(packed: Map<String, Any?>?): String {
        if (packed == null) return ""
        val raw = Crypto.b64d(packed.str("body_b64"))
        val len = packed.int("body_len").coerceIn(0, raw.size)
        return String(raw, 0, len, Charsets.UTF_8)
    }

    private fun handleOnion(packet: MutableMap<String, Any?>): MutableMap<String, Any?> {
        val routeId = packet.str("route_id")
        val nonce = packet.str("msg_nonce").trim()
        if (nonce.isNotEmpty()) {
            val cutoff = System.currentTimeMillis() - 600_000
            seenNonces.entries.removeIf { it.value < cutoff }
            if (seenNonces.putIfAbsent(nonce, System.currentTimeMillis()) != null) return jsonObj("status" to "replay_dropped", "nodeid" to nodeId, "route_id" to routeId)
        }
        val onion = packet["onion"].asMap() ?: return jsonObj("status" to "invalid_onion", "nodeid" to nodeId, "route_id" to routeId)
        val layer = try { decryptLayer(onion) } catch (e: Exception) {
            return jsonObj("status" to "decrypt_error", "nodeid" to nodeId, "route_id" to routeId, "error" to (e.message ?: ""))
        }
        val nextHop = layer.str("next_hop")
        if (nextHop.isNotEmpty()) {
            val inner = layer["inner"].asMap() ?: return jsonObj("status" to "invalid_inner", "nodeid" to nodeId, "route_id" to routeId)
            val forward = jsonObj(
                "type" to packet["type"], "routing" to "onion", "network" to packet.str("network"), "route_id" to routeId,
                "circuit_id" to packet.str("circuit_id"), "msg_nonce" to nonce, "sender_counter" to (packet["sender_counter"] ?: JsonNumber.of(0)),
                "sender" to packet.str("sender"), "receiver" to packet.str("receiver"), "onion" to inner, "time" to JsonNumber.now(),
            )
            return try {
                send(nextHop, forward, 5000)
                jsonObj("status" to "forwarded", "nodeid" to nodeId, "route_id" to routeId)
            } catch (e: Exception) {
                jsonObj("status" to "forward_error", "nodeid" to nodeId, "route_id" to routeId, "error" to (e.message ?: ""))
            }
        }
        val final = layer["payload"].asMap() ?: return jsonObj("status" to "invalid_final_payload", "nodeid" to nodeId, "route_id" to routeId)
        if (packet["type"] == FAKE) return jsonObj("status" to "fake_discarded", "nodeid" to nodeId, "route_id" to routeId)
        val delivered = jsonObj(
            "type" to REAL, "routing" to "onion", "network" to packet.str("network"), "sender" to packet.str("sender"),
            "receiver" to packet.str("receiver"), "route_id" to routeId, "circuit_id" to packet.str("circuit_id"), "msg_nonce" to nonce,
            "text" to unpackBody(final["packed_body"].asMap()), "time" to JsonNumber.now(),
        )
        try { onMessage?.invoke(delivered) } catch (_: Exception) {}
        return jsonObj("status" to "delivered", "nodeid" to nodeId, "route_id" to routeId)
    }

    class OnionResult(val route: List<String>, val routeId: String, val response: Map<String, Any?>?)

    fun sendOnion(receiver: String, text: String, network: String, type: String, relayCount: Int, relayPool: List<String>, keys: Map<String, String>, timeoutMs: Int = 5000): OnionResult {
        val receiverEp = Endpoint.normalize(receiver)
        val receiverKey = keys[receiverEp] ?: throw IllegalArgumentException("Missing receiver public key for $receiverEp")
        val candidates = relayPool.map { Endpoint.normalize(it) }.toSet().filter { it != nodeId && it != receiverEp && keys.containsKey(it) }
        val cacheKey = "$network|$receiverEp|$type"
        val now = System.currentTimeMillis()
        var circuit = circuits[cacheKey]
        if (circuit == null || now > circuit.expiresAt || circuit.uses >= 8 || !candidates.containsAll(circuit.relays)) {
            circuit = Circuit("circuit-${UUID.randomUUID().toString().replace("-", "")}", candidates.shuffled().take(relayCount.coerceAtLeast(0)), now + 120_000)
            circuits[cacheKey] = circuit
        } else circuit.uses++
        val route = circuit.relays + receiverEp
        val routeId = UUID.randomUUID().toString()
        var onion = encryptLayer(jsonObj("next_hop" to "", "payload" to jsonObj("route_id" to routeId, "message_type" to type, "packed_body" to packBody(text))), receiverKey)
        for (i in route.size - 2 downTo 0) {
            val hopKey = keys[route[i]] ?: throw IllegalArgumentException("Missing public key for hop ${route[i]}")
            onion = encryptLayer(jsonObj("next_hop" to route[i + 1], "inner" to onion), hopKey)
        }
        senderCounter++
        val packet = jsonObj(
            "type" to type, "routing" to "onion", "network" to network, "route_id" to routeId, "circuit_id" to circuit.id,
            "msg_nonce" to UUID.randomUUID().toString().replace("-", ""), "sender_counter" to JsonNumber.of(senderCounter),
            "sender" to nodeId, "receiver" to receiverEp, "onion" to onion, "time" to JsonNumber.now(),
        )
        val response = send(route[0], packet, timeoutMs)
        return OnionResult(route, routeId, response)
    }
}
