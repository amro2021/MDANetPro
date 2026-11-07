package com.mdanetpro.core

import java.io.DataInputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Signed route records: the ways to reach a node right now (see mda_p2p.py). */
object Records {
    const val MAX_AGE_SECONDS = 30L * 24 * 3600

    fun fingerprint(publicPem: String): String =
        Crypto.sha256Hex(publicPem.filterNot { it.isWhitespace() }.toByteArray(Charsets.US_ASCII)).substring(0, 20)

    fun nodeAddress(publicPem: String, port: Int) = "${fingerprint(publicPem)}${Endpoint.VIRTUAL_SUFFIX}:$port"

    fun sign(record: Map<String, Any?>, identity: Crypto.Identity): MutableMap<String, Any?> {
        val body = LinkedHashMap(record).apply { remove("sig") }
        val signed = LinkedHashMap<String, Any?>(body)
        signed["sig"] = Crypto.b64(Crypto.sign(identity.privateKey, Json.bytes(body)))
        return signed
    }

    fun verify(record: Any?, maxAge: Long = MAX_AGE_SECONDS): Boolean {
        val r = record.asMap() ?: return false
        return try {
            val pub = r.str("pubkey")
            val host = Endpoint.split(r.str("node")).first
            if (host != fingerprint(pub) + Endpoint.VIRTUAL_SUFFIX) return false
            if (maxAge > 0 && Math.abs(System.currentTimeMillis() / 1000.0 - r.num("time")) > maxAge) return false
            val body = LinkedHashMap(r).apply { remove("sig") }
            Crypto.verifyPem(pub, Json.bytes(body), r.str("sig"))
        } catch (_: Exception) {
            false
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun routes(record: Map<String, Any?>?): List<Map<String, Any?>> =
        (record?.get("routes") as? List<Any?>)?.mapNotNull { it.asMap() } ?: emptyList()
}

/** Length-prefixed JSON frames, the wire format of every TCP connection. */
object Frames {
    fun write(out: OutputStream, payload: Any?) {
        val body = Json.bytes(payload)
        val header = byteArrayOf((body.size ushr 24).toByte(), (body.size ushr 16).toByte(), (body.size ushr 8).toByte(), body.size.toByte())
        out.write(header + body)
        out.flush()
    }

    fun read(input: DataInputStream): MutableMap<String, Any?>? {
        val length = try { input.readInt() } catch (_: java.io.EOFException) { return null }
        if (length <= 0 || length > 16 * 1024 * 1024) return null
        val body = readAll(input, length) ?: return null
        return Json.parse(String(body, Charsets.UTF_8)).asMap()
    }
}

class Transport(private val node: Node, stunServers: List<Pair<String, Int>>? = null) {
    val records = ConcurrentHashMap<String, MutableMap<String, Any?>>()
    @Volatile var localRecord: MutableMap<String, Any?>? = null
    val lastRoute = ConcurrentHashMap<String, String>()
    val relayStatus = ConcurrentHashMap<String, String>()
    @Volatile var relays: List<String> = emptyList()
        private set
    @Volatile var manualPublic = ""
    @Volatile var stunPublic: Pair<String, Int>? = null
    @Volatile var natType = "unknown"
    @Volatile var mapping: PortMapper.Mapping? = null
    var relayPolicy: ((String) -> Boolean)? = null
    var onRecordChanged: ((Map<String, Any?>) -> Unit)? = null
    var debug: ((String) -> Unit)? = null
    var stunServers: List<Pair<String, Int>> = stunServers ?: Stun.defaultServers

    private val lock = Any()
    private val routeCache = ConcurrentHashMap<String, Triple<String, String, Long>>()
    private val failedRoutes = ConcurrentHashMap<String, Long>()
    private val relaySessions = ConcurrentHashMap<String, RelaySession>()
    private val relayClients = ConcurrentHashMap<String, RelayClientState>()
    private var udp: DatagramSocket? = null
    private val udpSessions = ConcurrentHashMap<String, Pair<InetSocketAddress, Long>>()
    private val udpWaiters = ConcurrentHashMap<String, Waiter>()
    private val udpPartial = ConcurrentHashMap<String, Partial>()
    private val udpReplyCache = ConcurrentHashMap<String, Pair<Long, ByteArray>>()
    private val punchWaiters = ConcurrentHashMap<String, Waiter>()
    private val stunWaiters = ConcurrentHashMap<String, Waiter>()
    @Volatile private var running = false

    private class Waiter {
        val latch = CountDownLatch(1)
        @Volatile var value: Any? = null
    }

    private class Partial(val count: Int) {
        val parts = HashMap<Int, ByteArray>()
        val time = System.currentTimeMillis()
    }

    // ---------------------------------------------------------------- lifecycle
    fun start() {
        running = true
        try {
            val s = DatagramSocket(null)
            s.reuseAddress = false
            s.bind(InetSocketAddress(node.port))
            s.soTimeout = 500
            udp = s
            thread("mda-udp") { udpLoop(s) }
        } catch (e: Exception) {
            udp = null
        }
        thread("mda-keepalive") { keepaliveLoop() }
        refreshLocalRecord()
    }

    fun close() {
        running = false
        relayClients.values.forEach { it.stop() }
        relayClients.clear()
        relaySessions.values.forEach { it.close() }
        try { mapping?.close?.invoke() } catch (_: Exception) {}
        udp?.close()
        udp = null
    }

    // ---------------------------------------------------------------- NAT discovery
    fun discoverNat(useUpnp: Boolean) {
        stunProbe()
        if (useUpnp) {
            val m = try { PortMapper.open(node.host, node.port) } catch (_: Exception) { null }
            if (m != null && m.externalIp.isNotEmpty()) {
                val pub = stunPublic?.first
                m.usable = NetInfo.isPublicIpv4(m.externalIp) && (pub == null || pub == m.externalIp)
            }
            mapping = m
        }
        refreshLocalRecord()
    }

    fun stunProbe() {
        val sock = udp ?: return
        val results = ArrayList<Pair<String, Int>?>()
        for ((host, port) in stunServers.take(3)) {
            val address = try { InetSocketAddress(InetAddress.getByName(host), port) } catch (_: Exception) { continue }
            val (req, tx) = Stun.request()
            val w = Waiter()
            val key = tx.joinToString("") { "%02x".format(it) }
            stunWaiters[key] = w
            var mapped: Pair<String, Int>? = null
            for (attempt in 0 until 2) {
                try { sock.send(DatagramPacket(req, req.size, address)) } catch (_: Exception) { break }
                if (w.latch.await(1500, TimeUnit.MILLISECONDS)) {
                    @Suppress("UNCHECKED_CAST")
                    mapped = w.value as? Pair<String, Int>
                    break
                }
            }
            stunWaiters.remove(key)
            results.add(mapped)
            if (results.count { it != null } >= 2) break
        }
        val (pub, nat) = Stun.classify(results, node.port)
        stunPublic = pub
        natType = nat
    }

    // ---------------------------------------------------------------- local record
    fun buildRoutes(): List<Map<String, Any?>> {
        val port = node.port
        val routes = ArrayList<Map<String, Any?>>()
        for (iface in NetInfo.interfaces().take(3)) {
            routes.add(jsonObj("t" to "tcp", "a" to Endpoint.format(iface.ip, port), "s" to "lan", "net" to NetInfo.cidr(iface)))
        }
        if (routes.isEmpty() && node.host.isNotEmpty()) routes.add(jsonObj("t" to "tcp", "a" to Endpoint.format(node.host, port), "s" to "lan", "net" to ""))
        for (ip in NetInfo.globalIpv6()) routes.add(jsonObj("t" to "tcp", "a" to Endpoint.format(ip, port), "s" to "ipv6"))
        mapping?.let { m ->
            if (m.usable) {
                routes.add(jsonObj("t" to "tcp", "a" to Endpoint.format(m.externalIp, m.tcpPort), "s" to "public", "m" to m.method))
                if (m.udpPort != 0) routes.add(jsonObj("t" to "udp", "a" to Endpoint.format(m.externalIp, m.udpPort), "s" to "public"))
            }
        }
        if (manualPublic.isNotBlank()) {
            try {
                val text = if (manualPublic.contains(':') && !manualPublic.contains("::")) manualPublic else "$manualPublic:$port"
                val (h, p) = Endpoint.split(text)
                routes.add(jsonObj("t" to "tcp", "a" to Endpoint.format(h, p), "s" to "public", "m" to "manual"))
            } catch (_: Exception) {}
        }
        stunPublic?.let { routes.add(jsonObj("t" to "udp", "a" to Endpoint.format(it.first, it.second), "s" to "stun")) }
        for (relay in relays) {
            if (relayStatus[relay] == "connected") {
                routes.add(jsonObj("t" to "relay", "a" to relay, "via" to directAddresses(relay).take(3)))
            }
        }
        return routes
    }

    fun refreshLocalRecord(): Map<String, Any?> = synchronized(lock) {
        val routes = buildRoutes()
        val m = mapping
        val record = jsonObj(
            "node" to node.nodeId,
            "pubkey" to node.identity.publicPem,
            "routes" to routes,
            "pub_ip" to (stunPublic?.first ?: (if (m != null && m.usable) m.externalIp else "")),
            "nat" to natType,
            "time" to JsonNumber.now(),
        )
        record["reachable"] = routes.any { it["t"] == "tcp" && (it["s"] == "public" || it["s"] == "ipv6") }
        val old = localRecord
        val signed = Records.sign(record, node.identity)
        localRecord = signed
        records[node.nodeId] = signed
        if (old == null || meaning(old) != meaning(signed)) {
            try { onRecordChanged?.invoke(signed) } catch (_: Exception) {}
        }
        signed
    }

    private fun meaning(r: Map<String, Any?>) = Json.dumps(listOf(r["routes"], r["nat"], r["pub_ip"]))

    fun isReachable() = localRecord?.get("reachable") == true

    fun connectivitySummary(): String {
        val routes = Records.routes(localRecord)
        val public = routes.firstOrNull { it["t"] == "tcp" && it["s"] == "public" }
        val v6 = routes.firstOrNull { it["t"] == "tcp" && it["s"] == "ipv6" }
        val relayCount = routes.count { it["t"] == "relay" }
        return when {
            public != null -> "reachable from the internet at ${public["a"]} (${public["m"] ?: "port-forward"})"
            v6 != null -> "reachable over IPv6 at ${v6["a"]}"
            relayCount > 0 -> "behind NAT ($natType); others reach you via $relayCount relay(s)"
            else -> "behind NAT ($natType); reachable on your local network only"
        }
    }

    // ---------------------------------------------------------------- records from others
    fun learnRecord(record: Any?): Boolean {
        if (!Records.verify(record)) return false
        val r = record.asMap() ?: return false
        val id = r.str("node")
        if (id == node.nodeId) return false
        synchronized(lock) {
            val current = records[id]
            if (current != null && current.num("time") >= r.num("time")) return false
            records[id] = r
            routeCache.remove(id)
            failedRoutes.keys.filter { it.startsWith("$id|") }.forEach { failedRoutes.remove(it) }
        }
        return true
    }

    private fun directAddresses(endpoint: String) = Records.routes(records[endpoint]).filter { it["t"] == "tcp" }.map { it.str("a") }

    // ---------------------------------------------------------------- route selection
    fun candidateRoutes(endpoint: String): List<Pair<String, String>> {
        val selfRelay = "self-relay" to node.nodeId
        val record = records[endpoint] ?: return if (relaySessions.containsKey(endpoint)) listOf(selfRelay) else emptyList()
        val routes = Records.routes(record)
        if (routes.isEmpty()) return if (relaySessions.containsKey(endpoint)) listOf(selfRelay) else emptyList()
        val mine = localRecord ?: emptyMap()
        val myIfaces = NetInfo.interfaces()
        val myIps = myIfaces.map { it.ip }.toSet() + node.host
        val bothKnown = mine.str("pub_ip").isNotEmpty() && record.str("pub_ip").isNotEmpty()
        val samePublic = bothKnown && mine.str("pub_ip") == record.str("pub_ip")
        val ordered = ArrayList<Pair<String, String>>()
        fun add(kind: String, address: String) { if ((kind to address) !in ordered) ordered.add(kind to address) }
        fun own(address: String) = try { Endpoint.split(address).let { it.first in myIps && it.second == node.port } } catch (_: Exception) { true }

        for (r in routes) if (r["t"] == "tcp" && r["s"] == "lan" && !own(r.str("a"))) {
            val net = r.str("net")
            val inMyNet = net.isNotEmpty() && myIfaces.any { NetInfo.cidr(it) == net }
            if (samePublic || (inMyNet && !bothKnown)) add("tcp", r.str("a"))
        }
        if (NetInfo.globalIpv6().isNotEmpty()) for (r in routes) if (r["t"] == "tcp" && r["s"] == "ipv6") add("tcp", r.str("a"))
        for (r in routes) if (r["t"] == "tcp" && r["s"] == "public") add("tcp", r.str("a"))
        if (udpSessions.containsKey(endpoint)) add("udp", "session")
        if (routes.any { it["t"] == "udp" } && udp != null && record.str("nat") != "symmetric" && mine.str("nat") != "symmetric") add("punch", "")
        for (r in routes) if (r["t"] == "relay" && r.str("a") != node.nodeId) add("relay", r.str("a"))
        if (relaySessions.containsKey(endpoint) || routes.any { it["t"] == "relay" && it.str("a") == node.nodeId }) add("self-relay", node.nodeId)
        if (!bothKnown) for (r in routes) if (r["t"] == "tcp" && r["s"] == "lan" && !own(r.str("a"))) add("tcp", r.str("a"))
        return ordered
    }

    fun send(endpoint: String, payload: Map<String, Any?>, timeoutMs: Int): MutableMap<String, Any?>? {
        if (endpoint == node.nodeId) return node.processPacket(LinkedHashMap(payload), "127.0.0.1", 0)
        if (!Endpoint.isVirtual(endpoint)) {
            val (h, p) = Endpoint.split(endpoint)
            return node.sendTcp(h, p, payload, timeoutMs)
        }
        val candidates = ArrayList(candidateRoutes(endpoint))
        if (candidates.isEmpty()) {
            throw java.io.IOException(if (records.containsKey(endpoint)) "no usable route to $endpoint: it is behind NAT and has no relay yet"
            else "no route to $endpoint (unknown node: its route record has not been received)")
        }
        val now = System.currentTimeMillis()
        val cached = routeCache[endpoint]?.takeIf { it.third > now && (it.first to it.second) in candidates }
        if (cached != null) { candidates.remove(cached.first to cached.second); candidates.add(0, cached.first to cached.second) }
        val skipFailed = candidates.any { (failedRoutes["$endpoint|${it.first}|${it.second}"] ?: 0L) <= now }
        val errors = ArrayList<String>()
        for ((kind, address) in candidates) {
            val key = "$endpoint|$kind|$address"
            val recentlyFailed = (failedRoutes[key] ?: 0L) > now
            if (skipFailed && recentlyFailed && !(cached != null && cached.first == kind && cached.second == address)) continue
            val started = System.currentTimeMillis()
            try {
                val reply = sendOn(endpoint, kind, address, payload, timeoutMs)
                failedRoutes.remove(key)
                routeCache[endpoint] = Triple(kind, address, System.currentTimeMillis() + 300_000)
                lastRoute[endpoint] = describe(endpoint, kind, address)
                debug?.invoke("route $kind $address to $endpoint ok in ${(System.currentTimeMillis() - started) / 1000.0}s")
                return reply
            } catch (e: Exception) {
                failedRoutes[key] = System.currentTimeMillis() + 60_000
                errors.add("$kind $address: ${e.message}")
                debug?.invoke("route $kind $address to $endpoint failed: ${e.message}")
            }
        }
        throw java.io.IOException("all routes to $endpoint failed: " + errors.joinToString("; ").ifEmpty { "none usable" })
    }

    fun describe(endpoint: String, kind: String, address: String): String = when (kind) {
        "tcp" -> when (scope(endpoint, address)) {
            "lan" -> "direct (same network) $address"; "ipv6" -> "direct (IPv6) $address"; "public" -> "direct (internet) $address"; else -> "direct $address"
        }
        "udp", "punch" -> "direct (UDP hole punch)" + (udpSessions[endpoint]?.first?.let { " ${it.address.hostAddress}:${it.port}" } ?: "")
        "relay" -> "via relay $address"
        "self-relay" -> "via its connection to you"
        else -> kind
    }

    private fun scope(endpoint: String, address: String) = Records.routes(records[endpoint]).firstOrNull { it.str("a") == address }?.str("s") ?: ""

    private fun sendOn(endpoint: String, kind: String, address: String, payload: Map<String, Any?>, timeoutMs: Int): MutableMap<String, Any?>? {
        val withTo = LinkedHashMap(payload)
        withTo["_to"] = endpoint
        val reply = when (kind) {
            "tcp" -> {
                val (h, p) = Endpoint.split(address)
                node.sendTcp(h, p, withTo, if (scope(endpoint, address) == "lan") minOf(timeoutMs, 2500) else timeoutMs)
            }
            "udp" -> udpRequest(endpoint, withTo, timeoutMs)
            "punch" -> { punch(endpoint, minOf(timeoutMs, 4000)); udpRequest(endpoint, withTo, timeoutMs) }
            "relay" -> sendViaRelay(address, endpoint, withTo, timeoutMs)
            "self-relay" -> (relaySessions[endpoint] ?: throw java.io.IOException("not connected to us as a relay")).request(withTo, timeoutMs)
            else -> throw IllegalArgumentException("unknown route kind $kind")
        }
        if (reply?.get("status") == "wrong_node") throw java.io.IOException("reached a different node (${reply["nodeid"]})")
        return reply
    }

    private fun sendDirectOnly(endpoint: String, payload: Map<String, Any?>, timeoutMs: Int): MutableMap<String, Any?>? {
        if (!Endpoint.isVirtual(endpoint)) {
            val (h, p) = Endpoint.split(endpoint)
            return node.sendTcp(h, p, payload, timeoutMs)
        }
        val errors = ArrayList<String>()
        for ((kind, address) in candidateRoutes(endpoint)) {
            if (kind != "tcp") continue
            try {
                val (h, p) = Endpoint.split(address)
                return node.sendTcp(h, p, payload, minOf(timeoutMs, 3000))
            } catch (e: Exception) { errors.add(e.message ?: "error") }
        }
        throw java.io.IOException("no direct route: " + errors.joinToString("; "))
    }

    private fun sendViaRelay(relay: String, endpoint: String, payload: Map<String, Any?>, timeoutMs: Int): MutableMap<String, Any?>? {
        val forward = jsonObj("type" to "relay_forward", "to" to endpoint, "packet" to payload)
        val reply = try {
            sendDirectOnly(relay, forward, timeoutMs + 1000)
        } catch (e: Exception) {
            // Unknown relay (e.g. a web gateway): use the addresses the target listed for it.
            val via = Records.routes(records[endpoint]).firstOrNull { it["t"] == "relay" && it.str("a") == relay }?.get("via").asList()
            var answer: MutableMap<String, Any?>? = null
            var ok = false
            for (address in via ?: emptyList()) {
                try {
                    val (h, p) = Endpoint.split(address.toString())
                    answer = node.sendTcp(h, p, forward, timeoutMs + 1000)
                    ok = true
                    break
                } catch (_: Exception) {}
            }
            if (!ok) throw e
            answer
        }
        if (reply == null || reply["type"] != "relay_result") throw java.io.IOException("relay gave no answer")
        if (reply["ok"] != true) throw java.io.IOException("relay: ${reply["error"] ?: "failed"}")
        return reply["reply"].asMap()
    }

    // ---------------------------------------------------------------- relay server side
    fun handleRelayRegister(socket: Socket, packet: Map<String, Any?>, remoteIp: String) {
        val out = socket.getOutputStream()
        val record = packet["record"].asMap()
        if (!Records.verify(record)) { Frames.write(out, jsonObj("type" to "relay_registered", "ok" to false, "error" to "invalid record")); return }
        if (relayPolicy?.invoke(record!!.str("pubkey")) == false) { Frames.write(out, jsonObj("type" to "relay_registered", "ok" to false, "error" to "not a member")); return }
        learnRecord(record)
        val id = record!!.str("node")
        val session = RelaySession(socket)
        relaySessions.put(id, session)?.close()
        session.write(jsonObj("type" to "relay_registered", "ok" to true, "seen_ip" to remoteIp))
        try { session.readLoop() } finally { relaySessions.remove(id, session) }
    }

    fun handleRelayForward(packet: Map<String, Any?>): MutableMap<String, Any?> {
        val target = packet.str("to")
        val inner = packet["packet"].asMap() ?: return jsonObj("type" to "relay_result", "ok" to false, "error" to "bad packet")
        if (target == node.nodeId) return jsonObj("type" to "relay_result", "ok" to true, "reply" to node.processPacket(inner, "relay", 0))
        val session = relaySessions[target] ?: return jsonObj("type" to "relay_result", "ok" to false, "error" to "target not connected to this relay")
        return try {
            jsonObj("type" to "relay_result", "ok" to true, "reply" to session.request(inner, 8000))
        } catch (e: Exception) {
            jsonObj("type" to "relay_result", "ok" to false, "error" to (e.message ?: "error"))
        }
    }

    fun relayClientsConnected(): List<String> = relaySessions.keys.sorted()

    private class RelaySession(val socket: Socket) {
        private val out = socket.getOutputStream()
        private val pending = ConcurrentHashMap<String, Waiter>()
        @Volatile var closed = false

        @Synchronized fun write(frame: Map<String, Any?>) = Frames.write(out, frame)

        fun request(packet: Map<String, Any?>, timeoutMs: Int): MutableMap<String, Any?>? {
            if (closed) throw java.io.IOException("relay connection closed")
            val rid = UUID.randomUUID().toString().replace("-", "")
            val w = Waiter()
            pending[rid] = w
            try {
                write(jsonObj("type" to "relay_deliver", "rid" to rid, "packet" to packet))
                if (!w.latch.await(timeoutMs.toLong(), TimeUnit.MILLISECONDS)) throw java.io.IOException("no reply through relay")
                return w.value.asMap()
            } finally { pending.remove(rid) }
        }

        fun readLoop() {
            socket.soTimeout = 90_000
            val input = DataInputStream(socket.getInputStream())
            try {
                while (!closed) {
                    val frame = Frames.read(input) ?: break
                    when (frame["type"]) {
                        "relay_reply" -> pending[frame.str("rid")]?.let { it.value = frame["reply"]; it.latch.countDown() }
                        "relay_ping" -> write(jsonObj("type" to "relay_pong"))
                    }
                }
            } catch (_: Exception) {
            } finally { close() }
        }

        fun close() {
            closed = true
            try { socket.close() } catch (_: Exception) {}
        }
    }

    // ---------------------------------------------------------------- relay client side
    private inner class RelayClientState(val relay: String) {
        @Volatile var stopped = false
        @Volatile var socket: Socket? = null
        fun stop() { stopped = true; try { socket?.close() } catch (_: Exception) {} }
    }

    fun updateRelays(wanted: List<String>) {
        val list = wanted.filter { it.isNotEmpty() && it != node.nodeId }.take(2)
        for (r in relayClients.keys.toList()) if (r !in list) { relayClients.remove(r)?.stop(); relayStatus.remove(r) }
        relays = list
        for (r in list) if (!relayClients.containsKey(r)) {
            val state = RelayClientState(r)
            relayClients[r] = state
            thread("mda-relay-client") { relayClientLoop(state) }
        }
        refreshLocalRecord()
    }

    private fun relayClientLoop(state: RelayClientState) {
        var backoff = 2000L
        while (running && !state.stopped) {
            var sock: Socket? = null
            try {
                sock = openDirect(state.relay, 5000)
                state.socket = sock
                sock.soTimeout = 0
                val out = sock.getOutputStream()
                val input = DataInputStream(sock.getInputStream())
                val writeLock = Any()
                synchronized(writeLock) { Frames.write(out, jsonObj("type" to "relay_register", "record" to (localRecord ?: refreshLocalRecord()))) }
                val answer = Frames.read(input)
                if (answer == null || answer["ok"] != true) throw java.io.IOException(answer?.str("error") ?: "registration refused")
                relayStatus[state.relay] = "connected"
                refreshLocalRecord()
                backoff = 2000L
                val pinger = thread("mda-relay-ping") {
                    try {
                        while (!state.stopped) {
                            Thread.sleep(20_000)
                            synchronized(writeLock) { Frames.write(out, jsonObj("type" to "relay_ping")) }
                        }
                    } catch (_: Exception) {}
                }
                while (!state.stopped) {
                    val frame = Frames.read(input) ?: break
                    if (frame["type"] == "relay_deliver") {
                        thread("mda-relayed") {
                            val reply = try { node.processPacket(frame["packet"].asMap() ?: LinkedHashMap(), "relay", 0) }
                            catch (e: Exception) { jsonObj("status" to "error", "error" to (e.message ?: "error")) }
                            try { synchronized(writeLock) { Frames.write(out, jsonObj("type" to "relay_reply", "rid" to frame["rid"], "reply" to reply)) } } catch (_: Exception) {}
                        }
                    }
                }
                pinger.interrupt()
            } catch (e: Exception) {
                relayStatus[state.relay] = "error: ${e.message}"
            } finally {
                state.socket = null
                try { sock?.close() } catch (_: Exception) {}
            }
            if (relayStatus[state.relay] == "connected") relayStatus[state.relay] = "disconnected"
            if (running && !state.stopped) {
                refreshLocalRecord()
                try { Thread.sleep(backoff + (Math.random() * 1000).toLong()) } catch (_: InterruptedException) {}
                backoff = minOf(backoff * 2, 30_000L)
            }
        }
    }

    private fun openDirect(endpoint: String, timeoutMs: Int): Socket {
        val addresses = if (!Endpoint.isVirtual(endpoint)) listOf(endpoint) else candidateRoutes(endpoint).filter { it.first == "tcp" }.map { it.second }
        var last: Exception? = null
        for (a in addresses) {
            val (h, p) = Endpoint.split(a)
            try { return Socket().apply { connect(InetSocketAddress(h, p), timeoutMs) } } catch (e: Exception) { last = e }
        }
        throw java.io.IOException("cannot reach relay $endpoint: ${last?.message}")
    }

    // ---------------------------------------------------------------- UDP
    private val magic = "MDAU".toByteArray()

    private fun sendFrames(addr: InetSocketAddress, kind: Int, msgId: ByteArray, data: ByteArray) {
        val sock = udp ?: return
        val chunks = if (data.isEmpty()) listOf(ByteArray(0)) else (data.indices step 1100).map { data.copyOfRange(it, minOf(it + 1100, data.size)) }
        chunks.forEachIndexed { i, chunk ->
            val header = magic + byteArrayOf(kind.toByte()) + msgId + byteArrayOf((i ushr 8).toByte(), i.toByte(), (chunks.size ushr 8).toByte(), chunks.size.toByte())
            val packet = header + chunk
            sock.send(DatagramPacket(packet, packet.size, addr))
        }
    }

    private fun hexOf(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    private fun udpLoop(sock: DatagramSocket) {
        val buf = ByteArray(65535)
        while (running && !sock.isClosed) {
            val p = DatagramPacket(buf, buf.size)
            try { sock.receive(p) } catch (_: SocketTimeoutException) { cleanupUdp(); continue } catch (_: Exception) { if (!running) break else continue }
            val data = buf.copyOf(p.length)
            val from = InetSocketAddress(p.address, p.port)
            if (Stun.isStun(data, data.size)) {
                Stun.parse(data, data.size)?.let { (tx, ip, port) ->
                    stunWaiters[hexOf(tx)]?.let { it.value = ip to port; it.latch.countDown() }
                }
                continue
            }
            if (data.size < 25 || !data.copyOfRange(0, 4).contentEquals(magic)) continue
            val kind = data[4].toInt()
            val msgId = data.copyOfRange(5, 21)
            val index = ((data[21].toInt() and 0xFF) shl 8) or (data[22].toInt() and 0xFF)
            val count = ((data[23].toInt() and 0xFF) shl 8) or (data[24].toInt() and 0xFF)
            val chunk = data.copyOfRange(25, data.size)
            if (kind in 3..5) { handlePunchFrame(kind, chunk, from); continue }
            if (count == 0 || count > 2000 || index >= count) continue
            val key = "${from}|${hexOf(msgId)}|$kind"
            val entry = udpPartial.getOrPut(key) { Partial(count) }
            entry.parts[index] = chunk
            if (entry.parts.size < entry.count) continue
            udpPartial.remove(key)
            val body = (0 until entry.count).fold(ByteArray(0)) { acc, i -> acc + (entry.parts[i] ?: ByteArray(0)) }
            if (kind == 1) thread("mda-udp-serve") { udpServe(from, msgId, body) }
            else if (kind == 2) udpWaiters[hexOf(msgId)]?.let { w ->
                w.value = try { Json.parse(String(body, Charsets.UTF_8)) } catch (_: Exception) { null }
                w.latch.countDown()
            }
        }
    }

    private fun cleanupUdp() {
        val cutoff = System.currentTimeMillis() - 30_000
        udpPartial.entries.removeIf { it.value.time < cutoff }
        udpReplyCache.entries.removeIf { it.value.first < cutoff }
    }

    private fun udpServe(from: InetSocketAddress, msgId: ByteArray, body: ByteArray) {
        val key = hexOf(msgId)
        val cached = udpReplyCache[key] ?: run {
            val reply = try {
                val request = Json.parseObject(String(body, Charsets.UTF_8))
                val sender = request.str("from")
                if (sender.isNotEmpty()) udpSessions[sender] = from to System.currentTimeMillis()
                node.processPacket(request["packet"].asMap() ?: LinkedHashMap(), from.address.hostAddress ?: "", from.port)
            } catch (e: Exception) { jsonObj("status" to "error", "error" to (e.message ?: "error")) }
            (System.currentTimeMillis() to Json.bytes(reply)).also { udpReplyCache[key] = it }
        }
        try { sendFrames(from, 2, msgId, cached.second) } catch (_: Exception) {}
    }

    private fun udpRequest(endpoint: String, payload: Map<String, Any?>, timeoutMs: Int): MutableMap<String, Any?>? {
        val session = udpSessions[endpoint] ?: throw java.io.IOException("no UDP session")
        if (udp == null) throw java.io.IOException("no UDP socket")
        val msgId = Crypto.randomBytes(16)
        val body = Json.bytes(jsonObj("from" to node.nodeId, "packet" to payload))
        val w = Waiter()
        udpWaiters[hexOf(msgId)] = w
        try {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (System.currentTimeMillis() < deadline) {
                sendFrames(session.first, 1, msgId, body)
                if (w.latch.await(minOf(1000L, maxOf(50L, deadline - System.currentTimeMillis())), TimeUnit.MILLISECONDS)) {
                    udpSessions[endpoint] = session.first to System.currentTimeMillis()
                    return w.value.asMap()
                }
            }
            throw java.io.IOException("UDP request timed out")
        } finally { udpWaiters.remove(hexOf(msgId)) }
    }

    private fun handlePunchFrame(kind: Int, chunk: ByteArray, from: InetSocketAddress) {
        val info = try { if (chunk.isEmpty()) LinkedHashMap() else Json.parseObject(String(chunk, Charsets.UTF_8)) } catch (_: Exception) { return }
        val sender = info.str("from")
        val token = info.str("token")
        if (sender.isEmpty() || sender == node.nodeId) return
        udpSessions[sender] = from to System.currentTimeMillis()
        if (kind == 3) {
            try { sendFrames(from, 4, Crypto.randomBytes(16), Json.bytes(jsonObj("from" to node.nodeId, "token" to token))) } catch (_: Exception) {}
        }
        if (kind == 3 || kind == 4) punchWaiters[token]?.let { it.value = from; it.latch.countDown() }
    }

    private fun udpAddresses(record: Map<String, Any?>?, excludeOwn: Boolean): List<InetSocketAddress> {
        val own = if (excludeOwn) NetInfo.interfaces().map { it.ip }.toSet() + node.host else emptySet()
        val out = ArrayList<InetSocketAddress>()
        for (r in Records.routes(record)) {
            try {
                if (r["t"] == "udp") Endpoint.split(r.str("a")).let { out.add(InetSocketAddress(it.first, it.second)) }
                else if (r["t"] == "tcp" && r["s"] == "lan") {
                    val (h, p) = Endpoint.split(r.str("a"))
                    if (!h.contains(':') && !(h in own && p == node.port)) out.add(InetSocketAddress(h, p))
                }
            } catch (_: Exception) {}
        }
        return out
    }

    private fun spray(targets: List<InetSocketAddress>, token: String, durationMs: Long) {
        val payload = Json.bytes(jsonObj("from" to node.nodeId, "token" to token))
        val end = System.currentTimeMillis() + durationMs
        while (System.currentTimeMillis() < end && running) {
            for (t in targets) try { sendFrames(t, 3, Crypto.randomBytes(16), payload) } catch (_: Exception) {}
            if (punchWaiters[token]?.latch?.count == 0L) break
            Thread.sleep(150)
        }
    }

    fun punch(endpoint: String, timeoutMs: Int) {
        if (udpSessions.containsKey(endpoint)) return
        val targets = udpAddresses(records[endpoint], true)
        if (targets.isEmpty() || udp == null) throw java.io.IOException("no UDP address for peer")
        val token = Crypto.hex(16)
        val w = Waiter()
        punchWaiters[token] = w
        try {
            val mine = udpAddresses(localRecord, false).map { Endpoint.format(it.address.hostAddress ?: it.hostString, it.port) }
            val request = jsonObj("type" to "punch_request", "from" to node.nodeId, "token" to token, "record" to localRecord, "udp" to mine)
            var introduced = false
            for ((kind, address) in candidateRoutes(endpoint)) {
                if (kind != "relay" && kind != "self-relay") continue
                try { sendOn(endpoint, kind, address, request, 4000); introduced = true; break } catch (_: Exception) {}
            }
            if (!introduced) throw java.io.IOException("no relay to coordinate hole punching")
            thread("mda-spray") { spray(targets, token, timeoutMs.toLong()) }
            if (!w.latch.await(timeoutMs.toLong(), TimeUnit.MILLISECONDS)) throw java.io.IOException("hole punching failed (NAT did not open)")
            udpSessions[endpoint] = (w.value as InetSocketAddress) to System.currentTimeMillis()
        } finally { punchWaiters.remove(token) }
    }

    fun handlePunchRequest(packet: Map<String, Any?>): MutableMap<String, Any?> {
        packet["record"]?.let { learnRecord(it) }
        val targets = packet["udp"].asList()?.mapNotNull { v -> try { Endpoint.split(v.toString()).let { InetSocketAddress(it.first, it.second) } } catch (_: Exception) { null } } ?: emptyList()
        val token = packet.str("token")
        if (targets.isNotEmpty() && token.isNotEmpty() && udp != null) thread("mda-spray") { spray(targets, token, 4000) }
        return jsonObj("status" to "punching")
    }

    private fun keepaliveLoop() {
        while (running) {
            try { Thread.sleep(15_000) } catch (_: InterruptedException) { return }
            val now = System.currentTimeMillis()
            for ((id, s) in udpSessions.entries.toList()) {
                if (now - s.second > 180_000) { udpSessions.remove(id); continue }
                try { sendFrames(s.first, 5, Crypto.randomBytes(16), Json.bytes(jsonObj("from" to node.nodeId))) } catch (_: Exception) {}
            }
        }
    }
}

internal fun thread(name: String, block: () -> Unit): Thread = Thread(block, name).apply { isDaemon = true; start() }
