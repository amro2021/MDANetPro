package com.mdanetpro.core

import java.io.File
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * The MDANetPro "client": networks, members, joins and approvals, chat, relays, connection tests.
 * A port of mdaclient.py without the UI. All state lives on one engine thread; network calls run
 * on worker threads and post their results back. The Android app and the CLI both drive this.
 */
class Engine(
    private val dataDir: File,
    private val platform: Platform = Platform.NONE,
    private val stunServers: List<Pair<String, Int>>? = null,
) {
    interface Platform {
        fun onSnapshot(snapshot: Snapshot) {}
        fun onChatMessage(from: String, nickname: String, text: String) {}
        fun onJoinRequest(request: JoinRequestView) {}
        fun onNotice(title: String, text: String) {}

        companion object {
            val NONE = object : Platform {}
        }
    }

    data class MemberView(val nickname: String, val endpoint: String, val role: String, val isMe: Boolean)
    data class NetworkView(val name: String, val type: String, val myRole: String, val status: String, val discoverable: Boolean, val members: List<MemberView>)
    data class ContactView(val nickname: String, val endpoint: String, val network: String, val unread: Int, val lastText: String)
    data class ChatMessage(val incoming: Boolean, val text: String, val time: Long)
    data class JoinRequestView(val id: String, val network: String, val nickname: String, val endpoint: String)
    data class NearbyView(val network: String, val owner: String, val address: String, val type: String, val membership: String, val raw: Map<String, Any?>)
    data class Settings(val name: String, val port: Int, val useUpnp: Boolean, val publicAddress: String, val coverTraffic: Boolean, val relayHops: Int, val intervalMs: Int)
    data class Snapshot(
        val running: Boolean, val nodeId: String, val host: String, val internet: String, val setupDone: Boolean,
        val activeNetwork: String, val networks: List<NetworkView>, val contacts: List<ContactView>,
        val chats: Map<String, List<ChatMessage>>, val pending: List<JoinRequestView>, val nearby: List<NearbyView>,
        val logs: List<String>, val settings: Settings,
    )
    data class TestLine(val ok: Boolean?, val text: String)

    // ---------------------------------------------------------------- state
    private val loop: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { r -> Thread(r, "mda-engine").apply { isDaemon = true } }
    private val workers = Executors.newCachedThreadPool { r -> Thread(r, "mda-worker").apply { isDaemon = true } }
    private val stateFile = File(dataDir, "mda_state.json")
    lateinit var identity: Crypto.Identity
        private set
    var node: Node? = null
        private set
    private var discovery: Discovery? = null

    private var nodeName = "node"
    private var port = Node.PORT
    private var useUpnp = true
    private var publicAddress = ""
    private var coverTraffic = true
    private var relayHops = 2
    private var intervalMs = 4000
    private var setupDone = false
    private var activeNetwork = ""
    private val networks = LinkedHashMap<String, MutableMap<String, Any?>>()
    private val contacts = ArrayList<MutableMap<String, Any?>>()
    private val chats = LinkedHashMap<String, MutableList<ChatMessage>>()
    private val unread = HashMap<String, Int>()
    private val outgoing = ArrayList<MutableMap<String, Any?>>()
    private val pendingJoins = LinkedHashMap<String, MutableMap<String, Any?>>()
    private val pendingUpdates = HashMap<String, MutableMap<String, Any?>>()
    private val logs = ArrayDeque<String>()
    private val recentJoinRequesters = ConcurrentHashMap<String, Long>()
    @Volatile private var memberKeys: Set<String> = emptySet()
    @Volatile private var helloCache: List<Map<String, Any?>> = emptyList()
    private var natChecked = 0L
    private var natRunning = false
    private var routesBroadcastPending = false
    private var savePending = false

    init {
        dataDir.mkdirs()
        load()
    }

    // ---------------------------------------------------------------- threading helpers
    fun post(block: () -> Unit) {
        loop.execute { try { block() } catch (e: Exception) { log("Error: ${e.message}") } }
    }

    private fun later(ms: Long, block: () -> Unit) {
        loop.schedule({ try { block() } catch (e: Exception) { log("Error: ${e.message}") } }, ms, TimeUnit.MILLISECONDS)
    }

    private fun background(block: () -> Unit) {
        workers.execute { try { block() } catch (e: Exception) { post { log("Error: ${e.message}") } } }
    }

    private fun log(text: String) {
        val line = "${java.text.SimpleDateFormat("HH:mm:ss").format(java.util.Date())} $text"
        synchronized(logs) {
            logs.addLast(line)
            while (logs.size > 300) logs.removeFirst()
        }
        publish()
    }

    // ---------------------------------------------------------------- persistence
    private fun load() {
        val state = try { if (stateFile.exists()) Json.parseObject(stateFile.readText()) else null } catch (_: Exception) { null }
        val id = state?.get("identity").asMap()
        identity = if (id != null) Crypto.loadIdentity(id.str("private_key_pem"), id.str("public_key_pem")) else Crypto.generateIdentity()
        if (state == null) {
            nodeName = System.getProperty("user.name")?.take(32)?.ifBlank { null } ?: "node"
            save()
            return
        }
        state["node"].asMap()?.let {
            nodeName = it.str("name", nodeName)
            port = it.int("port", Node.PORT)
            useUpnp = it.bool("use_upnp", true)
            publicAddress = it.str("public_address")
        }
        state["traffic"].asMap()?.let {
            coverTraffic = it.bool("cover_enabled", true)
            relayHops = it.int("relay_hops", 2)
            intervalMs = it.int("interval_ms", 4000).coerceAtLeast(1000)
        }
        setupDone = state.bool("setup_done", false)
        activeNetwork = state.str("active_network")
        state["networks"].asMap()?.forEach { (k, v) -> v.asMap()?.let { networks[k] = it } }
        state["contacts"].asList()?.forEach { c -> c.asMap()?.let { contacts.add(it) } }
        state["chats"].asMap()?.forEach { (ep, list) ->
            chats[ep] = list.asList()?.mapNotNull { m -> m.asMap()?.let { ChatMessage(it.bool("in"), it.str("text"), it.num("time").toLong()) } }?.toMutableList() ?: ArrayList()
        }
        refreshMemberKeys()
    }

    private fun save() {
        val state = jsonObj(
            "identity" to jsonObj("private_key_pem" to identity.privatePem, "public_key_pem" to identity.publicPem),
            "node" to jsonObj("name" to nodeName, "port" to port, "use_upnp" to useUpnp, "public_address" to publicAddress),
            "traffic" to jsonObj("cover_enabled" to coverTraffic, "relay_hops" to relayHops, "interval_ms" to intervalMs),
            "setup_done" to setupDone,
            "active_network" to activeNetwork,
            "networks" to networks,
            "contacts" to contacts,
            "chats" to chats.mapValues { (_, list) -> list.takeLast(500).map { jsonObj("in" to it.incoming, "text" to it.text, "time" to it.time) } },
        )
        val tmp = File(dataDir, "mda_state.json.tmp")
        tmp.writeText(Json.dumps(state))
        tmp.renameTo(stateFile)
    }

    private fun saveSoon() {
        if (savePending) return
        savePending = true
        later(500) { savePending = false; save() }
    }

    // ---------------------------------------------------------------- snapshot for the UI
    private fun publish() {
        loop.execute { platform.onSnapshot(snapshot()) }
    }

    fun snapshot(): Snapshot {
        val n = node
        val local = localEndpoint()
        val nets = networks.map { (name, info) ->
            val members = nodesOf(info).map { (k, v) ->
                val ep = endpointOf(v)
                MemberView(nicknameOf(k, v).ifEmpty { ep }, ep, roleOf(k, v), ep == local)
            }
            NetworkView(name, info.str("type", "private"), info.str("my_role", "member"), info.str("membership_status", "active"), info.bool("discoverable", true), members)
        }
        val contactViews = contacts.map {
            val ep = it.str("endpoint")
            ContactView(it.str("nickname", ep), ep, it.str("network"), unread[ep] ?: 0, chats[ep]?.lastOrNull()?.text ?: "")
        }
        val nearby = discovery?.nearby()?.map {
            val owner = it.str("nickname", "?")
            NearbyView(it.str("network"), owner, it.str("seen_from"), it.str("type"), membershipLabel(it.str("network")), it)
        } ?: emptyList()
        val internet = when {
            n == null -> "not running"
            natRunning && natChecked == 0L -> "checking internet connectivity…"
            else -> n.transport.connectivitySummary()
        }
        return Snapshot(
            n != null, local, n?.host ?: "", internet, setupDone, activeNetwork, nets, contactViews,
            chats.mapValues { it.value.toList() },
            pendingJoins.map { (id, p) -> JoinRequestView(id, p.str("network"), p.str("node_name", "New node"), p.str("sender")) },
            nearby, synchronized(logs) { logs.toList() },
            Settings(nodeName, port, useUpnp, publicAddress, coverTraffic, relayHops, intervalMs),
        )
    }

    private fun membershipLabel(network: String): String {
        val info = networks[network] ?: return ""
        return if (info.str("membership_status", "active") == "active") "member" else "waiting for approval"
    }

    // ---------------------------------------------------------------- node lifecycle
    fun localEndpoint(): String = node?.nodeId ?: Records.nodeAddress(identity.publicPem, port)

    fun start() = post {
        if (node != null) return@post
        val n = Node(identity, port, NetInfo.primaryIp(), stunServers)
        n.onMessage = { packet -> post { handlePacket(packet) } }
        n.helloProvider = { helloCache }
        n.transport.relayPolicy = { pub -> relayAllowed(pub) }
        n.transport.manualPublic = publicAddress
        n.transport.onRecordChanged = { record -> post { onLocalRecordChanged(record) } }
        try {
            n.start()
        } catch (e: Exception) {
            log("Could not start: port $port is in use or blocked (${e.message}).")
            platform.onNotice("Start failed", "Port $port is already in use.")
            return@post
        }
        node = n
        upsertLocalNode()
        loadRecords()
        refreshHelloCache()
        discovery = Discovery({ localEndpoint() }).also { it.start(); if (it.listenError.isNotEmpty()) log("Networks Nearby unavailable: ${it.listenError}") }
        log("Node started (${n.host}).")
        startNatCheck()
        scheduleTicks()
        publish()
    }

    fun stop() = post {
        discovery?.stop(); discovery = null
        node?.close(); node = null
        log("Node stopped.")
    }

    fun shutdown() {
        stop()
        loop.execute { save() }
        loop.shutdown()
    }

    private var ticksScheduled = false

    private fun scheduleTicks() {
        if (ticksScheduled) return
        ticksScheduled = true
        loop.scheduleWithFixedDelay({ safe { trafficTick() } }, intervalMs.toLong(), intervalMs.toLong(), TimeUnit.MILLISECONDS)
        loop.scheduleWithFixedDelay({ safe { p2pTick() } }, 4000, 15000, TimeUnit.MILLISECONDS)
        loop.scheduleWithFixedDelay({ safe { announceTick() } }, 1000, 3000, TimeUnit.MILLISECONDS)
        loop.scheduleWithFixedDelay({ safe { publish() } }, 2000, 2000, TimeUnit.MILLISECONDS)
    }

    private fun safe(block: () -> Unit) = try { block() } catch (e: Exception) { log("Error: ${e.message}") }

    /** Call when the phone switches network (Wi-Fi <-> mobile data). */
    fun onNetworkChanged() = post {
        NetInfo.invalidate()
        val n = node ?: return@post
        n.host = NetInfo.primaryIp()
        n.transport.refreshLocalRecord()
        startNatCheck(force = true)
    }

    // ---------------------------------------------------------------- node entries
    private fun nodesOf(info: MutableMap<String, Any?>): MutableMap<String, Any?> =
        info["nodes"].asMap() ?: LinkedHashMap<String, Any?>().also { info["nodes"] = it }

    private fun endpointOf(entry: Any?): String = when (entry) {
        is String -> try { Endpoint.normalize(entry) } catch (_: Exception) { "" }
        is Map<*, *> -> {
            val m = entry.asMap()!!
            val ep = m.str("endpoint")
            if (ep.isNotEmpty()) try { Endpoint.normalize(ep) } catch (_: Exception) { "" }
            else if (m.str("host").isNotEmpty() && m["port"] != null) "${m.str("host")}:${m.str("port")}" else ""
        }
        else -> ""
    }

    private fun roleOf(key: String, entry: Any?): String = when (entry) {
        is Map<*, *> -> entry.asMap()!!.str("role").trim().lowercase()
        else -> if (key.trim().lowercase().startsWith("seed")) "seed" else ""
    }

    private fun nicknameOf(key: String, entry: Any?): String {
        (entry as? Map<*, *>)?.asMap()?.str("nickname")?.trim()?.let { if (it.isNotEmpty()) return it }
        val name = key.trim()
        return if (name.isEmpty() || name.lowercase() == "self") "" else name
    }

    private fun samePubkey(a: Any?, b: Any?): Boolean {
        val x = a?.toString()?.trim() ?: ""
        return x.isNotEmpty() && x == (b?.toString()?.trim() ?: "")
    }

    private fun putNodeEntry(nodes: MutableMap<String, Any?>, name: String, entryIn: Any?, previous: MutableList<String>? = null): String {
        val entry: MutableMap<String, Any?> = entryIn.asMap()?.let { LinkedHashMap(it) } ?: jsonObj("endpoint" to endpointOf(entryIn))
        val endpoint = endpointOf(entry)
        val pubkey = entry.str("pubkey").trim()
        var match: String? = null
        if (pubkey.isNotEmpty()) match = nodes.entries.firstOrNull { (_, v) -> v is Map<*, *> && samePubkey(v.asMap()!!["pubkey"], pubkey) }?.key
        if (match == null && endpoint.isNotEmpty()) match = nodes.entries.firstOrNull { (_, v) -> endpointOf(v) == endpoint }?.key
        if (match != null) {
            val existing = nodes[match]
            val old = endpointOf(existing)
            if (old.isNotEmpty() && endpoint.isNotEmpty() && old != endpoint) previous?.add(old)
            val m = existing.asMap()
            if (m != null) m.putAll(entry) else nodes[match] = entry
            return match
        }
        val base = name.trim().ifEmpty { endpoint.ifEmpty { "node" } }
        var key = base
        var i = 2
        while (nodes.containsKey(key)) key = "$base-${i++}"
        nodes[key] = entry
        return key
    }

    private fun upsertLocalNode(): Set<String> {
        val local = localEndpoint()
        val old = HashSet<String>()
        for ((_, info) in networks) {
            val nodes = nodesOf(info)
            val existingRole = nodes.values.firstOrNull { it is Map<*, *> && samePubkey(it.asMap()!!["pubkey"], identity.publicPem) }?.asMap()?.str("role")?.lowercase() ?: ""
            val previous = ArrayList<String>()
            val entry = jsonObj("endpoint" to local, "nickname" to nodeName, "role" to existingRole.ifEmpty { info.str("my_role", "member") }, "pubkey" to identity.publicPem)
            node?.transport?.localRecord?.let { entry["record"] = it }
            putNodeEntry(nodes, nodeName, entry, previous)
            old.addAll(previous.filter { it != local })
        }
        refreshMemberKeys()
        return old
    }

    private fun refreshMemberKeys() {
        memberKeys = networks.values.flatMap { info -> nodesOf(info).values.mapNotNull { it.asMap()?.str("pubkey")?.trim()?.takeIf { k -> k.isNotEmpty() } } }.toSet()
    }

    private fun networkEndpoints(network: String): List<String> =
        networks[network]?.let { info -> nodesOf(info).mapNotNull { (k, v) -> endpointOf(v).ifEmpty { endpointOf(k) }.ifEmpty { null } } }?.toSortedSet()?.toList() ?: emptyList()

    private fun publicKeyMap(network: String): Map<String, String> {
        val map = HashMap<String, String>()
        networks[network]?.let { info -> nodesOf(info).values.forEach { v -> val ep = endpointOf(v); val pk = v.asMap()?.str("pubkey")?.trim() ?: ""; if (ep.isNotEmpty() && pk.isNotEmpty()) map[ep] = pk } }
        map[localEndpoint()] = identity.publicPem
        return map
    }

    private fun nicknameFor(endpoint: String): String {
        for (info in networks.values) for ((k, v) in nodesOf(info)) if (endpointOf(v) == endpoint) nicknameOf(k, v).let { if (it.isNotEmpty()) return it }
        return contacts.firstOrNull { it.str("endpoint") == endpoint }?.str("nickname") ?: ""
    }

    // ---------------------------------------------------------------- records & relays
    private fun learnRecordsFrom(nodes: Map<String, Any?>?) {
        val t = node?.transport ?: return
        nodes?.values?.forEach { v ->
            val m = v.asMap() ?: return@forEach
            val rec = m["record"].asMap() ?: return@forEach
            if (m.str("pubkey").isEmpty() || samePubkey(rec["pubkey"], m["pubkey"])) t.learnRecord(rec)
        }
    }

    private fun loadRecords() = networks.values.forEach { learnRecordsFrom(nodesOf(it)) }

    private fun recordFor(endpoint: String): Map<String, Any?>? {
        node?.transport?.records?.get(endpoint)?.let { return it }
        for (info in networks.values) for (v in nodesOf(info).values) {
            val m = v.asMap() ?: continue
            if (endpointOf(m) == endpoint) m["record"].asMap()?.let { return it }
        }
        return null
    }

    private fun relayAllowed(pubkey: String): Boolean {
        val p = pubkey.trim()
        if (p.isEmpty()) return false
        if (System.currentTimeMillis() - (recentJoinRequesters[p] ?: 0L) < 3_600_000) return true
        return p in memberKeys
    }

    private fun startNatCheck(force: Boolean = false) {
        val n = node ?: return
        if (natRunning && !force) return
        natRunning = true
        val upnp = useUpnp
        background {
            n.transport.discoverNat(upnp)
            post {
                natRunning = false
                natChecked = System.currentTimeMillis()
                n.transport.mapping?.let { m -> log(if (m.usable) "Router opened port ${m.tcpPort} automatically (${m.method})." else "Router mapped the port but is behind another NAT.") }
                n.transport.stunPublic?.let { log("Internet address ${it.first} (NAT type: ${n.transport.natType}).") }
                    ?: log("Could not reach STUN servers: internet connections may only work through relays.")
                chooseRelays()
                publish()
            }
        }
    }

    private fun p2pTick() {
        val n = node ?: return
        if (natChecked > 0 && System.currentTimeMillis() - natChecked > 600_000) { NetInfo.invalidate(); startNatCheck() }
        chooseRelays()
        val cutoff = System.currentTimeMillis() - 3_600_000
        recentJoinRequesters.entries.removeIf { it.value < cutoff }
        val currentIp = NetInfo.primaryIp()
        if (currentIp != n.host) { n.host = currentIp; n.transport.refreshLocalRecord() }
    }

    private fun chooseRelays() {
        val t = node?.transport ?: return
        if (t.isReachable()) { if (t.relays.isNotEmpty()) t.updateRelays(emptyList()); return }
        val local = localEndpoint()
        val rank = mapOf("seed" to 0, "trusted" to 1)
        val candidates = ArrayList<Pair<Pair<Int, Int>, String>>()
        for ((_, info) in networks) {
            val pending = info.str("membership_status") == "pending_approval"
            for ((k, v) in nodesOf(info)) {
                val ep = endpointOf(v)
                if (ep.isEmpty() || ep == local) continue
                if (t.records[ep]?.get("reachable") != true) continue
                candidates.add(((if (pending) 0 else 1) to (rank[roleOf(k, v)] ?: 2)) to ep)
            }
        }
        val chosen = candidates.sortedWith(compareBy({ it.first.first }, { it.first.second })).map { it.second }.distinct().take(2)
        if (chosen != t.relays) {
            t.updateRelays(chosen)
            if (chosen.isNotEmpty()) log("Behind NAT: others will reach you through ${chosen.joinToString { nicknameFor(it).ifEmpty { it } }}.")
        }
    }

    private fun onLocalRecordChanged(record: Map<String, Any?>) {
        for (info in networks.values) for (v in nodesOf(info).values) {
            val m = v.asMap() ?: continue
            if (samePubkey(m["pubkey"], identity.publicPem)) m["record"] = record
        }
        refreshHelloCache()
        if (!routesBroadcastPending) {
            routesBroadcastPending = true
            later(1500) { broadcastRoutes() }
        }
        publish()
    }

    private fun broadcastRoutes() {
        routesBroadcastPending = false
        val n = node ?: return
        val record = n.transport.localRecord ?: return
        saveSoon()
        val payload = jsonObj("type" to "control", "action" to "routes_update", "network" to "", "sender" to n.nodeId, "record" to record)
        val targets = networks.keys.flatMap { networkEndpoints(it) }.toSet().filter { it != localEndpoint() }
        background { targets.forEach { try { n.sendControl(it, payload, 4000) } catch (_: Exception) {} } }
    }

    private fun handleRoutesUpdate(packet: Map<String, Any?>) {
        val t = node?.transport ?: return
        val record = packet["record"].asMap() ?: return
        if (!Records.verify(record)) { log("Ignored a routes update with an invalid signature."); return }
        val isNew = t.learnRecord(record)
        if (isNew && relayAllowed(record.str("pubkey"))) {
            val sender = packet.str("sender")
            val targets = networks.keys.flatMap { networkEndpoints(it) }.toSet().filter { it !in setOf(sender, record.str("node"), localEndpoint()) }
            val n = node!!
            val forward = jsonObj("type" to "control", "action" to "routes_update", "network" to "", "sender" to n.nodeId, "record" to record)
            background { targets.forEach { try { n.sendControl(it, forward, 4000) } catch (_: Exception) {} } }
        }
        var changed = false
        for (info in networks.values) for (v in nodesOf(info).values) {
            val m = v.asMap() ?: continue
            if (samePubkey(m["pubkey"], record["pubkey"])) {
                val old = endpointOf(m)
                if (old != record.str("node")) { renameEndpoint(old, record.str("node")); m["endpoint"] = record.str("node") }
                m["record"] = record
                changed = true
            }
        }
        if (changed) saveSoon()
    }

    private fun renameEndpoint(old: String, new: String) {
        if (old.isEmpty() || new.isEmpty() || old == new) return
        contacts.filter { it.str("endpoint") == old }.forEach { it["endpoint"] = new }
        chats.remove(old)?.let { chats[new] = it }
        outgoing.filter { it.str("receiver") == old }.forEach { it["receiver"] = new }
    }

    // ---------------------------------------------------------------- discovery & hello
    private fun refreshHelloCache() {
        val n = node
        helloCache = networks.filter { (_, info) ->
            info.str("my_role", "member").lowercase() in setOf("seed", "trusted") && info.str("membership_status", "active") == "active" && info.bool("discoverable", true)
        }.map { (name, info) ->
            jsonObj(
                "network" to name, "type" to info.str("type", "private"), "description" to info.str("description").take(160),
                "rules" to (info["rules"].asList()?.map { it.toString().take(40) }?.take(5) ?: emptyList<String>()),
                "min_approvals" to info.int("min_approvals", 2).coerceAtLeast(1), "endpoint" to localEndpoint(),
                "role" to info.str("my_role", "member"), "nickname" to nodeName, "pubkey" to identity.publicPem,
                "port" to port, "record" to n?.transport?.localRecord,
            )
        }
    }

    private fun announceTick() {
        val d = discovery ?: return
        if (node == null) return
        val items = helloCache.map { LinkedHashMap(it).apply { remove("pubkey"); remove("record") } }
        if (items.isNotEmpty()) background { d.announce(items) }
    }

    // ---------------------------------------------------------------- creating and joining
    fun createNetwork(name: String, type: String = "private", myRole: String = "seed", minApprovals: Int = 1, description: String = "", rules: List<String> = emptyList(), discoverable: Boolean = true) = post {
        val n = name.trim()
        if (n.isEmpty()) return@post
        if (networks.containsKey(n)) { platform.onNotice("Create Network", "You already have a network called '$n'."); return@post }
        val info = jsonObj("type" to type, "description" to description, "rules" to rules.toMutableList(), "nodes" to LinkedHashMap<String, Any?>(),
            "membership_status" to "active", "my_role" to myRole, "min_approvals" to minApprovals, "discoverable" to discoverable)
        networks[n] = info
        val entry = jsonObj("endpoint" to localEndpoint(), "role" to myRole, "nickname" to nodeName, "pubkey" to identity.publicPem)
        node?.transport?.localRecord?.let { entry["record"] = it }
        nodesOf(info)[nodeName] = entry
        activeNetwork = n
        refreshMemberKeys()
        refreshHelloCache()
        log("Network created: $n")
        save()
    }

    fun deleteNetwork(name: String) = post {
        networks.remove(name) ?: return@post
        contacts.removeAll { it.str("network") == name }
        if (activeNetwork == name) activeNetwork = networks.keys.firstOrNull() ?: ""
        refreshMemberKeys(); refreshHelloCache(); save()
        log("Network deleted: $name")
    }

    fun setActiveNetwork(name: String) = post { if (networks.containsKey(name)) { activeNetwork = name; saveSoon(); publish() } }

    private fun collectJoinTargets(nodes: Map<String, Any?>): List<String> {
        val local = localEndpoint()
        return nodes.mapNotNull { (k, v) -> endpointOf(v).takeIf { it.isNotEmpty() && it != local && roleOf(k, v) in setOf("seed", "trusted") } }.toSortedSet().toList()
    }

    private fun joinNetwork(name: String, type: String, description: String, rules: List<String>, nodesIn: Map<String, Any?>, myRole: String = "member", minApprovals: Int = 2) {
        @Suppress("UNCHECKED_CAST")
        val nodes = Json.copy(nodesIn) as MutableMap<String, Any?>
        learnRecordsFrom(nodes)
        val targets = collectJoinTargets(nodes)
        val info = networks[name] ?: jsonObj("nodes" to LinkedHashMap<String, Any?>())
        info["type"] = type; info["description"] = description; info["rules"] = rules.toMutableList(); info["nodes"] = nodes
        info["membership_status"] = "pending_approval"; info["my_role"] = myRole; info["min_approvals"] = minApprovals
        if (!info.containsKey("discoverable")) info["discoverable"] = true
        networks[name] = info
        val entry = jsonObj("endpoint" to localEndpoint(), "role" to myRole, "nickname" to nodeName, "pubkey" to identity.publicPem)
        node?.transport?.localRecord?.let { entry["record"] = it }
        putNodeEntry(nodes, nodeName, entry)
        activeNetwork = name
        refreshMemberKeys()
        log("Join targets for '$name': ${targets.joinToString()}")
        save()
        requestJoin(name, targets)
    }

    private fun requestJoin(network: String, targets: List<String>) {
        val n = node ?: run { platform.onNotice("Join Network", "Start the node first."); return }
        if (targets.isEmpty()) { platform.onNotice("Join Network", "No seed/trusted node found to send the join request to."); return }
        val payload = jsonObj(
            "type" to "control", "action" to "join_request", "network" to network, "sender" to n.nodeId, "node_name" to nodeName,
            "description" to "", "requested_role" to (networks[network]?.str("my_role", "member") ?: "member"),
            "public_key" to identity.publicPem, "record" to n.transport.localRecord, "time" to JsonNumber.now(),
        )
        background {
            var sent = 0
            for (t in targets) {
                try { n.sendControl(t, payload, 6000); sent++; post { log("Join request sent to ${nicknameFor(t).ifEmpty { t }} for '$network'.") } }
                catch (e: Exception) { post { log("Join request failed to $t: ${e.message}") } }
            }
            post {
                if (sent > 0) {
                    chooseRelays()
                    platform.onNotice("Join Network", "Join request sent. You will be notified when the network owner approves it.")
                } else platform.onNotice("Join Network", "Could not reach the network owner's computer. Check that it is on and has MDANetPro open, then run Test Connection.")
            }
        }
    }

    /** Join using a .mdar invite file's contents. */
    fun importMdar(text: String) = post {
        val payload = try { Json.parseObject(String(Crypto.b64d(text.trim().replace("\n", "")), Charsets.UTF_8)) } catch (_: Exception) { null }
        if (payload == null || payload.str("magic").isEmpty()) { platform.onNotice("Invite file", "This is not a valid .mdar file."); return@post }
        val name = payload.str("name").trim()
        val rules = when (val r = payload["rules"]) { is List<*> -> r.map { it.toString() }; is String -> r.split(",").map { it.trim() }.filter { it.isNotEmpty() }; else -> emptyList() }
        val type = payload.str("type", "private").lowercase().let { if (it == "public") "public" else "private" }
        joinNetwork(name, type, payload.str("description"), rules, payload["nodes"].asMap() ?: emptyMap(), "member", payload.int("min_approvals", 2).coerceAtLeast(1))
    }

    /** .mdar invite for a network (base64 JSON, like net_profile.py). */
    fun exportMdar(network: String, callback: (String?) -> Unit) = post {
        val info = networks[network] ?: run { callback(null); return@post }
        val selected = LinkedHashMap<String, Any?>()
        val byEndpoint = LinkedHashMap<String, MutableMap<String, Any?>>()
        val rank = mapOf("member" to 0, "trusted" to 1, "seed" to 2)
        fun upsert(endpoint: String, role: String, nickname: String, pubkey: String) {
            if (endpoint.isEmpty()) return
            val r = if (role in rank) role else "member"
            val existing = byEndpoint[endpoint]
            if (existing == null) {
                val e = jsonObj("endpoint" to endpoint, "role" to r, "nickname" to nickname.ifBlank { endpoint }, "pubkey" to pubkey)
                recordFor(endpoint)?.let { e["record"] = it }
                byEndpoint[endpoint] = e
            } else {
                if ((rank[r] ?: 0) > (rank[existing.str("role")] ?: 0)) existing["role"] = r
                if (pubkey.isNotEmpty()) existing["pubkey"] = pubkey
            }
        }
        for ((k, v) in nodesOf(info)) upsert(endpointOf(v), roleOf(k, v), nicknameOf(k, v), v.asMap()?.str("pubkey") ?: "")
        contacts.filter { it.str("network") == network }.forEach { upsert(it.str("endpoint"), "member", it.str("nickname"), "") }
        upsert(localEndpoint(), info.str("my_role", "member"), nodeName, identity.publicPem)
        byEndpoint.values.forEach { e -> var key = e.str("nickname"); var i = 2; while (selected.containsKey(key)) key = "${e.str("nickname")}-${i++}"; selected[key] = e }
        val payload = jsonObj("magic" to "**MDA Project Network profile**", "name" to network, "type" to info.str("type", "private"),
            "description" to info.str("description"), "rules" to (info["rules"].asList() ?: emptyList<Any?>()), "nodes" to selected)
        callback(Crypto.b64(Json.dumps(payload).toByteArray(Charsets.UTF_8)))
    }

    /** Join by Address: ask the owner's computer which networks it offers, then join. */
    fun lookupAndJoin(address: String, preferred: String? = null, choose: ((List<String>, (String) -> Unit) -> Unit)? = null) = post {
        val n = node ?: run { platform.onNotice("Join by Address", "Start the node first."); return@post }
        val endpoint = when {
            address.count { it == ':' } > 1 && !address.startsWith("[") -> "[$address]:${Node.PORT}"
            address.contains(':') -> address
            else -> "$address:${Node.PORT}"
        }
        log("Looking up networks at $endpoint…")
        background {
            val reply = try { n.hello(endpoint) } catch (e: Exception) { post { platform.onNotice("Join by Address", "Could not reach $endpoint: ${e.message}") }; return@background }
            post {
                if (reply == null) { platform.onNotice("Join by Address", "That computer runs an older MDANetPro version."); return@post }
                val record = reply["record"].asMap()
                var items = reply["networks"].asList()?.mapNotNull { it.asMap()?.let { m -> LinkedHashMap(m) } }?.filter { it.str("network").isNotEmpty() } ?: emptyList()
                items.forEach { if (record != null && Records.verify(record) && record.str("node") == it.str("endpoint")) it["record"] = record }
                if (preferred != null) items = items.filter { it.str("network") == preferred }.ifEmpty { items }
                when {
                    items.isEmpty() -> platform.onNotice("Join by Address", "That computer is reachable, but it has no networks open for joining.")
                    items.size == 1 || choose == null -> joinFromSummary(items[0])
                    else -> choose(items.map { it.str("network") }) { picked -> post { items.firstOrNull { it.str("network") == picked }?.let { joinFromSummary(it) } } }
                }
            }
        }
    }

    fun joinNearby(item: Map<String, Any?>) {
        val from = item.str("seen_from")
        if (from.isNotEmpty()) lookupAndJoin("$from:${item.int("port", Node.PORT)}", item.str("network"))
        else post { joinFromSummary(item) }
    }

    private fun joinFromSummary(summary: Map<String, Any?>) {
        val name = summary.str("network").trim()
        val endpoint = summary.str("endpoint").trim()
        if (name.isEmpty() || endpoint.isEmpty()) return
        if (networks[name]?.str("membership_status", "active") == "active") { platform.onNotice("Join Network", "You are already a member of '$name'."); return }
        val owner = summary.str("nickname", "owner")
        val entry = jsonObj("endpoint" to endpoint, "role" to summary.str("role", "seed"), "nickname" to owner, "pubkey" to summary.str("pubkey"))
        summary["record"].asMap()?.let { if (Records.verify(it)) { entry["record"] = it; node?.transport?.learnRecord(it) } }
        val type = summary.str("type", "private").lowercase().let { if (it == "public") "public" else "private" }
        val rules = summary["rules"].asList()?.map { it.toString() }?.filter { it.isNotBlank() } ?: emptyList()
        joinNetwork(name, type, summary.str("description"), rules, jsonObj(owner to entry), "member", summary.int("min_approvals", 2).coerceAtLeast(1))
    }

    // ---------------------------------------------------------------- incoming packets
    private fun handlePacket(packet: MutableMap<String, Any?>) {
        when (packet.str("type")) {
            "control" -> handleControl(packet)
            "chat", "real" -> {
                val sender = packet.str("sender").ifEmpty { packet.str("received_from") }
                val network = packet.str("network")
                if (contacts.none { it.str("endpoint") == sender }) {
                    contacts.add(jsonObj("nickname" to nicknameFor(sender).ifEmpty { "Peer-${sender.substringAfterLast(':')}" }, "endpoint" to sender, "circuit" to "", "network" to network))
                }
                val text = packet.str("text")
                chats.getOrPut(sender) { ArrayList() }.add(ChatMessage(true, text, System.currentTimeMillis()))
                unread[sender] = (unread[sender] ?: 0) + 1
                platform.onChatMessage(sender, nicknameFor(sender).ifEmpty { sender }, text)
                saveSoon(); publish()
            }
        }
    }

    private fun handleControl(packet: MutableMap<String, Any?>) {
        val action = packet.str("action").trim().lowercase()
        val network = packet.str("network").trim()
        when (action) {
            "join_request" -> handleJoinRequest(packet, network)
            "address_update" -> packet["record"]?.let { node?.transport?.learnRecord(it) }
            "routes_update" -> handleRoutesUpdate(packet)
            "join_approved", "node_list_update" -> handleSignedUpdate(packet, network, action, action == "join_approved")
            "join_rejected" -> { log("Join request rejected for '$network'."); platform.onNotice("Join Request Rejected", packet.str("reason", "Rejected by the network owner.")) }
            else -> log("Unknown control action ignored: $action")
        }
    }

    private fun handleJoinRequest(packet: MutableMap<String, Any?>, network: String) {
        val info = networks[network] ?: run { log("Join request ignored: unknown network '$network'."); return }
        if (info.str("my_role", "member").lowercase() !in setOf("seed", "trusted")) { log("Join request ignored: you are not an approver of '$network'."); return }
        if (packet.str("sender").isEmpty()) return
        val pub = packet.str("public_key").trim()
        if (pub.isNotEmpty()) recentJoinRequesters[pub] = System.currentTimeMillis()
        packet["record"].asMap()?.let { if (Records.verify(it) && samePubkey(it["pubkey"], pub)) node?.transport?.learnRecord(it) }
        // One pending request per requester and network.
        pendingJoins.entries.removeIf { it.value.str("network") == network && it.value.str("sender") == packet.str("sender") }
        val id = UUID.randomUUID().toString()
        pendingJoins[id] = packet
        val view = JoinRequestView(id, network, packet.str("node_name", "New node"), packet.str("sender"))
        log("Join request from ${view.nickname} for '$network'.")
        platform.onJoinRequest(view)
        publish()
    }

    fun rejectJoin(id: String) = post {
        val packet = pendingJoins.remove(id) ?: return@post
        val payload = jsonObj("type" to "control", "action" to "join_rejected", "network" to packet.str("network"),
            "reason" to "Join request rejected by trusted/seed node.", "sender" to localEndpoint(), "time" to JsonNumber.now())
        sendReliable(packet.str("sender"), payload, "join rejection")
        log("Join request rejected: ${packet.str("node_name")}")
        publish()
    }

    fun approveJoin(id: String) = post {
        val packet = pendingJoins.remove(id) ?: return@post
        val network = packet.str("network")
        val info = networks[network] ?: return@post
        val myRole = info.str("my_role", "member").lowercase()
        val sender = packet.str("sender")
        val name = packet.str("node_name", "New node").ifBlank { "New node" }
        var requestedRole = packet.str("requested_role", "member").lowercase()
        if (requestedRole !in setOf("member", "trusted", "seed")) requestedRole = "member"
        if (requestedRole != "member" && myRole != "seed") requestedRole = "member"
        val pub = packet.str("public_key").trim()
        val entry = jsonObj("endpoint" to sender, "role" to requestedRole, "nickname" to name, "pubkey" to pub)
        packet["record"].asMap()?.let { if (Records.verify(it) && samePubkey(it["pubkey"], pub)) entry["record"] = it }
        val previous = ArrayList<String>()
        putNodeEntry(nodesOf(info), name, entry, previous)
        previous.forEach { renameEndpoint(it, sender) }
        upsertContact(sender, name, network)
        refreshMemberKeys()
        save()

        val body = updateBody(info)
        val updateId = "update-${UUID.randomUUID().toString().replace("-", "")}"
        val hash = Crypto.sha256Hex(Json.bytes(body))
        val joinVote = signVote("join_approved", network, updateId, hash)
        val listVote = signVote("node_list_update", network, updateId, hash)
        registerVote(network, "node_list_update", updateId, hash, body, listVote)
        val joinPayload = jsonObj("type" to "control", "action" to "join_approved", "network" to network, "update_id" to updateId,
            "update_hash" to hash, "update_body" to body, "signer" to joinVote["signer"], "signer_pubkey" to joinVote["signer_pubkey"],
            "signature" to joinVote["signature"], "sender" to localEndpoint(), "time" to JsonNumber.now())
        sendReliable(sender, joinPayload, "join approval")
        broadcastVote(network, "node_list_update", updateId, hash, body, listVote)
        log("Join request approved for $name on '$network'.")
        publish()
    }

    private fun upsertContact(endpoint: String, nickname: String?, network: String?) {
        val existing = contacts.firstOrNull { it.str("endpoint") == endpoint }
        if (existing != null) {
            if (!nickname.isNullOrBlank()) existing["nickname"] = nickname
            if (network != null) existing["network"] = network
            return
        }
        contacts.add(jsonObj("nickname" to (nickname ?: endpoint), "endpoint" to endpoint, "circuit" to "", "network" to (network ?: "")))
    }

    // ---------------------------------------------------------------- signed network updates
    private fun updateBody(info: Map<String, Any?>): MutableMap<String, Any?> = jsonObj(
        "network_type" to info.str("type", "private"), "network_description" to info.str("description"),
        "network_rules" to Json.copy(info["rules"] ?: emptyList<Any?>()), "nodes" to Json.copy(info["nodes"] ?: LinkedHashMap<String, Any?>()),
        "min_approvals" to info.int("min_approvals", 2).coerceAtLeast(1),
    )

    private fun voteSignable(action: String, network: String, updateId: String, hash: String, signer: String) =
        jsonObj("action" to action, "network" to network, "update_id" to updateId, "update_hash" to hash, "signer" to signer)

    private fun signVote(action: String, network: String, updateId: String, hash: String): Map<String, Any?> {
        val signer = localEndpoint()
        val sig = Crypto.sign(identity.privateKey, Json.bytes(voteSignable(action, network, updateId, hash, signer)))
        return jsonObj("signer" to signer, "signer_pubkey" to identity.publicPem, "signature" to Crypto.b64(sig))
    }

    private fun verifyVote(action: String, network: String, updateId: String, hash: String, vote: Map<String, Any?>): Boolean {
        val signer = vote.str("signer").trim()
        val pub = vote.str("signer_pubkey").trim()
        val sig = vote.str("signature").trim()
        if (signer.isEmpty() || pub.isEmpty() || sig.isEmpty()) return false
        return Crypto.verifyPem(pub, Json.bytes(voteSignable(action, network, updateId, hash, signer)), sig)
    }

    private fun registerVote(network: String, action: String, updateId: String, hash: String, body: Map<String, Any?>, vote: Map<String, Any?>): MutableMap<String, Any?>? {
        val bucket = pendingUpdates.getOrPut(network) { LinkedHashMap() }
        val key = "$action|$updateId"
        val pending = bucket[key].asMap() ?: jsonObj("hash" to hash, "body" to body, "votes" to LinkedHashMap<String, Any?>(), "applied" to false).also { bucket[key] = it }
        if (pending.str("hash") != hash) return null
        pending["votes"].asMap()!![vote.str("signer")] = vote
        return pending
    }

    private fun requiredApprovals(network: String, body: Map<String, Any?>): Int {
        val base = (networks[network]?.int("min_approvals", body.int("min_approvals", 2)) ?: body.int("min_approvals", 2)).coerceAtLeast(1)
        val trusted = body["nodes"].asMap()?.count { (k, v) -> roleOf(k, v) in setOf("trusted", "seed") } ?: 0
        return if (trusted <= 1) 1 else minOf(base, trusted)
    }

    private fun handleSignedUpdate(packet: Map<String, Any?>, network: String, action: String, markActive: Boolean) {
        val updateId = packet.str("update_id").trim()
        val hash = packet.str("update_hash").trim()
        val body = packet["update_body"].asMap()
        if (updateId.isEmpty() || hash.isEmpty() || body == null) { log("Ignored malformed update for '$network'."); return }
        if (Crypto.sha256Hex(Json.bytes(body)) != hash) { log("Ignored update with hash mismatch for '$network'."); return }
        val vote = jsonObj("signer" to packet["signer"], "signer_pubkey" to packet["signer_pubkey"], "signature" to packet["signature"])
        if (!verifyVote(action, network, updateId, hash, vote)) { log("Ignored update with invalid signature for '$network'."); return }
        val signer = vote.str("signer").trim()
        val known = publicKeyMap(network)[signer]
        if (known != null && known != vote.str("signer_pubkey").trim()) { log("Ignored update with signer key mismatch for '$network'."); return }
        val rank = mapOf("member" to 0, "trusted" to 1, "seed" to 2)
        var signerRole = ""
        body["nodes"].asMap()?.forEach { (k, v) -> if (endpointOf(v) == signer) roleOf(k, v).let { if ((rank[it] ?: -1) > (rank[signerRole] ?: -1)) signerRole = it } }
        if (signerRole !in setOf("trusted", "seed")) { log("Ignored update from non-trusted signer for '$network'."); return }
        val pending = registerVote(network, action, updateId, hash, body, vote) ?: run { log("Ignored conflicting update for '$network'."); return }
        val myRole = networks[network]?.str("my_role", "member")?.lowercase() ?: "member"
        val votes = pending["votes"].asMap()!!
        if (action == "node_list_update" && myRole in setOf("trusted", "seed") && !votes.containsKey(localEndpoint())) {
            val mine = signVote(action, network, updateId, hash)
            votes[mine.str("signer")] = mine
            broadcastVote(network, action, updateId, hash, body, mine)
        }
        val required = if (action == "join_approved") 1 else requiredApprovals(network, body)
        if (pending["applied"] == true) return
        if (votes.size < required) { log("Pending update for '$network' (${votes.size}/$required approvals)."); return }
        pending["applied"] = true
        applyUpdate(body, network, markActive)
    }

    private fun broadcastVote(network: String, action: String, updateId: String, hash: String, body: Map<String, Any?>, vote: Map<String, Any?>) {
        val payload = jsonObj("type" to "control", "action" to action, "network" to network, "update_id" to updateId, "update_hash" to hash,
            "update_body" to body, "signer" to vote["signer"], "signer_pubkey" to vote["signer_pubkey"], "signature" to vote["signature"],
            "sender" to localEndpoint(), "time" to JsonNumber.now())
        networkEndpoints(network).filter { it != localEndpoint() }.forEach { sendReliable(it, payload, action) }
    }

    private fun applyUpdate(body: Map<String, Any?>, network: String, markActive: Boolean) {
        val info = networks[network] ?: jsonObj("type" to "private", "description" to "", "rules" to ArrayList<Any?>(), "nodes" to LinkedHashMap<String, Any?>(), "my_role" to "member", "min_approvals" to 2)
        body.str("network_type").lowercase().let { if (it == "private" || it == "public") info["type"] = it }
        info["description"] = body.str("network_description", info.str("description"))
        info["rules"] = when (val r = body["network_rules"]) { is List<*> -> r.map { it.toString().trim() }.filter { it.isNotEmpty() }.toMutableList(); is String -> mutableListOf(r); else -> info["rules"] }
        info["min_approvals"] = body.int("min_approvals", info.int("min_approvals", 2)).coerceAtLeast(1)
        val wasPending = info.str("membership_status") == "pending_approval"
        @Suppress("UNCHECKED_CAST")
        val merged = (Json.copy(info["nodes"] ?: LinkedHashMap<String, Any?>()) as MutableMap<String, Any?>)
        val incoming = body["nodes"].asMap()
        learnRecordsFrom(incoming)
        incoming?.forEach { (k, v) ->
            val previous = ArrayList<String>()
            putNodeEntry(merged, k, v, previous)
            previous.filter { it != localEndpoint() }.forEach { renameEndpoint(it, endpointOf(v)) }
        }
        info["nodes"] = merged
        merged.entries.firstOrNull { (_, v) -> endpointOf(v) == localEndpoint() }?.let { (k, v) -> roleOf(k, v).takeIf { it in setOf("member", "trusted", "seed") }?.let { info["my_role"] = it } }
        if (markActive || !info.containsKey("membership_status")) info["membership_status"] = "active"
        if (!info.containsKey("my_role")) info["my_role"] = "member"
        networks[network] = info
        if (markActive) activeNetwork = network
        val local = localEndpoint()
        for ((k, v) in merged) {
            val ep = endpointOf(v)
            if (ep.isEmpty() || ep == local) continue
            upsertContact(ep, nicknameOf(k, v).ifEmpty { "Peer-${ep.substringAfterLast(':')}" }, network)
        }
        refreshMemberKeys(); refreshHelloCache(); save()
        log("Network '$network' synchronized.")
        if (markActive && wasPending) {
            chooseRelays()
            later(500) { broadcastRoutes() }
            platform.onNotice("Joined", "You joined '$network'. The members now appear in your contacts.")
        }
        publish()
    }

    // ---------------------------------------------------------------- reliable control delivery
    private fun sendReliable(endpoint: String, payloadIn: Map<String, Any?>, label: String, withinMs: Long = 180_000) {
        val n = node ?: return
        @Suppress("UNCHECKED_CAST")
        val payload = Json.copy(payloadIn) as Map<String, Any?> // frozen: signed bodies must not change while retrying
        background {
            val deadline = System.currentTimeMillis() + withinMs
            var attempt = 0
            var last = ""
            while (System.currentTimeMillis() < deadline && node === n) {
                attempt++
                try {
                    n.sendControl(endpoint, payload, 6000)
                    if (attempt > 1) post { log("$label delivered to ${nicknameFor(endpoint).ifEmpty { endpoint }} (attempt $attempt).") }
                    return@background
                } catch (e: Exception) {
                    last = e.message ?: "error"
                    Thread.sleep(minOf(3000L * attempt, 15_000L))
                }
            }
            post { log("Could not deliver $label to $endpoint: $last") }
        }
    }

    // ---------------------------------------------------------------- chat & traffic
    fun sendChat(endpoint: String, text: String) = post {
        if (text.isBlank()) return@post
        val contact = contacts.firstOrNull { it.str("endpoint") == endpoint } ?: run { platform.onNotice("Chat", "Unknown contact."); return@post }
        val network = contact.str("network")
        if (networks[network]?.str("membership_status", "active") != "active") {
            platform.onNotice("Chat", "Wait until your membership in '$network' is approved."); return@post
        }
        outgoing.add(jsonObj("receiver" to endpoint, "text" to text, "network" to network))
        chats.getOrPut(endpoint) { ArrayList() }.add(ChatMessage(false, text, System.currentTimeMillis()))
        saveSoon(); publish()
    }

    fun markRead(endpoint: String) = post { unread.remove(endpoint); publish() }

    private fun trafficTick() {
        val n = node ?: return
        val item = outgoing.firstOrNull { networks[it.str("network")]?.str("membership_status", "active") == "active" }
        if (item != null) {
            outgoing.remove(item)
            val network = item.str("network")
            val keys = publicKeyMap(network)
            val pool = networkEndpoints(network)
            background {
                try { n.sendOnion(item.str("receiver"), item.str("text"), network, Node.REAL, relayHops, pool, keys) }
                catch (e: Exception) { post { log("Message to ${nicknameFor(item.str("receiver"))} failed: ${e.message}") } }
            }
            return
        }
        if (!coverTraffic) return
        val network = activeNetwork
        if (networks[network]?.str("membership_status", "active") != "active") return
        val receivers = contacts.filter { it.str("network") == network }.map { it.str("endpoint") }
        if (receivers.isEmpty()) return
        val receiver = receivers.random()
        val keys = publicKeyMap(network)
        val pool = networkEndpoints(network)
        background { try { n.sendOnion(receiver, "cover-${System.currentTimeMillis() / 1000}", network, Node.FAKE, relayHops, pool, keys) } catch (_: Exception) {} }
    }

    // ---------------------------------------------------------------- connection test
    fun testConnection(callback: (List<TestLine>) -> Unit) = post {
        val n = node ?: run { callback(listOf(TestLine(false, "The node is not running."))); return@post }
        val network = activeNetwork
        val local = localEndpoint()
        val rank = mapOf("seed" to 0, "trusted" to 1)
        val targets = networks[network]?.let { info -> nodesOf(info).mapNotNull { (k, v) ->
            val ep = endpointOf(v)
            if (ep.isEmpty() || ep == local || samePubkey(v.asMap()?.get("pubkey"), identity.publicPem)) null
            else Triple(rank[roleOf(k, v)] ?: 2, nicknameOf(k, v).ifEmpty { ep }, ep to roleOf(k, v))
        } }?.sortedBy { it.first }?.take(6) ?: emptyList()
        val summary = n.transport.connectivitySummary()
        background {
            val lines = ArrayList<TestLine>()
            lines.add(TestLine(null, "Network: $network"))
            lines.add(TestLine(null, "Internet: $summary"))
            if (targets.isEmpty()) lines.add(TestLine(null, "There are no other members in '$network' yet."))
            for ((_, name, epRole) in targets) {
                val (ep, role) = epRole
                val label = if (role.isNotEmpty()) "$name [$role]" else name
                val probe = n.probe(ep)
                when {
                    !probe.connectOk -> lines.add(TestLine(false, "$label: can't reach it. It may be off, not running MDANetPro, or blocked."))
                    probe.callbackOk -> lines.add(TestLine(true, "$label: connected both ways.\n   you → them: ${probe.route}\n   them → you: ${probe.callbackRoute}"))
                    else -> lines.add(TestLine(false, "$label: you can reach it, but it can't reach you back." +
                        if (!n.transport.isReachable() && n.transport.relays.isEmpty()) " You are behind NAT and have no relay yet." else ""))
                }
            }
            callback(lines)
        }
    }

    // ---------------------------------------------------------------- settings & contacts
    fun updateSettings(name: String? = null, useUpnp: Boolean? = null, publicAddress: String? = null, coverTraffic: Boolean? = null, port: Int? = null) = post {
        name?.trim()?.takeIf { it.isNotEmpty() }?.let { nodeName = it.take(32); upsertLocalNode(); refreshHelloCache() }
        var natChanged = false
        useUpnp?.let { if (it != this.useUpnp) { this.useUpnp = it; natChanged = true } }
        publicAddress?.let { if (it.trim() != this.publicAddress) { this.publicAddress = it.trim(); node?.transport?.manualPublic = this.publicAddress; natChanged = true } }
        coverTraffic?.let { this.coverTraffic = it }
        port?.let { if (it in 1024..65535) this.port = it }
        if (natChanged) startNatCheck(force = true)
        save(); publish()
    }

    fun completeSetup(name: String) = post {
        nodeName = name.trim().take(32).ifEmpty { nodeName }
        setupDone = true
        upsertLocalNode(); refreshHelloCache(); save(); publish()
    }

    fun removeContact(endpoint: String) = post {
        contacts.removeAll { it.str("endpoint") == endpoint }
        chats.remove(endpoint); save(); publish()
    }

    /** For the CLI/tests: a blocking wait helper. */
    fun <T> query(block: Engine.() -> T): T = loop.submit<T> { block() }.get()

    fun networkStatus(name: String): String? = networks[name]?.str("membership_status", "active")
    fun contactEndpoint(nickname: String): String? = contacts.firstOrNull { it.str("nickname") == nickname }?.str("endpoint")
    fun chatText(endpoint: String): String = chats[endpoint]?.joinToString("\n") { it.text } ?: ""
    fun allChatText(): String = chats.values.flatten().joinToString("\n") { it.text }
    fun pendingJoinIds(): List<String> = pendingJoins.keys.toList()
}
