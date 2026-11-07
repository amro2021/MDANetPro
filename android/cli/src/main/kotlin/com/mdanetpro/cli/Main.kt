package com.mdanetpro.cli

import com.mdanetpro.core.Engine
import java.io.File
import kotlin.system.exitProcess

/**
 * Headless MDANetPro node built on the same core as the Android app.
 * Used by CI to prove the Kotlin implementation interoperates with the Python app.
 *
 *   member --data D --name N --port P --join HOST:PORT --network NET --expect TEXT --reply-to NICK --reply TEXT
 *   seed   --data D --name N --port P --network NET --greet-prefix TEXT --expect TEXT --wait-member NICK
 */
fun main(args: Array<String>) {
    val mode = args.firstOrNull() ?: usage()
    val opts = args.drop(1).chunked(2).associate { (k, v) -> k.removePrefix("--") to v }
    val stun = opts["stun"]?.split(",")?.filter { it.isNotBlank() }?.map { it.substringBeforeLast(':') to it.substringAfterLast(':').toInt() }
    val checks = LinkedHashMap<String, Boolean>()
    val notices = ArrayList<String>()
    val pending = ArrayList<Engine.JoinRequestView>()
    val engine = Engine(File(opts["data"] ?: "cli-data"), object : Engine.Platform {
        override fun onNotice(title: String, text: String) { synchronized(notices) { notices.add("$title: $text") }; println("NOTICE $title: $text") }
        override fun onJoinRequest(request: Engine.JoinRequestView) { synchronized(pending) { pending.add(request) } }
        override fun onChatMessage(from: String, nickname: String, text: String) = println("CHAT from $nickname: $text")
    }, stun)
    engine.updateSettings(name = opts["name"], port = opts["port"]?.toInt(), coverTraffic = true)
    engine.completeSetup(opts["name"] ?: "kotlin")
    engine.start()
    val network = opts["network"] ?: "Interop"
    val timeout = (opts["timeout"] ?: "120").toLong() * 1000

    fun waitFor(label: String, ms: Long = timeout, cond: () -> Boolean): Boolean {
        val end = System.currentTimeMillis() + ms
        while (System.currentTimeMillis() < end) {
            if (cond()) { checks[label] = true; println("PASS $label"); return true }
            Thread.sleep(200)
        }
        checks[label] = false; println("FAIL $label"); return false
    }

    waitFor("node started", 15_000) { engine.query { node != null } }
    Thread.sleep(3000) // NAT check

    when (mode) {
        "member" -> {
            engine.lookupAndJoin(opts["join"] ?: error("--join required"), network)
            waitFor("joined '$network' (approved by the Python seed)") { engine.query { networkStatus(network) } == "active" }
            val seedNick = opts["reply-to"] ?: "Amr"
            waitFor("seed appears in contacts") { engine.query { contactEndpoint(seedNick) } != null }
            waitFor("received chat from the Python seed") { engine.query { allChatText() }.contains(opts["expect"] ?: "welcome") }
            engine.sendChat(engine.query { contactEndpoint(seedNick) }!!, opts["reply"] ?: "thanks")
            val result = java.util.concurrent.LinkedBlockingQueue<List<Engine.TestLine>>()
            engine.testConnection { result.put(it) }
            val lines = result.poll(60, java.util.concurrent.TimeUnit.SECONDS) ?: emptyList()
            lines.forEach { println("TEST ${it.text}") }
            checks["connection test: connected both ways"] = lines.any { it.ok == true }
            println((if (checks["connection test: connected both ways"] == true) "PASS" else "FAIL") + " connection test: connected both ways")
            Thread.sleep((opts["linger"] ?: "20").toLong() * 1000)
        }
        "seed" -> {
            engine.createNetwork(network, minApprovals = 1)
            File(opts["ready-file"] ?: "seed.ready").writeText(engine.query { localEndpoint() })
            waitFor("got a join request") { synchronized(pending) { pending.isNotEmpty() } }
            val request = synchronized(pending) { pending.first() }
            engine.approveJoin(request.id)
            val member = opts["wait-member"] ?: request.nickname
            waitFor("member '$member' in contacts") { engine.query { contactEndpoint(member) } != null }
            Thread.sleep(3000)
            engine.sendChat(engine.query { contactEndpoint(member) }!!, "${opts["greet-prefix"] ?: "welcome"} $member")
            waitFor("received reply from the Python member") { engine.query { allChatText() }.contains(opts["expect"] ?: "thanks") }
            Thread.sleep((opts["linger"] ?: "20").toLong() * 1000)
        }
        else -> usage()
    }
    engine.query { snapshot().logs }.takeLast(40).forEach { println("LOG $it") }
    val failed = checks.count { !it.value }
    println("RESULT: " + if (failed == 0) "ALL PASSED" else "$failed FAILED")
    engine.shutdown()
    exitProcess(if (failed == 0) 0 else 1)
}

private fun usage(): Nothing {
    println("usage: member|seed --data DIR --name NAME --port PORT ...")
    exitProcess(2)
}
