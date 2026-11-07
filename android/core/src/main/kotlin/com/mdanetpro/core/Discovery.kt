package com.mdanetpro.core

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap

/** "Networks Nearby": UDP broadcast announcements on port 50405 (same format as mda_discovery.py). */
class Discovery(private val ownEndpoint: () -> String, val port: Int = PORT) {
    companion object {
        const val PORT = 50405
        const val MAGIC = "MDANetPro/announce/1"
        const val STALE_MS = 12_000L
    }

    private var socket: DatagramSocket? = null
    @Volatile private var running = false
    private val seen = ConcurrentHashMap<String, MutableMap<String, Any?>>()
    var listenError = ""

    fun start() {
        if (running) return
        running = true
        try {
            val s = DatagramSocket(null)
            s.reuseAddress = true
            s.broadcast = true
            s.bind(InetSocketAddress(port))
            s.soTimeout = 1000
            socket = s
            thread("mda-discovery") { loop(s) }
        } catch (e: Exception) {
            listenError = e.message ?: "error"
        }
    }

    fun stop() {
        running = false
        socket?.close()
        socket = null
    }

    private fun loop(s: DatagramSocket) {
        val buf = ByteArray(65535)
        while (running && !s.isClosed) {
            val p = DatagramPacket(buf, buf.size)
            try { s.receive(p) } catch (_: SocketTimeoutException) { continue } catch (_: Exception) { break }
            handle(String(buf, 0, p.length, Charsets.UTF_8), p.address.hostAddress ?: "")
        }
    }

    fun handle(text: String, from: String) {
        val msg = try { Json.parseObject(text) } catch (_: Exception) { return }
        if (msg["magic"] != MAGIC) return
        val network = msg.str("network").trim()
        val endpoint = msg.str("endpoint").trim()
        if (network.isEmpty() || endpoint.isEmpty() || endpoint == ownEndpoint()) return
        msg["seen_from"] = from
        msg["last_seen"] = System.currentTimeMillis()
        seen["$network|$endpoint"] = msg
    }

    fun nearby(): List<Map<String, Any?>> {
        val cutoff = System.currentTimeMillis() - STALE_MS
        seen.entries.removeIf { ((it.value["last_seen"] as? Long) ?: 0L) < cutoff }
        return seen.values.sortedWith(compareBy({ it.str("network").lowercase() }, { it.str("endpoint") }))
    }

    fun announce(items: List<Map<String, Any?>>) {
        if (items.isEmpty()) return
        for ((bcast, source) in NetInfo.broadcastTargets()) {
            try {
                DatagramSocket(null).use { s ->
                    s.broadcast = true
                    s.bind(if (source.isNotEmpty()) InetSocketAddress(source, 0) else InetSocketAddress(0))
                    for (item in items) {
                        val body = Json.bytes(LinkedHashMap(item).apply { put("magic", MAGIC) })
                        if (body.size > 1400) continue
                        s.send(DatagramPacket(body, body.size, InetAddress.getByName(bcast), port))
                    }
                }
            } catch (_: Exception) {}
        }
    }
}
