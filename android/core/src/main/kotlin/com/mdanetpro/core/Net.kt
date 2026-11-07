package com.mdanetpro.core

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Proxy
import java.net.SocketTimeoutException
import java.net.URL
import java.nio.ByteBuffer

/** Endpoint strings: "host:port", "[v6]:port"; key-based node addresses end in ".mda". */
object Endpoint {
    const val VIRTUAL_SUFFIX = ".mda"

    fun split(endpoint: String): Pair<String, Int> {
        val text = endpoint.trim()
        if (text.startsWith("[")) {
            val close = text.indexOf("]:")
            require(close > 0) { "bad endpoint $endpoint" }
            return text.substring(1, close) to text.substring(close + 2).toInt()
        }
        val i = text.lastIndexOf(':')
        require(i > 0) { "bad endpoint $endpoint" }
        return text.substring(0, i) to text.substring(i + 1).toInt()
    }

    fun format(host: String, port: Int) = if (host.contains(':')) "[$host]:$port" else "$host:$port"

    fun isVirtual(endpoint: String) = try {
        split(endpoint).first.endsWith(VIRTUAL_SUFFIX)
    } catch (_: Exception) {
        false
    }

    fun normalize(endpoint: String): String = split(endpoint).let { format(it.first, it.second) }
}

/** Local adapters (cached briefly; NetworkInterface enumeration is slow on some phones). */
object NetInfo {
    data class Iface(val name: String, val ip: String, val prefix: Int, val broadcast: String?)

    private var cacheTime = 0L
    private var cache: List<Iface> = emptyList()
    private var v6Time = 0L
    private var v6Cache: List<String> = emptyList()
    private val virtualHints = listOf("veth", "docker", "vmnet", "vbox", "tun", "tap", "dummy", "rmnet_data") // rmnet_data: shown separately as mobile

    @Synchronized
    fun invalidate() {
        cacheTime = 0; v6Time = 0
    }

    @Synchronized
    fun interfaces(): List<Iface> {
        val now = System.currentTimeMillis()
        if (now - cacheTime < 15_000) return cache
        val result = ArrayList<Iface>()
        try {
            for (nif in NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()) {
                if (!nif.isUp || nif.isLoopback) continue
                for (ia in nif.interfaceAddresses) {
                    val addr = ia.address
                    if (addr is Inet4Address && !addr.isLinkLocalAddress && !addr.isLoopbackAddress) {
                        result.add(Iface(nif.name, addr.hostAddress ?: continue, ia.networkPrefixLength.toInt(), ia.broadcast?.hostAddress))
                    }
                }
            }
        } catch (_: Exception) {
        }
        // Wi-Fi/Ethernet first, mobile/virtual later.
        cache = result.sortedBy { iface -> if (virtualHints.any { iface.name.startsWith(it) }) 1 else 0 }
        cacheTime = now
        return cache
    }

    fun primaryIp(): String {
        localIpFor("8.8.8.8")?.let { return it }
        return interfaces().firstOrNull()?.ip ?: "127.0.0.1"
    }

    /** The local address the OS would use to reach [host] (no packet is sent). */
    fun localIpFor(host: String): String? = try {
        DatagramSocket().use { s ->
            s.connect(InetSocketAddress(host, 80))
            val a = s.localAddress
            if (a == null || a.isAnyLocalAddress || a.isLoopbackAddress) null else a.hostAddress
        }
    } catch (_: Exception) {
        null
    }

    fun cidr(iface: Iface): String {
        val ip = InetAddress.getByName(iface.ip).address
        val mask = if (iface.prefix == 0) 0 else (-1 shl (32 - iface.prefix))
        val value = ByteBuffer.wrap(ip).int and mask
        val net = ByteBuffer.allocate(4).putInt(value).array()
        return "${InetAddress.getByAddress(net).hostAddress}/${iface.prefix}"
    }

    fun inNetwork(ip: String, cidr: String): Boolean = try {
        val (netText, prefixText) = cidr.split("/")
        val prefix = prefixText.toInt()
        val mask = if (prefix == 0) 0 else (-1 shl (32 - prefix))
        val a = ByteBuffer.wrap(InetAddress.getByName(ip).address).int
        val n = ByteBuffer.wrap(InetAddress.getByName(netText).address).int
        (a and mask) == (n and mask)
    } catch (_: Exception) {
        false
    }

    @Synchronized
    fun globalIpv6(): List<String> {
        val now = System.currentTimeMillis()
        if (now - v6Time < 15_000) return v6Cache
        val found = LinkedHashSet<String>()
        try {
            DatagramSocket().use { s ->
                s.connect(InetSocketAddress(InetAddress.getByName("2001:4860:4860::8888"), 80))
                (s.localAddress as? Inet6Address)?.let { if (isGlobal6(it)) found.add(clean6(it)) }
            }
        } catch (_: Exception) {
        }
        try {
            for (nif in NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()) {
                if (!nif.isUp || nif.isLoopback) continue
                for (a in nif.inetAddresses) if (a is Inet6Address && isGlobal6(a)) found.add(clean6(a))
            }
        } catch (_: Exception) {
        }
        v6Cache = found.take(2)
        v6Time = now
        return v6Cache
    }

    private fun clean6(a: Inet6Address) = (a.hostAddress ?: "").substringBefore('%')

    private fun isGlobal6(a: Inet6Address): Boolean {
        val first = a.address[0].toInt() and 0xE0
        return first == 0x20 && !a.isLinkLocalAddress && !a.isSiteLocalAddress && !a.isMulticastAddress
    }

    fun isPublicIpv4(ip: String): Boolean = try {
        val a = InetAddress.getByName(ip)
        val b = a.address
        val first = b[0].toInt() and 0xFF
        val second = b[1].toInt() and 0xFF
        a is Inet4Address && !a.isSiteLocalAddress && !a.isLoopbackAddress && !a.isLinkLocalAddress &&
            !a.isAnyLocalAddress && !a.isMulticastAddress && !(first == 100 && second in 64..127)
    } catch (_: Exception) {
        false
    }

    /** (broadcast address, source ip) pairs for LAN discovery. */
    fun broadcastTargets(): List<Pair<String, String>> {
        val out = LinkedHashSet<Pair<String, String>>()
        for (iface in interfaces()) {
            iface.broadcast?.let { out.add(it to iface.ip) }
            out.add("255.255.255.255" to iface.ip)
        }
        if (out.isEmpty()) out.add("255.255.255.255" to "")
        return out.toList()
    }
}

/** STUN client pieces (RFC 5389), shared with the UDP socket owned by the transport. */
object Stun {
    private const val COOKIE = 0x2112A442

    val defaultServers = listOf("stun.l.google.com" to 19302, "stun.cloudflare.com" to 3478, "stun1.l.google.com" to 19302)

    fun isStun(data: ByteArray, len: Int) = len >= 20 && (data[0].toInt() and 0xC0) == 0 &&
        ByteBuffer.wrap(data, 4, 4).int == COOKIE

    fun request(): Pair<ByteArray, ByteArray> {
        val tx = Crypto.randomBytes(12)
        val buf = ByteBuffer.allocate(20).putShort(1).putShort(0).putInt(COOKIE).put(tx)
        return buf.array() to tx
    }

    /** (transactionId, ip, port) from a binding success response, or null. */
    fun parse(data: ByteArray, len: Int): Triple<ByteArray, String, Int>? {
        if (!isStun(data, len)) return null
        val bb = ByteBuffer.wrap(data, 0, len)
        if (bb.short.toInt() and 0xFFFF != 0x0101) return null
        val length = bb.short.toInt() and 0xFFFF
        bb.int
        val tx = ByteArray(12).also { bb.get(it) }
        var mapped: Pair<String, Int>? = null
        val end = minOf(len, 20 + length)
        var offset = 20
        while (offset + 4 <= end) {
            val type = ByteBuffer.wrap(data, offset, 2).short.toInt() and 0xFFFF
            val alen = ByteBuffer.wrap(data, offset + 2, 2).short.toInt() and 0xFFFF
            val v = offset + 4
            if ((type == 0x20 || type == 0x01) && alen >= 8 && data[v + 1].toInt() == 1) {
                var port = ByteBuffer.wrap(data, v + 2, 2).short.toInt() and 0xFFFF
                val ip = data.copyOfRange(v + 4, v + 8)
                if (type == 0x20) {
                    port = port xor (COOKIE ushr 16)
                    val c = ByteBuffer.allocate(4).putInt(COOKIE).array()
                    for (i in 0..3) ip[i] = (ip[i].toInt() xor c[i].toInt()).toByte()
                }
                if (type == 0x20 || mapped == null) mapped = InetAddress.getByAddress(ip).hostAddress!! to port
            }
            offset += 4 + alen + ((4 - alen % 4) % 4)
        }
        return mapped?.let { Triple(tx, it.first, it.second) }
    }

    fun classify(results: List<Pair<String, Int>?>, localPort: Int): Pair<Pair<String, Int>?, String> {
        val mapped = results.filterNotNull()
        if (mapped.isEmpty()) return null to "unknown"
        val first = mapped[0]
        val nat = when {
            mapped.size >= 2 && (mapped.map { it.first }.toSet().size > 1 || mapped.map { it.second }.toSet().size > 1) -> "symmetric"
            first.second == localPort -> "cone-preserving"
            else -> "cone"
        }
        return first to nat
    }
}

/** Automatic port opening on home routers: NAT-PMP, then UPnP IGD. */
object PortMapper {
    class Mapping(val method: String, val externalIp: String, val tcpPort: Int, val udpPort: Int, val close: () -> Unit) {
        var usable = false
    }

    fun defaultGateway(): String? {
        // Java has no API for this; a /24 guess on the primary interface works for nearly all homes.
        val ip = NetInfo.primaryIp()
        val parts = ip.split(".")
        return if (parts.size == 4) "${parts[0]}.${parts[1]}.${parts[2]}.1" else null
    }

    private fun natpmp(gateway: String, internal: Int, external: Int, tcp: Boolean, lifetime: Int): Pair<String, Int>? = try {
        DatagramSocket().use { s ->
            s.soTimeout = 1500
            val gw = InetAddress.getByName(gateway)
            val req = ByteBuffer.allocate(12).put(0).put(if (tcp) 2 else 1).putShort(0)
                .putShort(internal.toShort()).putShort(external.toShort()).putInt(lifetime).array()
            s.send(DatagramPacket(req, req.size, gw, 5351))
            val buf = ByteArray(64)
            val p = DatagramPacket(buf, buf.size)
            s.receive(p)
            val bb = ByteBuffer.wrap(buf, 0, p.length)
            bb.get(); val op = bb.get().toInt() and 0xFF; val result = bb.short.toInt()
            if (op != 128 + (if (tcp) 2 else 1) || result != 0) return null
            bb.int; bb.short; val mapped = bb.short.toInt() and 0xFFFF
            val ipReq = byteArrayOf(0, 0)
            s.send(DatagramPacket(ipReq, 2, gw, 5351))
            val p2 = DatagramPacket(buf, buf.size)
            s.receive(p2)
            if (p2.length < 12) return null
            InetAddress.getByAddress(buf.copyOfRange(8, 12)).hostAddress!! to mapped
        }
    } catch (_: Exception) {
        null
    }

    private fun http(url: String, body: String? = null, soapAction: String? = null): String {
        val conn = URL(url).openConnection(Proxy.NO_PROXY) as HttpURLConnection
        conn.connectTimeout = 3000; conn.readTimeout = 4000
        if (body != null) {
            conn.requestMethod = "POST"; conn.doOutput = true
            conn.setRequestProperty("Content-Type", "text/xml; charset=\"utf-8\"")
            conn.setRequestProperty("SOAPAction", "\"$soapAction\"")
            conn.outputStream.use { it.write(body.toByteArray()) }
        }
        return conn.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
    }

    private class Gateway(val control: String, val service: String, val localIp: String) {
        fun soap(action: String, args: List<Pair<String, Any>>): String {
            val a = args.joinToString("") { "<${it.first}>${it.second}</${it.first}>" }
            val body = "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" " +
                "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:$action xmlns:u=\"$service\">$a</u:$action></s:Body></s:Envelope>"
            return http(control, body, "$service#$action")
        }

        fun add(port: Int, proto: String, lifetime: Int) = soap("AddPortMapping", listOf(
            "NewRemoteHost" to "", "NewExternalPort" to port, "NewProtocol" to proto, "NewInternalPort" to port,
            "NewInternalClient" to localIp, "NewEnabled" to 1, "NewPortMappingDescription" to "MDANetPro", "NewLeaseDuration" to lifetime))

        fun delete(port: Int, proto: String) = try {
            soap("DeletePortMapping", listOf("NewRemoteHost" to "", "NewExternalPort" to port, "NewProtocol" to proto))
        } catch (_: Exception) {
            ""
        }

        fun externalIp(): String = Regex("<NewExternalIPAddress>\\s*([^<\\s]+)\\s*</NewExternalIPAddress>").find(soap("GetExternalIPAddress", emptyList()))?.groupValues?.get(1) ?: ""
    }

    private fun discoverUpnp(localIp: String): Gateway? {
        val locations = LinkedHashSet<String>()
        try {
            DatagramSocket(InetSocketAddress(localIp, 0)).use { s ->
                s.soTimeout = 500
                for (st in listOf("urn:schemas-upnp-org:device:InternetGatewayDevice:1", "upnp:rootdevice")) {
                    val msg = "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: $st\r\n\r\n".toByteArray()
                    s.send(DatagramPacket(msg, msg.size, InetAddress.getByName("239.255.255.250"), 1900))
                }
                val end = System.currentTimeMillis() + 2000
                val buf = ByteArray(4096)
                while (System.currentTimeMillis() < end) {
                    try {
                        val p = DatagramPacket(buf, buf.size)
                        s.receive(p)
                        Regex("(?im)^location:\\s*(\\S+)").find(String(buf, 0, p.length))?.let { locations.add(it.groupValues[1]) }
                    } catch (_: SocketTimeoutException) {
                    }
                }
            }
        } catch (_: Exception) {
            return null
        }
        val services = listOf("urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANIPConnection:1", "urn:schemas-upnp-org:service:WANPPPConnection:1")
        for (location in locations) {
            val xml = try { http(location) } catch (_: Exception) { continue }
            for (block in Regex("(?s)<service>(.*?)</service>").findAll(xml)) {
                val type = Regex("<serviceType>\\s*([^<]+?)\\s*</serviceType>").find(block.value)?.groupValues?.get(1) ?: continue
                val control = Regex("<controlURL>\\s*([^<]+?)\\s*</controlURL>").find(block.value)?.groupValues?.get(1) ?: continue
                if (type in services) return Gateway(URL(URL(location), control).toString(), type, localIp)
            }
        }
        return null
    }

    fun open(localIp: String, port: Int, lifetime: Int = 3600): Mapping? {
        defaultGateway()?.let { gw ->
            natpmp(gw, port, port, true, lifetime)?.let { tcp ->
                val udp = natpmp(gw, port, port, false, lifetime)
                return Mapping("nat-pmp", tcp.first, tcp.second, udp?.second ?: 0) {
                    natpmp(gw, port, 0, true, 0); natpmp(gw, port, 0, false, 0)
                }
            }
        }
        val gw = discoverUpnp(localIp) ?: return null
        return try {
            gw.add(port, "TCP", lifetime)
            val udp = try { gw.add(port, "UDP", lifetime); port } catch (_: Exception) { 0 }
            val ext = try { gw.externalIp() } catch (_: Exception) { "" }
            Mapping("upnp", ext, port, udp) { gw.delete(port, "TCP"); if (udp != 0) gw.delete(port, "UDP") }
        } catch (_: Exception) {
            null
        }
    }
}

internal fun readAll(input: java.io.InputStream, n: Int): ByteArray? {
    val out = ByteArrayOutputStream(n)
    val buf = ByteArray(minOf(n, 65536).coerceAtLeast(1))
    var remaining = n
    while (remaining > 0) {
        val r = input.read(buf, 0, minOf(buf.size, remaining))
        if (r < 0) return null
        out.write(buf, 0, r)
        remaining -= r
    }
    return out.toByteArray()
}
