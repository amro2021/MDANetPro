package com.mdanetpro.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Chat
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.mdanetpro.core.Engine
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Navy = Color(0xFF1F4E79)

@Composable
fun MdaTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = lightColorScheme(primary = Navy, secondary = Color(0xFF2E75B6)), content = content)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppScreen(activity: MainActivity) {
    val app = MdaApp.instance
    val engine = app.engine
    val snap by app.snapshot.collectAsState()
    val snackbar = remember { SnackbarHostState() }
    var notice by remember { mutableStateOf<Pair<String, String>?>(null) }
    LaunchedEffect(Unit) { app.notices.collect { notice = it } }

    val s = snap
    if (s == null) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text("Starting…") }
        return
    }
    notice?.let { (title, text) ->
        AlertDialog(onDismissRequest = { notice = null }, confirmButton = { TextButton(onClick = { notice = null }) { Text("OK") } },
            title = { Text(title) }, text = { Text(text) })
    }
    if (!s.setupDone) { SetupScreen(s, activity); return }

    val chat = activity.openChat.value
    if (chat != null) {
        ChatScreen(s, chat) { activity.openChat.value = null }
        return
    }

    var tab by remember { mutableStateOf(0) }
    Scaffold(
        topBar = {
            TopAppBar(title = { Text("MDANetPro") },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Navy, titleContentColor = Color.White))
        },
        bottomBar = {
            NavigationBar {
                val unread = s.contacts.sumOf { it.unread }
                NavigationBarItem(selected = tab == 0, onClick = { tab = 0 }, label = { Text("Chats") }, icon = {
                    BadgedBox(badge = { if (unread > 0) Badge { Text("$unread") } }) { Icon(Icons.Default.Chat, null) }
                })
                NavigationBarItem(selected = tab == 1, onClick = { tab = 1 }, label = { Text("Networks") }, icon = { Icon(Icons.Default.Hub, null) })
                NavigationBarItem(selected = tab == 2, onClick = { tab = 2 }, label = { Text("Status") }, icon = { Icon(Icons.Default.Info, null) })
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            JoinRequestBanner(s)
            when (tab) {
                0 -> ChatsTab(s) { activity.openChat.value = it; engine.markRead(it) }
                1 -> NetworksTab(s, activity)
                else -> StatusTab(s)
            }
        }
    }
}

// ------------------------------------------------------------------------------- setup
@Composable
fun SetupScreen(s: Engine.Snapshot, activity: MainActivity) {
    val engine = MdaApp.instance.engine
    var name by remember { mutableStateOf(s.settings.name.takeIf { it != "node" } ?: "") }
    var networkName by remember { mutableStateOf("") }
    var step by remember { mutableStateOf(1) }
    Column(Modifier.fillMaxSize().padding(24.dp).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("Welcome to MDANetPro", fontSize = 24.sp, fontWeight = FontWeight.Bold, color = Navy)
        if (step == 1) {
            Text("Step 1 of 2: your name", fontWeight = FontWeight.SemiBold)
            Text("This is the name other people see when you join or create a network.")
            OutlinedTextField(name, { name = it }, label = { Text("Your name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Button(onClick = { engine.updateSettings(name = name); step = 2 }, enabled = name.isNotBlank()) { Text("Next") }
        } else {
            Text("Step 2 of 2: create or join a network", fontWeight = FontWeight.SemiBold)
            OutlinedTextField(networkName, { networkName = it }, label = { Text("New network name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            Button(onClick = { engine.createNetwork(networkName.trim()); engine.completeSetup(name) }, enabled = networkName.isNotBlank()) { Text("Create my network") }
            HorizontalDivider()
            Text("Or join one:")
            OutlinedButton(onClick = { engine.completeSetup(name) }) { Text("Join a network nearby / by address") }
            OutlinedButton(onClick = { engine.completeSetup(name); activity.pickInvite() }) { Text("I have an invite file (.mdar)") }
        }
    }
}

// ------------------------------------------------------------------------------- join requests
@Composable
fun JoinRequestBanner(s: Engine.Snapshot) {
    val engine = MdaApp.instance.engine
    for (r in s.pending) {
        Card(Modifier.fillMaxWidth().padding(8.dp), colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF4CE))) {
            Column(Modifier.padding(12.dp)) {
                Text("${r.nickname} wants to join '${r.network}'", fontWeight = FontWeight.SemiBold)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { engine.approveJoin(r.id) }) { Text("Approve") }
                    OutlinedButton(onClick = { engine.rejectJoin(r.id) }) { Text("Reject") }
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------- chats
@Composable
fun ChatsTab(s: Engine.Snapshot, open: (String) -> Unit) {
    if (s.contacts.isEmpty()) {
        Column(Modifier.padding(24.dp)) {
            Text("No contacts yet.", fontWeight = FontWeight.SemiBold)
            Text("Join or create a network in the Networks tab. Members appear here once you are approved.")
        }
        return
    }
    LazyColumn {
        val groups = s.contacts.groupBy { it.network }
        for ((network, contacts) in groups) {
            item { Text(network.ifEmpty { "Other" }, Modifier.padding(start = 16.dp, top = 12.dp), color = Navy, fontWeight = FontWeight.SemiBold) }
            items(contacts) { c ->
                Row(Modifier.fillMaxWidth().clickable { open(c.endpoint) }.padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(40.dp).background(Navy, CircleShape), contentAlignment = Alignment.Center) {
                        Text(c.nickname.take(1).uppercase(), color = Color.White, fontWeight = FontWeight.Bold)
                    }
                    Column(Modifier.padding(start = 12.dp).weight(1f)) {
                        Text(c.nickname, fontWeight = FontWeight.SemiBold)
                        Text(c.lastText.ifEmpty { "Tap to chat" }, maxLines = 1, overflow = TextOverflow.Ellipsis, color = Color.Gray, fontSize = 13.sp)
                    }
                    if (c.unread > 0) Badge { Text("${c.unread}") }
                }
                HorizontalDivider()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(s: Engine.Snapshot, endpoint: String, back: () -> Unit) {
    val app = MdaApp.instance
    val contact = s.contacts.firstOrNull { it.endpoint == endpoint }
    val messages = s.chats[endpoint] ?: emptyList()
    var text by remember { mutableStateOf("") }
    val listState = rememberLazyListState()
    LaunchedEffect(endpoint) { app.visibleChat = endpoint; app.engine.markRead(endpoint) }
    LaunchedEffect(messages.size) { if (messages.isNotEmpty()) listState.animateScrollToItem(messages.size - 1) }
    androidx.activity.compose.BackHandler { app.visibleChat = null; back() }
    Scaffold(topBar = {
        TopAppBar(title = { Column { Text(contact?.nickname ?: "Chat"); Text(contact?.network ?: "", fontSize = 12.sp) } },
            navigationIcon = { IconButton(onClick = { app.visibleChat = null; back() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back", tint = Color.White) } },
            colors = TopAppBarDefaults.topAppBarColors(containerColor = Navy, titleContentColor = Color.White))
    }) { padding ->
        Column(Modifier.padding(padding).fillMaxSize().imePadding()) {
            LazyColumn(Modifier.weight(1f).fillMaxWidth().padding(horizontal = 8.dp), state = listState) {
                items(messages) { m ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = if (m.incoming) Arrangement.Start else Arrangement.End) {
                        Surface(color = if (m.incoming) Color(0xFFEFEFEF) else Color(0xFFD6E4F2), shape = RoundedCornerShape(12.dp)) {
                            Column(Modifier.padding(10.dp)) {
                                Text(m.text)
                                Text(SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(m.time)), fontSize = 10.sp, color = Color.Gray)
                            }
                        }
                    }
                }
            }
            Row(Modifier.fillMaxWidth().padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(text, { text = it }, Modifier.weight(1f), placeholder = { Text("Message") })
                IconButton(onClick = { app.engine.sendChat(endpoint, text); text = "" }, enabled = text.isNotBlank()) {
                    Icon(Icons.AutoMirrored.Filled.Send, "Send", tint = Navy)
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------- networks
@Composable
fun NetworksTab(s: Engine.Snapshot, activity: MainActivity) {
    val engine = MdaApp.instance.engine
    var showCreate by remember { mutableStateOf(false) }
    var showAddress by remember { mutableStateOf(false) }
    var detail by remember { mutableStateOf<String?>(null) }
    var choice by remember { mutableStateOf<Pair<List<String>, (String) -> Unit>?>(null) }

    detail?.let { name ->
        val net = s.networks.firstOrNull { it.name == name }
        if (net == null) detail = null else { NetworkDetail(net, s, activity) { detail = null }; return }
    }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Your networks", fontWeight = FontWeight.Bold, color = Navy)
        if (s.networks.isEmpty()) Text("None yet.")
        for (n in s.networks) {
            Card(Modifier.fillMaxWidth().clickable { detail = n.name }) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(n.name + if (n.name == s.activeNetwork) "  (active)" else "", fontWeight = FontWeight.SemiBold)
                        Text("${n.members.size} member(s) · you: ${n.myRole} · ${if (n.status == "active") "joined" else "waiting for approval"}", fontSize = 13.sp, color = Color.Gray)
                    }
                }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { showCreate = true }) { Text("Create") }
            OutlinedButton(onClick = { activity.pickInvite() }) { Text("Invite file") }
            OutlinedButton(onClick = { showAddress = true }) { Text("By address") }
        }
        HorizontalDivider()
        Text("Networks nearby", fontWeight = FontWeight.Bold, color = Navy)
        if (s.nearby.isEmpty()) Text("Looking… The owner's device must have MDANetPro open on the same Wi-Fi. Some Wi-Fi networks block this; use 'By address' instead.", fontSize = 13.sp, color = Color.Gray)
        for (item in s.nearby) {
            Card(Modifier.fillMaxWidth()) {
                Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(item.network, fontWeight = FontWeight.SemiBold)
                        Text("${item.owner} (${item.address}) · ${item.type}" + if (item.membership.isNotEmpty()) " · ${item.membership}" else "", fontSize = 13.sp, color = Color.Gray)
                    }
                    if (item.membership != "member") Button(onClick = { engine.joinNearby(item.raw) }) { Text("Join") }
                }
            }
        }
    }
    if (showCreate) CreateNetworkDialog { showCreate = false }
    if (showAddress) AddressDialog(onDismiss = { showAddress = false }) { address ->
        showAddress = false
        engine.lookupAndJoin(address) { names, pick -> choice = names to pick }
    }
    choice?.let { (names, pick) ->
        AlertDialog(onDismissRequest = { choice = null }, title = { Text("Choose a network") }, confirmButton = {}, dismissButton = { TextButton(onClick = { choice = null }) { Text("Cancel") } },
            text = { Column { names.forEach { n -> TextButton(onClick = { choice = null; pick(n) }) { Text(n) } } } })
    }
}

@Composable
fun CreateNetworkDialog(dismiss: () -> Unit) {
    var name by remember { mutableStateOf("") }
    var discoverable by remember { mutableStateOf(true) }
    AlertDialog(onDismissRequest = dismiss, title = { Text("Create network") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(name, { name = it }, label = { Text("Network name") }, singleLine = true)
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(discoverable, { discoverable = it }); Spacer(Modifier.width(8.dp)); Text("Show in Networks Nearby")
                }
                Text("You are the owner (seed). You approve everyone who asks to join.", fontSize = 12.sp, color = Color.Gray)
            }
        },
        confirmButton = { TextButton(enabled = name.isNotBlank(), onClick = { MdaApp.instance.engine.createNetwork(name.trim(), discoverable = discoverable); dismiss() }) { Text("Create") } },
        dismissButton = { TextButton(onClick = dismiss) { Text("Cancel") } })
}

@Composable
fun AddressDialog(onDismiss: () -> Unit, onJoin: (String) -> Unit) {
    var address by remember { mutableStateOf("") }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Join by address") },
        text = {
            Column {
                Text("Type the network owner's address: their public IP for the internet, or their local IP on the same Wi-Fi.", fontSize = 13.sp)
                OutlinedTextField(address, { address = it.trim() }, label = { Text("e.g. 85.10.20.30") }, singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
            }
        },
        confirmButton = { TextButton(enabled = address.isNotBlank(), onClick = { onJoin(address) }) { Text("Find networks") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}

@Composable
fun NetworkDetail(n: Engine.NetworkView, s: Engine.Snapshot, activity: MainActivity, back: () -> Unit) {
    val engine = MdaApp.instance.engine
    var confirmDelete by remember { mutableStateOf(false) }
    androidx.activity.compose.BackHandler { back() }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        TextButton(onClick = back) { Text("← Networks") }
        Text(n.name, fontSize = 22.sp, fontWeight = FontWeight.Bold, color = Navy)
        Text("Type: ${n.type} · You: ${n.myRole} · ${if (n.status == "active") "joined" else "waiting for approval"}")
        if (n.name != s.activeNetwork) OutlinedButton(onClick = { engine.setActiveNetwork(n.name) }) { Text("Make active") }
        Text("Members", fontWeight = FontWeight.SemiBold)
        for (m in n.members) Text("• ${m.nickname}${if (m.isMe) " (you)" else ""} – ${m.role}")
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { activity.shareInvite(n.name) }) { Text("Share invite") }
            OutlinedButton(onClick = { activity.saveInvite(n.name) }) { Text("Save .mdar") }
        }
        OutlinedButton(onClick = { confirmDelete = true }) { Text("Delete network", color = Color(0xFFB00020)) }
    }
    if (confirmDelete) AlertDialog(onDismissRequest = { confirmDelete = false }, title = { Text("Delete '${n.name}'?") },
        text = { Text("This removes the network and its contacts from this device.") },
        confirmButton = { TextButton(onClick = { engine.deleteNetwork(n.name); confirmDelete = false; back() }) { Text("Delete") } },
        dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } })
}

// ------------------------------------------------------------------------------- status
@Composable
fun StatusTab(s: Engine.Snapshot) {
    val engine = MdaApp.instance.engine
    var results by remember { mutableStateOf<List<Engine.TestLine>?>(null) }
    var testing by remember { mutableStateOf(false) }
    var name by remember(s.settings.name) { mutableStateOf(s.settings.name) }
    var publicAddress by remember(s.settings.publicAddress) { mutableStateOf(s.settings.publicAddress) }
    var showLog by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp)) {
                Text(if (s.running) "Node running" else "Node stopped", fontWeight = FontWeight.Bold, color = if (s.running) Color(0xFF2E7D32) else Color.Red)
                Text("Local address: ${s.host}", fontSize = 13.sp)
                Text("Internet: ${s.internet}", fontSize = 13.sp)
                Text("Active network: ${s.activeNetwork.ifEmpty { "–" }}", fontSize = 13.sp)
            }
        }
        Button(onClick = { testing = true; results = null; engine.testConnection { r -> results = r; testing = false } }, enabled = s.running && !testing) {
            Text(if (testing) "Testing…" else "Test connection")
        }
        results?.let { lines ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    for (l in lines) Text((when (l.ok) { true -> "✅ "; false -> "❌ "; null -> "" }) + l.text, fontSize = 13.sp)
                }
            }
        }
        HorizontalDivider()
        Text("Settings", fontWeight = FontWeight.Bold, color = Navy)
        OutlinedTextField(name, { name = it }, label = { Text("Your name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(publicAddress, { publicAddress = it }, label = { Text("Public address of a port-forward (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(s.settings.useUpnp, { engine.updateSettings(useUpnp = it) }); Spacer(Modifier.width(8.dp)); Text("Open router port automatically (UPnP)")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Switch(s.settings.coverTraffic, { engine.updateSettings(coverTraffic = it) }); Spacer(Modifier.width(8.dp))
            Column { Text("Cover traffic"); Text("Hides when you really send, but uses more data and battery.", fontSize = 12.sp, color = Color.Gray) }
        }
        Button(onClick = { engine.updateSettings(name = name, publicAddress = publicAddress) }) { Text("Save settings") }
        HorizontalDivider()
        TextButton(onClick = { showLog = !showLog }) { Text(if (showLog) "Hide log" else "Show log") }
        if (showLog) Text(s.logs.takeLast(80).joinToString("\n"), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        Spacer(Modifier.height(24.dp))
    }
}
