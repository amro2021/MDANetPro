#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import sqlite3
import time

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


class ClientStorage:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.db_path = os.path.join(base_dir, "mda_client_local.db")
        self.key_path = os.path.join(base_dir, ".mda_local_key.bin")
        self._db = sqlite3.connect(self.db_path)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._ensure_schema()
        self._db_key = self._load_or_create_db_key()

    def _ensure_schema(self):
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS identity (
                id INTEGER PRIMARY KEY CHECK(id=1),
                private_key_pem TEXT NOT NULL,
                public_key_pem TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS message_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                direction TEXT NOT NULL,
                network_name TEXT NOT NULL,
                sender TEXT NOT NULL,
                receiver TEXT NOT NULL,
                message_type TEXT NOT NULL,
                route_id TEXT,
                payload_enc TEXT NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        self._db.execute(
            """
            CREATE TABLE IF NOT EXISTS network_snapshot (
                network_name TEXT PRIMARY KEY,
                snapshot_enc TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        self._db.commit()

    def _load_or_create_db_key(self):
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as handle:
                key = handle.read()
            if len(key) == 32:
                return key
        key = Random.new().read(32)
        with open(self.key_path, "wb") as handle:
            handle.write(key)
        return key

    @staticmethod
    def _json_bytes(payload):
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _encrypt_payload(self, payload):
        nonce = Random.new().read(12)
        cipher = AES.new(self._db_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(self._json_bytes(payload))
        body = {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "tag": base64.b64encode(tag).decode("ascii"),
            "ct": base64.b64encode(ciphertext).decode("ascii"),
        }
        return json.dumps(body, separators=(",", ":"))

    def _decrypt_payload(self, payload_enc):
        body = json.loads(payload_enc)
        nonce = base64.b64decode(body["nonce"])
        tag = base64.b64decode(body["tag"])
        ciphertext = base64.b64decode(body["ct"])
        cipher = AES.new(self._db_key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return json.loads(plaintext.decode("utf-8"))

    def get_or_create_identity(self):
        row = self._db.execute(
            "SELECT private_key_pem, public_key_pem FROM identity WHERE id=1"
        ).fetchone()
        if row:
            return {"private_key_pem": row[0], "public_key_pem": row[1]}

        key = RSA.generate(2048)
        private_pem = key.export_key(format="PEM").decode("ascii")
        public_pem = key.publickey().export_key(format="PEM").decode("ascii")
        self._db.execute(
            "INSERT INTO identity (id, private_key_pem, public_key_pem, updated_at) VALUES (1, ?, ?, ?)",
            (private_pem, public_pem, time.time()),
        )
        self._db.commit()
        return {"private_key_pem": private_pem, "public_key_pem": public_pem}

    def log_message(self, direction, network_name, sender, receiver, message_type, route_id, payload):
        payload_enriched = dict(payload or {})
        payload_enriched.update(
            {
                "direction": direction,
                "network_name": network_name,
                "sender": sender,
                "receiver": receiver,
                "message_type": message_type,
                "route_id": route_id or "",
            }
        )
        payload_enc = self._encrypt_payload(payload_enriched)
        network_hash = hashlib.sha256((network_name or "").encode("utf-8")).hexdigest()
        sender_hash = hashlib.sha256((sender or "").encode("utf-8")).hexdigest()
        receiver_hash = hashlib.sha256((receiver or "").encode("utf-8")).hexdigest()
        route_hash = hashlib.sha256((route_id or "").encode("utf-8")).hexdigest() if route_id else ""
        self._db.execute(
            """
            INSERT INTO message_log
            (direction, network_name, sender, receiver, message_type, route_id, payload_enc, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                direction,
                network_hash,
                sender_hash,
                receiver_hash,
                message_type,
                route_hash,
                payload_enc,
                time.time(),
            ),
        )
        self._db.commit()

    def save_network_snapshot(self, network_name, snapshot):
        snapshot_enc = self._encrypt_payload(snapshot)
        self._db.execute(
            """
            INSERT INTO network_snapshot (network_name, snapshot_enc, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(network_name) DO UPDATE SET snapshot_enc=excluded.snapshot_enc, updated_at=excluded.updated_at
            """,
            (network_name, snapshot_enc, time.time()),
        )
        self._db.commit()

    def load_network_snapshot(self, network_name):
        row = self._db.execute(
            "SELECT snapshot_enc FROM network_snapshot WHERE network_name = ?",
            (network_name,),
        ).fetchone()
        if not row:
            return {}
        return self._decrypt_payload(row[0])

    def recent_messages(self, limit=200):
        rows = self._db.execute(
            """
            SELECT id, direction, network_name, sender, receiver, message_type, route_id, payload_enc, created_at
            FROM message_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
        messages = []
        for row in rows:
            payload = {}
            try:
                payload = self._decrypt_payload(row[7])
            except Exception:
                payload = {"text": "<decrypt-failed>", "route": []}
            messages.append(
                {
                    "id": row[0],
                    "direction": payload.get("direction", row[1]),
                    "network_name": payload.get("network_name", row[2]),
                    "sender": payload.get("sender", row[3]),
                    "receiver": payload.get("receiver", row[4]),
                    "message_type": payload.get("message_type", row[5]),
                    "route_id": payload.get("route_id", row[6]),
                    "payload": payload,
                    "created_at": row[8],
                }
            )
        return messages
