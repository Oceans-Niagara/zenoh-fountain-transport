import sys
import os
import time
import json
import hashlib
import struct
import zlib
import tempfile
import threading
import queue
import re
import random
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidTag, InvalidSignature
import raptorq
import zenoh

try:
    import cbor2
    cbor_dumps = lambda obj: cbor2.dumps(obj, canonical=True)
    cbor_loads = cbor2.loads
except ImportError:
    import json
    def cbor_dumps(obj):
        def _enc(o):
            if isinstance(o, bytes):
                return {"__b__": o.hex()}
            raise TypeError(f"Type {o.__class__.__name__} not serializable")
        return json.dumps(obj, default=_enc, sort_keys=True).encode()

    def cbor_loads(b):
        def _dec(dct):
            if "__b__" in dct:
                return bytes.fromhex(dct["__b__"])
            return dct
        return json.loads(b.decode(), object_hook=_dec)

MAGIC = b"CYTO"
HEADER_FORMAT = ">4sB3s32sQQIHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
FRAGMENT_META_FORMAT = ">QQHHH"
FRAGMENT_META_SIZE = struct.calcsize(FRAGMENT_META_FORMAT)

HEX_CID_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ACTIVE_FILE_HANDLES = 32

def partition_bytes(total_bytes: int, num_blocks: int) -> List[int]:
    base_size = total_bytes // num_blocks
    remainder = total_bytes - (num_blocks * base_size)
    return [base_size + 1 if i < remainder else base_size for i in range(num_blocks)]

class ZTunnelAEAD:
    def __init__(self, key: Optional[bytes] = None):
        if key is None:
            raw_key = os.environ.get("MESH_PSK")
            if not raw_key:
                raise ValueError("Pre-shared key must be provided or set in MESH_PSK environment variable.")
            self.key = hashlib.sha256(raw_key.encode() if isinstance(raw_key, str) else raw_key).digest()
        else:
            if len(key) != 32:
                raise ValueError("Key must be exactly 32 bytes.")
            self.key = key
        self.cipher = ChaCha20Poly1305(self.key)

    def encrypt(self, plaintext: bytes, aad: Optional[bytes] = None) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.cipher.encrypt(nonce, plaintext, aad)

    def decrypt(self, payload: bytes, aad: Optional[bytes] = None) -> bytes:
        if len(payload) < 28:
            raise ValueError("Payload too short for AEAD")
        return self.cipher.decrypt(payload[:12], payload[12:], aad)

class SecurityManager:
    def __init__(self, node_id: str, key_dir: str = "keys", psk: Optional[bytes] = None):
        self.node_id = node_id.upper()
        self.key_dir = os.path.join(key_dir, self.node_id)
        os.makedirs(self.key_dir, exist_ok=True)
        self.priv_path = os.path.join(self.key_dir, f"{self.node_id}.priv")
        self.seq_path = os.path.join(self.key_dir, "seq_state.json")
        self.signing_key = self._load_or_create_key()
        self.public_key_bytes = self.signing_key.public_key().public_bytes_raw()

        self.ztunnel = ZTunnelAEAD(key=psk)
        self.authorized_keys: Dict[str, bytes] = {self.node_id: self.public_key_bytes}
        self.seq_lock = threading.Lock()
        self.peer_seq_track: Dict[str, int] = self._load_seq_state()
        self.my_seq = self.peer_seq_track.get("__SELF__", 0)

    def _load_or_create_key(self) -> ed25519.Ed25519PrivateKey:
        if os.path.exists(self.priv_path):
            with open(self.priv_path, "rb") as f:
                return ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
        key = ed25519.Ed25519PrivateKey.generate()
        with open(self.priv_path, "wb") as f:
            f.write(key.private_bytes_raw())
        return key

    def _load_seq_state(self) -> Dict[str, int]:
        if os.path.exists(self.seq_path):
            try:
                with open(self.seq_path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_seq_state(self):
        temp_path = f"{self.seq_path}.tmp"
        with open(temp_path, "w") as f:
            json.dump(self.peer_seq_track, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, self.seq_path)

    def authorize_peer(self, peer_id: str, pubkey_bytes: bytes):
        self.authorized_keys[peer_id.upper()] = pubkey_bytes

    def next_sequence(self) -> int:
        with self.seq_lock:
            self.my_seq += 1
            self.peer_seq_track["__SELF__"] = self.my_seq
            self._save_seq_state()
            return self.my_seq

    def sign_command(self, payload: dict) -> bytes:
        payload["sender"] = self.node_id
        payload["seq"] = self.next_sequence()
        payload["ts"] = time.time()
        serialized = cbor_dumps(payload)
        sig = self.signing_key.sign(serialized)
        envelope = {
            "payload": payload,
            "signature": sig,
            "sender": self.node_id
        }
        return self.ztunnel.encrypt(cbor_dumps(envelope))

    def verify_command(self, encrypted_bytes: bytes) -> Optional[dict]:
        try:
            raw = self.ztunnel.decrypt(encrypted_bytes)
            envelope = cbor_loads(raw)
            payload = envelope["payload"]
            sig = envelope["signature"]
            sender = envelope.get("sender", "").upper()

            trusted_pubkey = self.authorized_keys.get(sender)
            if not trusted_pubkey:
                return None

            peer_key = ed25519.Ed25519PublicKey.from_public_bytes(trusted_pubkey)
            peer_key.verify(sig, cbor_dumps(payload))

            seq = payload.get("seq", 0)
            with self.seq_lock:
                last_seq = self.peer_seq_track.get(sender, -1)
                if seq <= last_seq:
                    return None
                self.peer_seq_track[sender] = seq
                self._save_seq_state()

            return payload
        except (InvalidTag, InvalidSignature, Exception):
            return None

class AtomicStorageManager:
    def __init__(self, base_dir: str = "zenoh_storage", sync_batch_size: int = 32):
        self.base_dir = base_dir
        self.sync_batch_size = sync_batch_size
        self._unflushed_counts: Dict[str, int] = {}
        self._active_handles: Dict[str, Any] = {}
        self._queue: queue.Queue = queue.Queue()
        self._stop_event = threading.Event()
        os.makedirs(self.base_dir, exist_ok=True)
        self._worker_thread = threading.Thread(target=self._worker, daemon=True)
        self._worker_thread.start()

    def _job_dir(self, cid: str) -> str:
        if not HEX_CID_REGEX.match(cid):
            raise ValueError(f"Malicious or invalid CID: {cid}")
        d = os.path.join(self.base_dir, cid)
        os.makedirs(d, exist_ok=True)
        return d

    def append_fragment(self, cid: str, fragment_bytes: bytes) -> None:
        self._queue.put((cid, fragment_bytes))

    def _worker(self):
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                cid, fragment_bytes = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue

            if cid not in self._active_handles:
                if len(self._active_handles) >= MAX_ACTIVE_FILE_HANDLES:
                    evict_cid, evict_handle = next(iter(self._active_handles.items()))
                    try:
                        evict_handle.flush()
                        os.fsync(evict_handle.fileno())
                        evict_handle.close()
                    except Exception:
                        pass
                    del self._active_handles[evict_cid]
                    self._unflushed_counts.pop(evict_cid, None)

                frag_path = os.path.join(self._job_dir(cid), "fragments.bin")
                self._active_handles[cid] = open(frag_path, "a+b")
                self._unflushed_counts[cid] = 0

            handle = self._active_handles[cid]
            handle.write(len(fragment_bytes).to_bytes(2, byteorder="big"))
            handle.write(fragment_bytes)

            count = self._unflushed_counts[cid] + 1
            if count >= self.sync_batch_size or self._queue.empty():
                handle.flush()
                os.fsync(handle.fileno())
                self._unflushed_counts[cid] = 0
            else:
                self._unflushed_counts[cid] = count

            self._queue.task_done()

    def atomic_write(self, target_path: str, data: bytes) -> None:
        dir_name = os.path.dirname(target_path) or "."
        os.makedirs(dir_name, exist_ok=True)
        with tempfile.NamedTemporaryFile("wb", dir=dir_name, delete=False) as tf:
            tf.write(data)
            tf.flush()
            os.fsync(tf.fileno())
            temp_name = tf.name
        os.replace(temp_name, target_path)

    def close(self):
        self._stop_event.set()
        if self._worker_thread.is_alive():
            self._worker_thread.join(timeout=2.0)
        for handle in self._active_handles.values():
            try:
                handle.flush()
                os.fsync(handle.fileno())
                handle.close()
            except Exception:
                pass
        self._active_handles.clear()

class MeshOrchestrator:
    def __init__(
        self,
        node_id: str,
        listen_ep: Optional[str] = None,
        connect_ep: Optional[str] = None,
        psk: Optional[bytes] = None,
        drop_rate: float = 0.0
    ):
        self.node_id = node_id.upper()
        self.drop_rate = drop_rate
        self.received_count = 0
        self.dropped_count = 0
        self.security = SecurityManager(self.node_id, psk=psk)
        self.storage = AtomicStorageManager(base_dir=f"storage_{self.node_id}")
        self.lock = threading.RLock()

        self.jobs: Dict[str, dict] = {}
        self.completed_cids: Dict[str, bytes] = {}
        self.latest_telemetry: Dict[str, dict] = {}
        self._subs = []
        self._queryables = []

        config_dict = {"mode": "peer"}
        config_dict["scouting"] = {"multicast": {"enabled": True}}
        if listen_ep:
            config_dict["listen"] = {"endpoints": [listen_ep]}
        if connect_ep:
            config_dict["connect"] = {"endpoints": [connect_ep]}

        config = zenoh.Config.from_json5(json.dumps(config_dict))
        self.session = zenoh.open(config)
        self._register_subscribers()

    def _get_or_create_job(self, cid: str) -> dict:
        with self.lock:
            if cid not in self.jobs:
                self.jobs[cid] = {
                    "frag_hashes": set(),
                    "compressed_size": None,
                    "original_size": None,
                    "symbol_size": None,
                    "num_blocks": None,
                    "block_lengths": [],
                    "decoders": {},
                    "completed_blocks": {}
                }
            return self.jobs[cid]

    def _register_subscribers(self):
        self._subs = [
            self.session.declare_subscriber("course/assets/**", self.asset_listener),
            self.session.declare_subscriber("course/telemetry/**", self.telemetry_listener),
            self.session.declare_subscriber(f"course/command/{self.node_id}", self.command_listener),
            self.session.declare_subscriber("course/command/ALL", self.command_listener),
        ]
        self._queryables = [
            self.session.declare_queryable("course/assets/repair/**", self.repair_query_handler)
        ]

    def add_fragment(self, cid: str, decrypted_payload: bytes) -> bool:
        if len(decrypted_payload) < FRAGMENT_META_SIZE:
            return False

        frag_hash = hashlib.blake2b(decrypted_payload, digest_size=16).digest()
        job = self._get_or_create_job(cid)
        should_rebuild = False

        with self.lock:
            if frag_hash in job["frag_hashes"]:
                return False
            job["frag_hashes"].add(frag_hash)

            cs, osz, sym_sz, n_blocks, sbn = struct.unpack(FRAGMENT_META_FORMAT, decrypted_payload[:FRAGMENT_META_SIZE])
            if job["compressed_size"] is None:
                job["compressed_size"] = cs
                job["original_size"] = osz
                job["symbol_size"] = sym_sz
                job["num_blocks"] = n_blocks
                job["block_lengths"] = partition_bytes(cs, n_blocks)

            if sbn not in job["completed_blocks"]:
                if sbn not in job["decoders"]:
                    job["decoders"][sbn] = raptorq.Decoder.with_defaults(job["block_lengths"][sbn], sym_sz)

                raw_sym = decrypted_payload[FRAGMENT_META_SIZE:]
                res = job["decoders"][sbn].decode(raw_sym)
                if res is not None:
                    job["completed_blocks"][sbn] = res

            if job["num_blocks"] and len(job["completed_blocks"]) == job["num_blocks"]:
                should_rebuild = True

        self.storage.append_fragment(cid, decrypted_payload)

        if should_rebuild:
            self.rebuild_payload(cid)

        return True

    def asset_listener(self, sample):
        parts = str(sample.key_expr).strip("/").split("/")
        if len(parts) < 7 or parts[4] != "map":
            return
        cid = parts[5]
        if not HEX_CID_REGEX.match(cid):
            return

        if self.drop_rate > 0.0 and random.random() < self.drop_rate:
            self.dropped_count += 1
            return

        self.received_count += 1
        try:
            raw = bytes(sample.payload)
            decrypted = self.security.ztunnel.decrypt(raw)
            self.add_fragment(cid, decrypted)
        except Exception:
            return

    def telemetry_listener(self, sample):
        try:
            raw = bytes(sample.payload)
            data = cbor_loads(self.security.ztunnel.decrypt(raw))
            src_id = data.get("id", "Unknown")
            with self.lock:
                self.latest_telemetry[src_id] = data
        except Exception:
            pass

    def command_listener(self, sample):
        raw = bytes(sample.payload)
        cmd = self.security.verify_command(raw)
        if not cmd:
            return

        if cmd.get("action") == "REBUILD":
            self.rebuild_payload(cmd.get("cid"))

    def repair_query_handler(self, query):
        key_str = str(query.key_expr)
        clean_path = key_str.split("?")[0]
        parts = clean_path.strip("/").split("/")
        if len(parts) < 4:
            return
        cid = parts[3]

        need = 10
        target_sbn = 0
        esi_offset = 0
        if hasattr(query, "parameters") and query.parameters:
            params = dict(p.split("=") for p in query.parameters.split(";") if "=" in p)
            need = int(params.get("need", need))
            target_sbn = int(params.get("sbn", target_sbn))
            esi_offset = int(params.get("esi", esi_offset))

        with self.lock:
            cached_compressed = self.completed_cids.get(cid)
            job = self.jobs.get(cid)

        repair_symbols = []
        if cached_compressed and job and job["num_blocks"]:
            blk_lens = job["block_lengths"]
            offsets = [0]
            for l in blk_lens:
                offsets.append(offsets[-1] + l)

            blk_bytes = cached_compressed[offsets[target_sbn] : offsets[target_sbn + 1]]
            sym_sz = job["symbol_size"]
            k_blk = (len(blk_bytes) + sym_sz - 1) // sym_sz
            encoder = raptorq.Encoder.with_defaults(blk_bytes, sym_sz)
            oti = struct.pack(FRAGMENT_META_FORMAT, len(cached_compressed), job["original_size"], sym_sz, job["num_blocks"], target_sbn)
            total_repair = esi_offset + need
            all_pkts = encoder.get_encoded_packets(total_repair)
            fresh = all_pkts[k_blk + esi_offset : k_blk + esi_offset + need]
            repair_symbols = [oti + pkt for pkt in fresh]

        if repair_symbols:
            encrypted = self.security.ztunnel.encrypt(cbor_dumps(repair_symbols))
            query.reply(zenoh.Sample(clean_path, encrypted))

    def fetch_missing_fragments(self, cid: str, target_sbn: int = 0, count_needed: int = 10, esi_offset: int = 0) -> int:
        if not self.session or not HEX_CID_REGEX.match(cid):
            return 0
        added = 0
        query_key = f"course/assets/repair/{cid}?sbn={target_sbn};need={count_needed};esi={esi_offset}"
        try:
            for reply in self.session.get(query_key):
                sample = reply.ok if hasattr(reply, "ok") else None
                if sample:
                    raw_payload = bytes(sample.payload)
                    frags = cbor_loads(self.security.ztunnel.decrypt(raw_payload))
                    for f in frags:
                        if self.add_fragment(cid, f):
                            added += 1
        except Exception:
            pass
        return added

    def broadcast_file(self, fountain_bin_path: str = "fountain_output.bin", delay_sec: float = 0.003) -> bool:
        if not os.path.exists(fountain_bin_path):
            return False

        with open(fountain_bin_path, "rb") as f:
            raw_data = f.read()

        if not raw_data.startswith(MAGIC) or len(raw_data) < HEADER_SIZE:
            return False

        _, _, _, cid_bytes, _, _, _, _, _ = struct.unpack(HEADER_FORMAT, raw_data[:HEADER_SIZE])
        my_cid = cid_bytes.hex()

        fragments = []
        offset = HEADER_SIZE
        while offset + 2 <= len(raw_data):
            pkt_len = int.from_bytes(raw_data[offset:offset+2], byteorder="big")
            offset += 2
            fragments.append(raw_data[offset:offset+pkt_len])
            offset += pkt_len

        topic = f"course/assets/fleet/{self.node_id}/map/{my_cid}/fragment"
        pub = self.session.declare_publisher(
            topic,
            congestion_control=zenoh.CongestionControl.DROP,
            priority=zenoh.Priority.DATA_LOW
        )

        for frag in fragments:
            enc_frag = self.security.ztunnel.encrypt(frag)
            pub.put(enc_frag)
            if delay_sec > 0:
                time.sleep(delay_sec)

        pub.undeclare()
        return True

    def rebuild_payload(self, cid: str) -> Optional[bytes]:
        if not HEX_CID_REGEX.match(cid):
            return None

        with self.lock:
            data = self.jobs.get(cid)
            if not data:
                return None
            num_blocks = data.get("num_blocks")
            orig_size = data.get("original_size")
            completed = dict(data.get("completed_blocks", {}))

        if not num_blocks or not orig_size or len(completed) < num_blocks:
            return None

        if orig_size > MAX_DECOMPRESSED_BYTES:
            return None

        assembled_compressed = b"".join(completed[i] for i in range(num_blocks))

        if hashlib.sha256(assembled_compressed).hexdigest() == cid:
            decomp_obj = zlib.decompressobj()
            decompressed = decomp_obj.decompress(assembled_compressed, max_length=orig_size)
            if decomp_obj.unconsumed_tail or decomp_obj.unused_data or len(decompressed) != orig_size:
                return None
            with self.lock:
                self.completed_cids[cid] = assembled_compressed
            out_path = f"rebuilt_{cid[:8]}.bin"
            self.storage.atomic_write(out_path, decompressed)
            return decompressed

        return None

    def close(self):
        for sub in self._subs:
            try:
                sub.undeclare()
            except Exception:
                pass
        for q in self._queryables:
            try:
                q.undeclare()
            except Exception:
                pass
        self._subs.clear()
        self._queryables.clear()
        self.storage.close()
        if self.session:
            self.session.close()

def main():
    node_id = sys.argv[1].upper() if len(sys.argv) > 1 else "A"
    listen = os.environ.get("ZENOH_LISTEN")
    connect = os.environ.get("ZENOH_CONNECT")
    node = MeshOrchestrator(node_id, listen, connect)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        node.close()

if __name__ == "__main__":
    main()