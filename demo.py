import os
import sys
import time
import random
import hashlib
import zlib
import shutil

from encode import encode_file
from meshorchestrator import MeshOrchestrator

SHARED_PSK = hashlib.sha256(b"field_mesh_deployment_key_alpha").digest()
MAP_SRC = "synthetic_course_map.bin"
FOUNTAIN_BIN = "fountain_output.bin"

def generate_synthetic_course_map(points: int = 2500) -> bytes:
    random.seed(42)
    entries = []
    base_lat, base_lon = 36.5684, -121.9504
    hazards = [b"ROUGH", b"BUNKER", b"FAIRWAY", b"GREEN", b"WATER"]
    for i in range(points):
        lat = base_lat + random.gauss(0, 0.005)
        lon = base_lon + random.gauss(0, 0.005)
        elev = 18.5 + (random.random() * 12.0)
        h = hazards[i % len(hazards)]
        entries.append(f"POINT:{i:04d}|LAT:{lat:.7f}|LON:{lon:.7f}|ELEV:{elev:.2f}|HZ:{h.decode()};".encode())
    return b"".join(entries)

def run_demo():
    for d in ["keys", "storage_BASE", "storage_MOWER_1"]:
        if os.path.exists(d):
            shutil.rmtree(d)

    raw_map = generate_synthetic_course_map(2500)
    with open(MAP_SRC, "wb") as f:
        f.write(raw_map)

    enc_meta = encode_file(MAP_SRC, output_fountain=FOUNTAIN_BIN, mtu=512, redundancy=0.50, max_block_symbols=32)
    cid = enc_meta["cid"]

    print(f"Original Size   : {enc_meta['original_size']:,} bytes")
    print(f"Compressed Size : {enc_meta['compressed_size']:,} bytes")
    print(f"CID (SHA-256)   : {cid}")
    print(f"RFC 6330 Blocks : {enc_meta['num_blocks']} Source Blocks (Interleaved)")
    print(f"Total Droplets  : {enc_meta['packets']}")

    base = MeshOrchestrator("BASE", psk=SHARED_PSK)
    mower = MeshOrchestrator("MOWER_1", psk=SHARED_PSK, drop_rate=0.25)

    base.security.authorize_peer("MOWER_1", mower.security.public_key_bytes)
    mower.security.authorize_peer("BASE", base.security.public_key_bytes)

    time.sleep(1.0)

    print("\nStreaming interleaved droplets across Zenoh (simulating 25% radio drop)...")
    t_start = time.time()
    base.broadcast_file(FOUNTAIN_BIN, delay_sec=0.003)
    t_end = time.time()

    time.sleep(1.0)

    print(f"\nIngested: {mower.received_count}, Dropped: {mower.dropped_count}")
    print(f"Broadcast Duration: {t_end - t_start:.2f}s")

    job = mower.jobs.get(cid, {})
    solved = len(job.get("completed_blocks", {}))
    print(f"Solved Blocks: {solved} of {enc_meta['num_blocks']}")

    t0 = time.perf_counter()
    rebuilt = mower.rebuild_payload(cid)
    if rebuilt:
        solve_ms = (time.perf_counter() - t0) * 1000
        print(f"Assembly & Hash Time: {solve_ms:.2f} ms")

        test_cmd = {"action": "ENGAGE_CUTTER", "target": "MOWER_1"}
        signed = base.security.sign_command(test_cmd)
        verified = mower.security.verify_command(signed)
        if verified and verified.get("action") == "ENGAGE_CUTTER":
            print("Security: SUCCESS (Ed25519 whitelisted command verified)")
            print("Status: SUCCESS (Multi-block bit-exact match, 0 retransmissions)")
        else:
            print("Security: FAILURE")
            print("Status: FAILURE")
    else:
        print("Status: FAILURE (Incomplete blocks or hash mismatch)")

    base.close()
    mower.close()

    for f in [MAP_SRC, FOUNTAIN_BIN]:
        if os.path.exists(f):
            os.remove(f)

if __name__ == "__main__":
    run_demo()