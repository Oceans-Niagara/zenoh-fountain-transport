import os
import struct
import zlib
import hashlib
from typing import List, Tuple
import raptorq

MAGIC = b"CYTO"
VERSION = 3
HEADER_FORMAT = ">4sB3s32sQQIHH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
FRAGMENT_META_FORMAT = ">QQHHH"
FRAGMENT_META_SIZE = struct.calcsize(FRAGMENT_META_FORMAT)

def partition_bytes(total_bytes: int, num_blocks: int) -> List[int]:
    base_size = total_bytes // num_blocks
    remainder = total_bytes - (num_blocks * base_size)
    return [base_size + 1 if i < remainder else base_size for i in range(num_blocks)]

def pack_stream_header(cid_bytes: bytes, comp_size: int, orig_size: int, pkt_count: int, mtu: int, num_blocks: int) -> bytes:
    return struct.pack(HEADER_FORMAT, MAGIC, VERSION, b"\x00\x00\x00", cid_bytes, comp_size, orig_size, pkt_count, mtu, num_blocks)

def encode_bytes(raw_bytes: bytes, symbol_size: int = 512, redundancy: float = 0.50, max_block_symbols: int = 64) -> Tuple[str, bytes, List[bytes], int]:
    compressed = zlib.compress(raw_bytes, level=6)
    comp_size = len(compressed)
    orig_size = len(raw_bytes)
    cid_binary = hashlib.sha256(compressed).digest()
    cid_hex = cid_binary.hex()

    total_symbols = (comp_size + symbol_size - 1) // symbol_size
    num_blocks = max(1, (total_symbols + max_block_symbols - 1) // max_block_symbols)
    block_lengths = partition_bytes(comp_size, num_blocks)

    per_block_packets: List[List[bytes]] = []
    cursor = 0

    for sbn, blk_len in enumerate(block_lengths):
        blk_bytes = compressed[cursor : cursor + blk_len]
        cursor += blk_len
        oti_prefix = struct.pack(FRAGMENT_META_FORMAT, comp_size, orig_size, symbol_size, num_blocks, sbn)

        k_blk = (blk_len + symbol_size - 1) // symbol_size
        repair_count = max(2, int(redundancy * k_blk))

        enc = raptorq.Encoder.with_defaults(blk_bytes, symbol_size)
        raw_pkts = enc.get_encoded_packets(repair_count)
        per_block_packets.append([oti_prefix + pkt for pkt in raw_pkts])

    interleaved_packets: List[bytes] = []
    max_pkts = max(len(p) for p in per_block_packets)
    for col in range(max_pkts):
        for sbn in range(num_blocks):
            if col < len(per_block_packets[sbn]):
                interleaved_packets.append(per_block_packets[sbn][col])

    header = pack_stream_header(cid_binary, comp_size, orig_size, len(interleaved_packets), symbol_size, num_blocks)
    return cid_hex, header, interleaved_packets, num_blocks

def encode_file(source_file: str, output_fountain: str = "fountain_output.bin", mtu: int = 512, redundancy: float = 0.50, max_block_symbols: int = 64) -> dict:
    if not os.path.exists(source_file):
        raise FileNotFoundError(f"Source file not found: {source_file}")

    with open(source_file, "rb") as f:
        raw_bytes = f.read()

    cid_hex, header, packets, num_blocks = encode_bytes(raw_bytes, symbol_size=mtu, redundancy=redundancy, max_block_symbols=max_block_symbols)
    comp_size = struct.unpack(HEADER_FORMAT, header)[4]

    with open(output_fountain, "wb") as f:
        f.write(header)
        for pkt in packets:
            f.write(len(pkt).to_bytes(2, byteorder="big"))
            f.write(pkt)

    return {
        "cid": cid_hex,
        "compressed_size": comp_size,
        "original_size": len(raw_bytes),
        "packets": len(packets),
        "num_blocks": num_blocks,
        "output_path": output_fountain
    }