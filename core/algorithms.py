import hashlib
import struct
from collections import Counter, defaultdict


class DeterministicPRNG:
    def __init__(self, seed):
        self.seed = seed
        self.counter = 0
        self.buffer = b""
        self.offset = 0

    def next_uint32(self):
        if self.offset + 4 > len(self.buffer):
            self.buffer = hashlib.sha256(self.seed + struct.pack(">Q", self.counter)).digest()
            self.counter += 1
            self.offset = 0
        val = struct.unpack_from(">I", self.buffer, self.offset)[0]
        self.offset += 4
        return val

    def select_positions(self, pool, count):
        if count > len(pool):
            raise ValueError(
                f"Capacidade insuficiente no arquivo de cobertura: necessario {count} bits, disponivel {len(pool)}."
            )
        arr = list(pool)
        n = len(arr)
        selected = []
        for i in range(count):
            j = i + (self.next_uint32() % (n - i))
            arr[i], arr[j] = arr[j], arr[i]
            selected.append(arr[i])
        return selected


def get_vault_pool(total_samples, vault_index=None, total_vaults=4):
    if vault_index is None:
        return list(range(total_samples))
    return [i for i in range(total_samples) if (i % total_vaults) == vault_index]


def bytes_to_bits(data):
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def bits_to_bytes(bits):
    out = bytearray(len(bits) // 8)
    for idx in range(len(out)):
        val = 0
        base = idx * 8
        for b in range(8):
            val = (val << 1) | bits[base + b]
        out[idx] = val
    return bytes(out)


def build_neighbor_table(max_radius, distance_fn):
    table = []
    for v in range(256):
        target_bit = 1 - (v & 1)
        candidates = [
            (distance_fn(v, c), abs(v - c), c)
            for c in range(256)
            if (c & 1) == target_bit and distance_fn(v, c) <= max_radius
        ]
        candidates.sort()
        table.append([c for _, _, c in candidates])
    return table


def embed_graph_theoretic(
    samples,
    payload,
    seed,
    max_radius,
    distance_fn,
    vault_index=None,
    total_vaults=4,
):
    bits = bytes_to_bits(payload)
    pool = get_vault_pool(len(samples), vault_index, total_vaults)
    prng = DeterministicPRNG(seed)
    positions = prng.select_positions(pool, len(bits))
    used_set = set(positions)

    hist_before = Counter(samples)
    neighbors_of = build_neighbor_table(max_radius, distance_fn)

    # Separa posicoes onde o LSB precisa mudar (0->1 e 1->0) e tenta trocar pares
    # vizinhos entre si para manter a contagem de cada byte no histograma.
    need_one = []
    need_zero = []
    unchanged_count = 0

    for pos, target_bit in zip(positions, bits):
        if (samples[pos] & 1) == target_bit:
            unchanged_count += 1
        elif target_bit == 1:
            need_one.append(pos)
        else:
            need_zero.append(pos)

    zero_by_val = defaultdict(list)
    for pos in need_zero:
        zero_by_val[samples[pos]].append(pos)

    unmatched_one = []
    swapped_pairs = 0

    for pos1 in need_one:
        v1 = samples[pos1]
        matched_pos0 = None
        for candidate_val in neighbors_of[v1]:
            if zero_by_val[candidate_val]:
                matched_pos0 = zero_by_val[candidate_val].pop()
                break
        if matched_pos0 is not None:
            samples[pos1], samples[matched_pos0] = samples[matched_pos0], samples[pos1]
            swapped_pairs += 1
        else:
            unmatched_one.append(pos1)

    remaining_mismatched = unmatched_one[:]
    for pos_list in zero_by_val.values():
        remaining_mismatched.extend(pos_list)

    unused_by_val = defaultdict(list)
    for idx in pool:
        if idx not in used_set:
            unused_by_val[samples[idx]].append(idx)

    pool_swaps = 0
    direct_overwrites = 0

    for pos in remaining_mismatched:
        v = samples[pos]
        swap_partner = None
        for candidate_val in neighbors_of[v]:
            if unused_by_val[candidate_val]:
                swap_partner = unused_by_val[candidate_val].pop()
                break
        if swap_partner is not None:
            samples[pos], samples[swap_partner] = samples[swap_partner], samples[pos]
            pool_swaps += 1
        else:
            samples[pos] ^= 1
            direct_overwrites += 1

    hist_after = Counter(samples)
    l1_diff = sum(abs(hist_before[k] - hist_after[k]) for k in range(256))
    preservation_pct = 100.0 * (1.0 - l1_diff / max(1, 2 * len(samples)))

    return {
        "encoding": "graph",
        "bits_embedded": len(bits),
        "unchanged_positions": unchanged_count,
        "direct_pair_swaps": swapped_pairs,
        "pool_swaps": pool_swaps,
        "overwrites": direct_overwrites,
        "histogram_preservation_pct": round(preservation_pct, 4),
    }


def extract_graph_theoretic(
    samples,
    num_bytes,
    seed,
    vault_index=None,
    total_vaults=4,
    bit_offset=0,
):
    if num_bytes <= 0:
        return b""
    total_bits_needed = (bit_offset + num_bytes) * 8
    pool = get_vault_pool(len(samples), vault_index, total_vaults)
    prng = DeterministicPRNG(seed)
    positions = prng.select_positions(pool, total_bits_needed)
    slice_positions = positions[bit_offset * 8 : total_bits_needed]
    bits = [samples[pos] & 1 for pos in slice_positions]
    return bits_to_bytes(bits)


def embed_matrix_hamming(
    samples,
    payload,
    seed,
    vault_index=None,
    total_vaults=4,
):
    # Matrix Encoding Hamming (1, 3, 2): grava 2 bits a cada 3 amostras mudando no maximo 1 bit.
    bits = bytes_to_bits(payload)
    num_blocks = len(bits) // 2
    pool = get_vault_pool(len(samples), vault_index, total_vaults)
    prng = DeterministicPRNG(seed)
    positions = prng.select_positions(pool, num_blocks * 3)

    hist_before = Counter(samples)
    modified_samples = 0
    unchanged_blocks = 0

    for blk in range(num_blocks):
        p1, p2, p3 = positions[blk * 3 : blk * 3 + 3]
        b1, b2, b3 = samples[p1] & 1, samples[p2] & 1, samples[p3] & 1
        x1, x2 = bits[blk * 2], bits[blk * 2 + 1]
        c1 = b1 ^ b3
        c2 = b2 ^ b3
        syndrome = ((c2 ^ x2) << 1) | (c1 ^ x1)
        if syndrome == 0:
            unchanged_blocks += 1
        elif syndrome == 1:
            samples[p1] ^= 1
            modified_samples += 1
        elif syndrome == 2:
            samples[p2] ^= 1
            modified_samples += 1
        elif syndrome == 3:
            samples[p3] ^= 1
            modified_samples += 1

    hist_after = Counter(samples)
    l1_diff = sum(abs(hist_before[k] - hist_after[k]) for k in range(256))
    preservation_pct = 100.0 * (1.0 - l1_diff / max(1, 2 * len(samples)))

    return {
        "encoding": "matrix",
        "bits_embedded": len(bits),
        "blocks_total": num_blocks,
        "unchanged_blocks": unchanged_blocks,
        "modified_samples": modified_samples,
        "efficiency": round(len(bits) / max(1, modified_samples), 3),
        "histogram_preservation_pct": round(preservation_pct, 4),
    }


def extract_matrix_hamming(
    samples,
    num_bytes,
    seed,
    vault_index=None,
    total_vaults=4,
    byte_offset=0,
):
    if num_bytes <= 0:
        return b""
    total_bytes = byte_offset + num_bytes
    total_blocks = total_bytes * 4
    pool = get_vault_pool(len(samples), vault_index, total_vaults)
    prng = DeterministicPRNG(seed)
    positions = prng.select_positions(pool, total_blocks * 3)

    start_block = byte_offset * 4
    bits = []
    for blk in range(start_block, total_blocks):
        p1, p2, p3 = positions[blk * 3 : blk * 3 + 3]
        b1, b2, b3 = samples[p1] & 1, samples[p2] & 1, samples[p3] & 1
        bits.append(b1 ^ b3)
        bits.append(b2 ^ b3)
    return bits_to_bytes(bits)
