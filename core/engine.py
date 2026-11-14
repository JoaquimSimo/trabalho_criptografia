import math
import struct
import zlib
from collections import Counter

from .algorithms import (
    embed_graph_theoretic,
    embed_matrix_hamming,
    extract_graph_theoretic,
    extract_matrix_hamming,
)
from .carriers import load_carrier_bytes
from .crypto import (
    ENVELOPE_SIZE,
    normalize_cipher_params,
    pack_payload,
    prng_seed_from_passphrase,
    unpack_body,
    unpack_header,
)

SHARD_MAGIC = b"SHRD"


def compute_histogram_summary(samples, bins=32):
    step = 256 // bins
    counts = [0] * bins
    for val in samples:
        counts[min(bins - 1, val // step)] += 1
    return counts


def shannon_entropy(samples):
    n = len(samples)
    if n == 0:
        return 0.0
    counts = Counter(samples)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return round(ent, 4)


class SteghideEngine:
    @staticmethod
    def calculate_capacity(num_samples, encoding="graph", total_vaults=1):
        usable_samples = num_samples // max(1, total_vaults)
        if encoding == "matrix":
            raw_bytes = (usable_samples // 3) * 2 // 8
        else:
            raw_bytes = usable_samples // 8
        return max(0, raw_bytes - ENVELOPE_SIZE)

    @classmethod
    def embed(
        cls,
        cover_bytes,
        secret_bytes,
        passphrase,
        filename="segredo.bin",
        algorithm="rijndael-128",
        mode="cbc",
        encoding="graph",
        compress_level=9,
        embed_checksum=True,
        embed_filename=True,
        vault_index=None,
        total_vaults=4,
    ):
        algorithm, mode = normalize_cipher_params(algorithm, mode)
        carrier = load_carrier_bytes(cover_bytes)
        hist_before = compute_histogram_summary(carrier.samples)

        slot_tag = f"vault-{vault_index}-{encoding}" if vault_index is not None else f"primary-{encoding}"
        seed = prng_seed_from_passphrase(passphrase, slot_tag=slot_tag)

        payload = pack_payload(
            secret_data=secret_bytes,
            passphrase=passphrase,
            filename=filename,
            algorithm=algorithm,
            mode=mode,
            compress_level=compress_level,
            embed_checksum=embed_checksum,
            embed_filename=embed_filename,
        )

        if encoding == "matrix":
            stats = embed_matrix_hamming(
                carrier.samples,
                payload,
                seed,
                vault_index=vault_index,
                total_vaults=total_vaults,
            )
        else:
            stats = embed_graph_theoretic(
                carrier.samples,
                payload,
                seed,
                max_radius=carrier.max_radius,
                distance_fn=carrier.distance_fn,
                vault_index=vault_index,
                total_vaults=total_vaults,
            )

        stego_bytes = carrier.rebuild_fn(carrier.samples)
        hist_after = compute_histogram_summary(carrier.samples)

        report = {
            "format": carrier.format_name,
            "description": carrier.description,
            "total_samples": len(carrier.samples),
            "capacity_bytes": cls.calculate_capacity(
                len(carrier.samples), encoding, total_vaults if vault_index is not None else 1
            ),
            "secret_original_bytes": len(secret_bytes),
            "envelope_total_bytes": len(payload),
            "algorithm": algorithm,
            "mode": mode,
            "compressed": compress_level > 0,
            "compression_level": compress_level,
            "vault_index": vault_index,
            "stats": stats,
            "histogram_before": hist_before,
            "histogram_after": hist_after,
        }
        return stego_bytes, report

    @classmethod
    def extract(cls, stego_bytes, passphrase, total_vaults=4):
        carrier = load_carrier_bytes(stego_bytes)

        candidates = [(None, "graph"), (None, "matrix")]
        for v_idx in range(total_vaults):
            candidates.append((v_idx, "graph"))
            candidates.append((v_idx, "matrix"))

        last_err = None
        for vault_index, encoding in candidates:
            slot_tag = f"vault-{vault_index}-{encoding}" if vault_index is not None else f"primary-{encoding}"
            seed = prng_seed_from_passphrase(passphrase, slot_tag=slot_tag)
            try:
                max_cap = cls.calculate_capacity(
                    len(carrier.samples),
                    encoding,
                    total_vaults if vault_index is not None else 1,
                )
                if encoding == "matrix":
                    env_bytes = extract_matrix_hamming(
                        carrier.samples,
                        ENVELOPE_SIZE,
                        seed,
                        vault_index=vault_index,
                        total_vaults=total_vaults,
                        byte_offset=0,
                    )
                else:
                    env_bytes = extract_graph_theoretic(
                        carrier.samples,
                        ENVELOPE_SIZE,
                        seed,
                        vault_index=vault_index,
                        total_vaults=total_vaults,
                        bit_offset=0,
                    )
                header = unpack_header(env_bytes, passphrase)
                body_len = header["body_len"]
                if body_len > max_cap:
                    raise ValueError("Tamanho de carga invalido no cabecalho.")

                if encoding == "matrix":
                    body_bytes = extract_matrix_hamming(
                        carrier.samples,
                        body_len,
                        seed,
                        vault_index=vault_index,
                        total_vaults=total_vaults,
                        byte_offset=ENVELOPE_SIZE,
                    )
                else:
                    body_bytes = extract_graph_theoretic(
                        carrier.samples,
                        body_len,
                        seed,
                        vault_index=vault_index,
                        total_vaults=total_vaults,
                        bit_offset=ENVELOPE_SIZE,
                    )
                unpacked = unpack_body(header, body_bytes)
                meta = {
                    "format": carrier.format_name,
                    "description": carrier.description,
                    "encoding": encoding,
                    "vault_index": vault_index,
                }
                return unpacked, meta
            except Exception as exc:
                last_err = exc
                continue

        raise ValueError(str(last_err) if last_err else "Nao foi possivel extrair dados com a senha informada.")

    @classmethod
    def embed_multi(cls, cover_bytes, messages):
        if not messages or len(messages) > 4:
            raise ValueError("Suporta entre 1 e 4 mensagens por arquivo.")
        total_vaults = 4
        current_bytes = cover_bytes
        vault_reports = []
        used_passphrases = set()

        for idx, msg in enumerate(messages):
            pw = msg["passphrase"]
            if not pw:
                raise ValueError(f"Informe uma senha para a mensagem #{idx + 1}.")
            if pw in used_passphrases:
                raise ValueError("As senhas de cada mensagem oculta precisam ser diferentes.")
            used_passphrases.add(pw)
            current_bytes, rep = cls.embed(
                cover_bytes=current_bytes,
                secret_bytes=msg["secret_bytes"],
                passphrase=pw,
                filename=msg.get("filename", f"msg_{idx + 1}.txt"),
                algorithm=msg.get("algorithm", "rijndael-128"),
                mode=msg.get("mode", "cbc"),
                encoding=msg.get("encoding", "graph"),
                compress_level=msg.get("compress_level", 9),
                vault_index=idx,
                total_vaults=total_vaults,
            )
            vault_reports.append(rep)

        return current_bytes, {"total_vaults": total_vaults, "vaults": vault_reports}

    @classmethod
    def spread_secret(
        cls,
        cover_list,
        secret_bytes,
        passphrase,
        filename="segredo.bin",
        algorithm="rijndael-128",
        encoding="graph",
    ):
        num_shards = len(cover_list)
        if num_shards < 1:
            raise ValueError("Selecione pelo menos 1 arquivo de cobertura.")

        total_crc = zlib.crc32(secret_bytes) & 0xFFFFFFFF
        name_bytes = filename.encode("utf-8")[:255]
        chunk_size = math.ceil(len(secret_bytes) / num_shards) if secret_bytes else 0

        outputs = []
        shard_reports = []
        for idx, (cover_name, cover_bytes) in enumerate(cover_list):
            part = secret_bytes[idx * chunk_size : (idx + 1) * chunk_size]
            shard_blob = (
                struct.pack(">4sHHIB", SHARD_MAGIC, idx, num_shards, total_crc, len(name_bytes))
                + name_bytes
                + part
            )
            stego_bytes, rep = cls.embed(
                cover_bytes=cover_bytes,
                secret_bytes=shard_blob,
                passphrase=passphrase,
                filename=f"parte_{idx + 1}_de_{num_shards}.part",
                algorithm=algorithm,
                encoding=encoding,
            )
            out_name = f"parte_{idx + 1}_{cover_name}"
            outputs.append((out_name, stego_bytes))
            shard_reports.append({"shard_index": idx, "output_file": out_name, "shard_bytes": len(part), "report": rep})

        return outputs, {
            "total_shards": num_shards,
            "original_filename": filename,
            "original_size": len(secret_bytes),
            "shards": shard_reports,
        }

    @classmethod
    def gather_secret(cls, stego_list, passphrase):
        if not stego_list:
            raise ValueError("Nenhum arquivo fornecido para reconstrucao.")
        extracted_shards = {}
        expected_total = None
        expected_crc = None
        original_filename = "reconstruido.bin"

        for stego_bytes in stego_list:
            unpacked, _ = cls.extract(stego_bytes, passphrase)
            blob = unpacked.data
            if len(blob) < 13 or blob[:4] != SHARD_MAGIC:
                raise ValueError("O arquivo extraido nao contem uma parte fragmentada valida.")
            shard_idx, total_shards, total_crc, name_len = struct.unpack_from(">HHIB", blob, 4)
            if len(blob) < 13 + name_len:
                raise ValueError("Cabecalho do fragmento corrompido.")
            if expected_crc is not None and (total_crc != expected_crc or total_shards != expected_total):
                raise ValueError("As partes enviadas pertencem a arquivos diferentes.")
            original_filename = blob[13 : 13 + name_len].decode("utf-8", errors="replace") or "reconstruido.bin"
            part = blob[13 + name_len :]
            expected_total = total_shards
            expected_crc = total_crc
            extracted_shards[shard_idx] = part

        if expected_total is None or len(extracted_shards) < expected_total:
            missing = [i + 1 for i in range(expected_total or 0) if i not in extracted_shards]
            raise ValueError(f"Faltam partes para montar o arquivo original (partes faltando: {missing}).")

        combined = b"".join(extracted_shards[i] for i in range(expected_total))
        actual_crc = zlib.crc32(combined) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError("Falha de CRC32 ao juntar as partes do arquivo.")

        return combined, original_filename, {
            "shards_combined": expected_total,
            "original_filename": original_filename,
            "original_size": len(combined),
            "crc32": f"0x{actual_crc:08X}",
        }

    @classmethod
    def inspect_file(cls, file_bytes, passphrase=None):
        carrier = load_carrier_bytes(file_bytes)
        info = {
            "format": carrier.format_name,
            "description": carrier.description,
            "total_samples": len(carrier.samples),
            "capacity_graph_bytes": cls.calculate_capacity(len(carrier.samples), "graph"),
            "capacity_matrix_bytes": cls.calculate_capacity(len(carrier.samples), "matrix"),
            "entropy_bits_per_sample": shannon_entropy(carrier.samples),
            "histogram": compute_histogram_summary(carrier.samples),
            "metadata": carrier.metadata,
            "embedded": None,
        }
        if passphrase is not None:
            try:
                unpacked, ext_meta = cls.extract(file_bytes, passphrase)
                info["embedded"] = {
                    "filename": unpacked.filename,
                    "size_bytes": unpacked.original_size,
                    "algorithm": unpacked.algorithm,
                    "mode": unpacked.mode,
                    "compressed": unpacked.compressed,
                    "compression_level": unpacked.compression_level,
                    "crc32": f"0x{unpacked.crc32:08X}",
                    "checksum_verified": unpacked.checksum_verified,
                    "encoding": ext_meta["encoding"],
                    "vault_index": ext_meta["vault_index"],
                    "password_protected": bool(passphrase),
                }
            except Exception as exc:
                if passphrase != "":
                    info["embedded_error"] = str(exc)
        else:
            try:
                unpacked, ext_meta = cls.extract(file_bytes, "")
                info["embedded"] = {
                    "filename": unpacked.filename,
                    "size_bytes": unpacked.original_size,
                    "algorithm": unpacked.algorithm,
                    "mode": unpacked.mode,
                    "compressed": unpacked.compressed,
                    "compression_level": unpacked.compression_level,
                    "crc32": f"0x{unpacked.crc32:08X}",
                    "checksum_verified": unpacked.checksum_verified,
                    "encoding": ext_meta["encoding"],
                    "vault_index": ext_meta["vault_index"],
                    "password_protected": False,
                }
            except Exception:
                pass
        return info
