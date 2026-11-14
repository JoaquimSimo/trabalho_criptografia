import hashlib
import hmac
import os
import struct
import zlib

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

HEADER_MAGIC = b"STGH"
ENVELOPE_SIZE = 32

SUPPORTED_ALGORITHMS = {
    "rijndael-128": {"code": 1, "modes": ["cbc", "ctr"], "default_mode": "cbc", "key_len": 16},
    "aes-256": {"code": 2, "modes": ["cbc", "ctr"], "default_mode": "cbc", "key_len": 32},
    "chacha20": {"code": 3, "modes": ["stream"], "default_mode": "stream", "key_len": 32},
    "none": {"code": 0, "modes": ["none"], "default_mode": "none", "key_len": 16},
}

CODE_TO_ALGO = {v["code"]: (k, v["default_mode"]) for k, v in SUPPORTED_ALGORITHMS.items()}


class UnpackedPayload:
    def __init__(
        self,
        data,
        filename,
        has_filename,
        algorithm,
        mode,
        compressed,
        compression_level,
        checksum_verified,
        crc32,
        original_size,
    ):
        self.data = data
        self.filename = filename
        self.has_filename = has_filename
        self.algorithm = algorithm
        self.mode = mode
        self.compressed = compressed
        self.compression_level = compression_level
        self.checksum_verified = checksum_verified
        self.crc32 = crc32
        self.original_size = original_size


def normalize_cipher_params(algorithm, mode=None):
    algo = (algorithm or "rijndael-128").lower().strip()
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Algoritmo nao suportado: {algo}")
    spec = SUPPORTED_ALGORITHMS[algo]
    if not mode or algo in ("none", "chacha20"):
        return algo, spec["default_mode"]
    m = mode.lower().strip()
    if m not in spec["modes"]:
        raise ValueError(f"Modo '{m}' invalido para {algo}. Modos aceitos: {', '.join(spec['modes'])}")
    return algo, m


def derive_keys(passphrase, salt):
    raw = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 10000, dklen=64)
    return raw[:32], raw[32:]


def prng_seed_from_passphrase(passphrase, slot_tag="primary"):
    return hmac.new(
        passphrase.encode("utf-8"),
        f"steghide-prng-{slot_tag}".encode("utf-8"),
        hashlib.sha256,
    ).digest()


def keystream_xor(data, key, nonce):
    out = bytearray(len(data))
    block_idx = 0
    offset = 0
    while offset < len(data):
        counter_bytes = struct.pack(">Q", block_idx)
        digest = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
        chunk = min(32, len(data) - offset)
        for i in range(chunk):
            out[offset + i] = data[offset + i] ^ digest[i]
        offset += chunk
        block_idx += 1
    return bytes(out)


def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    if not data or len(data) % 16 != 0:
        raise ValueError("Tamanho de bloco invalido na descriptografia")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding PKCS#7 invalido (verifique a senha)")
    return data[:-pad_len]


def cipher_transform(data, key, iv, algorithm, mode, encrypt):
    if algorithm == "none":
        return data

    if not HAS_CRYPTOGRAPHY:
        return keystream_xor(data, key, iv)

    if algorithm in ("rijndael-128", "aes-256"):
        klen = 16 if algorithm == "rijndael-128" else 32
        aes_key = key[:klen]
        if mode == "cbc":
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            if encrypt:
                encryptor = cipher.encryptor()
                return encryptor.update(pkcs7_pad(data, 16)) + encryptor.finalize()
            decryptor = cipher.decryptor()
            return pkcs7_unpad(decryptor.update(data) + decryptor.finalize())
        if mode == "ctr":
            cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
            ctx = cipher.encryptor() if encrypt else cipher.decryptor()
            return ctx.update(data) + ctx.finalize()
        raise ValueError(f"Modo invalido: {mode}")

    if algorithm == "chacha20":
        cipher = Cipher(algorithms.ChaCha20(key[:32], iv), mode=None)
        ctx = cipher.encryptor() if encrypt else cipher.decryptor()
        return ctx.update(data) + ctx.finalize()

    raise ValueError(f"Algoritmo nao suportado: {algorithm}")


def pack_payload(
    secret_data,
    passphrase,
    filename="segredo.bin",
    algorithm="rijndael-128",
    mode="cbc",
    compress_level=9,
    embed_checksum=True,
    embed_filename=True,
):
    algorithm, mode = normalize_cipher_params(algorithm, mode)

    crc = zlib.crc32(secret_data) & 0xFFFFFFFF if embed_checksum else 0
    name_bytes = os.path.basename(filename).encode("utf-8")[:65535] if embed_filename else b""

    inner = name_bytes + secret_data
    if compress_level > 0:
        compressed_body = zlib.compress(inner, level=min(9, max(1, int(compress_level))))
        is_compressed = True
    else:
        compressed_body = inner
        is_compressed = False

    # Cabecalho de 32 bytes: 16B de IV aleatorio + 16B de metadados cifrados
    iv = os.urandom(16)
    enc_key, hdr_key = derive_keys(passphrase, iv)

    encrypted_body = cipher_transform(compressed_body, enc_key, iv, algorithm, mode, encrypt=True)

    flags = (
        (1 if is_compressed else 0)
        | (2 if embed_checksum else 0)
        | (4 if embed_filename else 0)
        | ((int(compress_level) & 0x0F) << 4)
    )
    algo_code = SUPPORTED_ALGORITHMS[algorithm]["code"] | (0x80 if mode == "ctr" else 0x00)

    raw_meta = struct.pack(
        ">4sIIBBH",
        HEADER_MAGIC,
        len(encrypted_body),
        crc,
        flags,
        algo_code,
        len(name_bytes),
    )
    encrypted_meta = keystream_xor(raw_meta, hdr_key, iv)
    return iv + encrypted_meta + encrypted_body


def unpack_header(envelope, passphrase):
    if len(envelope) != ENVELOPE_SIZE:
        raise ValueError("Tamanho de cabecalho invalido")
    iv = envelope[:16]
    encrypted_meta = envelope[16:32]
    enc_key, hdr_key = derive_keys(passphrase, iv)
    raw_meta = keystream_xor(encrypted_meta, hdr_key, iv)
    magic, body_len, crc, flags, algo_byte, name_len = struct.unpack(">4sIIBBH", raw_meta)
    if magic != HEADER_MAGIC:
        raise ValueError("Senha incorreta ou o arquivo nao contem dados ocultos.")

    base_code = algo_byte & 0x7F
    if base_code not in CODE_TO_ALGO:
        raise ValueError("Algoritmo desconhecido no cabecalho.")
    algo_name, default_mode = CODE_TO_ALGO[base_code]
    mode = "ctr" if (algo_byte & 0x80) and algo_name in ("rijndael-128", "aes-256") else default_mode

    return {
        "iv": iv,
        "enc_key": enc_key,
        "body_len": body_len,
        "crc32": crc,
        "compressed": bool(flags & 1),
        "has_checksum": bool(flags & 2),
        "has_filename": bool(flags & 4),
        "compression_level": (flags >> 4) & 0x0F,
        "algorithm": algo_name,
        "mode": mode,
        "name_len": name_len,
    }


def unpack_body(header, encrypted_body):
    decrypted = cipher_transform(
        encrypted_body,
        header["enc_key"],
        header["iv"],
        header["algorithm"],
        header["mode"],
        encrypt=False,
    )
    inner = zlib.decompress(decrypted) if header["compressed"] else decrypted
    name_len = header["name_len"]
    has_fname = bool(header["has_filename"] and name_len > 0)
    if has_fname:
        if name_len > len(inner):
            raise ValueError("Dados corrompidos ao ler o nome do arquivo.")
        filename = os.path.basename(inner[:name_len].decode("utf-8", errors="replace")) or "arquivo_extraido.bin"
        secret_data = inner[name_len:]
    else:
        filename = "arquivo_extraido.bin"
        secret_data = inner

    checksum_ok = True
    if header["has_checksum"]:
        actual_crc = zlib.crc32(secret_data) & 0xFFFFFFFF
        checksum_ok = actual_crc == header["crc32"]
        if not checksum_ok:
            raise ValueError("Erro de integridade: o CRC32 dos dados extraidos nao bate com o original.")

    return UnpackedPayload(
        data=secret_data,
        filename=filename,
        has_filename=has_fname,
        algorithm=header["algorithm"],
        mode=header["mode"],
        compressed=header["compressed"],
        compression_level=header["compression_level"],
        checksum_verified=checksum_ok,
        crc32=header["crc32"],
        original_size=len(secret_data),
    )
