import math
import struct
import zlib


class CarrierData:
    def __init__(self, format_name, description, samples, max_radius, distance_fn, rebuild_fn, metadata):
        self.format_name = format_name
        self.description = description
        self.samples = samples
        self.max_radius = max_radius
        self.distance_fn = distance_fn
        self.rebuild_fn = rebuild_fn
        self.metadata = metadata


def linear_distance(a, b):
    return abs(a - b)


def mulaw_to_linear_rank(u_val):
    # No formato .au mu-law o bit 7 guarda o sinal e os bits 0..6 sao invertidos em escala
    # logaritmica (0x7F e 0xFF ficam ambos proximos do zero).
    u_val &= 0xFF
    if u_val & 0x80:
        return 127 + (0xFF - u_val)
    return 127 - u_val


def mulaw_distance(a, b):
    return abs(mulaw_to_linear_rank(a) - mulaw_to_linear_rank(b))


def paeth_predictor(a, b, c):
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def load_bmp(raw):
    if len(raw) < 54 or raw[:2] != b"BM":
        raise ValueError("Arquivo BMP invalido.")
    pixel_offset = struct.unpack_from("<I", raw, 10)[0]
    dib_size = struct.unpack_from("<I", raw, 14)[0]
    if dib_size < 40 or pixel_offset >= len(raw):
        raise ValueError("Cabecalho BMP invalido ou incompleto.")
    width, height = struct.unpack_from("<ii", raw, 18)
    bpp = struct.unpack_from("<H", raw, 28)[0]
    compression = struct.unpack_from("<I", raw, 30)[0]
    if width <= 0 or height == 0:
        raise ValueError("Dimensoes de imagem BMP invalidas.")
    if compression != 0 or bpp not in (8, 24, 32):
        raise ValueError("Suporte apenas para BMP sem compressao (8, 24 ou 32 bits).")

    abs_h = abs(height)
    bytes_per_pixel = bpp // 8
    row_valid_bytes = width * bytes_per_pixel
    row_stride = (row_valid_bytes + 3) & ~3

    if pixel_offset + (abs_h - 1) * row_stride + row_valid_bytes > len(raw):
        raise ValueError("Dados de pixels do BMP estao truncados.")

    positions = []
    for r in range(abs_h):
        row_start = pixel_offset + r * row_stride
        for c in range(row_valid_bytes):
            positions.append(row_start + c)

    samples = bytearray(raw[idx] for idx in positions)

    dist_fn = linear_distance
    if bpp == 8:
        palette_offset = 14 + dib_size
        palette = []
        for i in range(256):
            p_pos = palette_offset + i * 4
            if p_pos + 3 <= pixel_offset and p_pos + 3 <= len(raw):
                b_c, g_c, r_c = raw[p_pos], raw[p_pos + 1], raw[p_pos + 2]
                palette.append((r_c, g_c, b_c))
            else:
                palette.append((i, i, i))

        def palette_dist(idx_a, idx_b):
            ca, cb = palette[idx_a & 0xFF], palette[idx_b & 0xFF]
            return max(abs(ca[0] - cb[0]), abs(ca[1] - cb[1]), abs(ca[2] - cb[2]))

        dist_fn = palette_dist

    def rebuild(modified_samples):
        out = bytearray(raw)
        for pos_idx, file_idx in enumerate(positions):
            out[file_idx] = modified_samples[pos_idx]
        return bytes(out)

    return CarrierData(
        format_name="BMP",
        description=f"BMP ({width}x{abs_h}, {bpp}-bit)",
        samples=samples,
        max_radius=4,
        distance_fn=dist_fn,
        rebuild_fn=rebuild,
        metadata={"width": width, "height": abs_h, "bpp": bpp},
    )


def load_png(raw):
    if len(raw) < 33 or raw[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Arquivo PNG invalido.")

    pos = 8
    ihdr = None
    idat_parts = []
    other_chunks_before = []
    other_chunks_after = []
    seen_idat = False

    while pos + 8 <= len(raw):
        length = struct.unpack_from(">I", raw, pos)[0]
        if pos + 12 + length > len(raw):
            raise ValueError("Chunk PNG truncado.")
        ctype = raw[pos + 4 : pos + 8]
        cdata = raw[pos + 8 : pos + 8 + length]
        pos += 12 + length
        if ctype == b"IHDR":
            ihdr = cdata
        elif ctype == b"IDAT":
            seen_idat = True
            idat_parts.append(cdata)
        elif ctype == b"IEND":
            break
        else:
            if not seen_idat:
                other_chunks_before.append((ctype, cdata))
            else:
                other_chunks_after.append((ctype, cdata))

    if ihdr is None or len(ihdr) != 13 or not idat_parts:
        raise ValueError("PNG invalido (sem IHDR ou IDAT).")

    width, height, bit_depth, color_type, comp, flt, interlace = struct.unpack(">IIBBBBB", ihdr)
    if width == 0 or height == 0:
        raise ValueError("Dimensoes PNG invalidas.")
    if bit_depth != 8 or color_type not in (0, 2, 6) or interlace != 0:
        raise ValueError("Suporte apenas para PNG de 8 bits por canal (tons de cinza, RGB ou RGBA) sem entrelacamento.")

    channels = {0: 1, 2: 3, 6: 4}[color_type]
    bpp = channels
    stride = width * channels
    decompressed = zlib.decompress(b"".join(idat_parts))
    if len(decompressed) < height * (1 + stride):
        raise ValueError("Dados de imagem PNG incompletos.")

    samples = bytearray(height * stride)
    for r in range(height):
        f_type = decompressed[r * (1 + stride)]
        row_in = decompressed[r * (1 + stride) + 1 : (r + 1) * (1 + stride)]
        row_out_start = r * stride
        prev_row_start = (r - 1) * stride
        for c in range(stride):
            x = row_in[c]
            a = samples[row_out_start + c - bpp] if c >= bpp else 0
            b = samples[prev_row_start + c] if r > 0 else 0
            c_val = samples[prev_row_start + c - bpp] if (r > 0 and c >= bpp) else 0
            if f_type == 0:
                recon = x
            elif f_type == 1:
                recon = (x + a) & 0xFF
            elif f_type == 2:
                recon = (x + b) & 0xFF
            elif f_type == 3:
                recon = (x + ((a + b) >> 1)) & 0xFF
            elif f_type == 4:
                recon = (x + paeth_predictor(a, b, c_val)) & 0xFF
            else:
                raise ValueError(f"Filtro PNG nao suportado: {f_type}")
            samples[row_out_start + c] = recon

    def make_chunk(ctype, cdata):
        crc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
        return struct.pack(">I", len(cdata)) + ctype + cdata + struct.pack(">I", crc)

    def rebuild(modified_samples):
        raw_rows = bytearray()
        for r in range(height):
            raw_rows.append(0)
            row_start = r * stride
            raw_rows.extend(modified_samples[row_start : row_start + stride])
        new_idat = zlib.compress(bytes(raw_rows), level=6)
        out = bytearray(b"\x89PNG\r\n\x1a\n")
        out.extend(make_chunk(b"IHDR", ihdr))
        for ctype, cdata in other_chunks_before:
            out.extend(make_chunk(ctype, cdata))
        out.extend(make_chunk(b"IDAT", new_idat))
        for ctype, cdata in other_chunks_after:
            out.extend(make_chunk(ctype, cdata))
        out.extend(make_chunk(b"IEND", b""))
        return bytes(out)

    color_label = {0: "Grayscale", 2: "RGB", 6: "RGBA"}[color_type]
    return CarrierData(
        format_name="PNG",
        description=f"PNG ({width}x{height}, {color_label})",
        samples=samples,
        max_radius=4,
        distance_fn=linear_distance,
        rebuild_fn=rebuild,
        metadata={"width": width, "height": height, "channels": channels},
    )


def load_wav(raw):
    if len(raw) < 44 or raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
        raise ValueError("Arquivo WAV invalido.")

    pos = 12
    audio_format = 1
    num_channels = 1
    sample_rate = 44100
    bits_per_sample = 16
    data_offset = None
    data_size = 0

    while pos + 8 <= len(raw):
        cid = raw[pos : pos + 4]
        csize = struct.unpack_from("<I", raw, pos + 4)[0]
        if cid == b"fmt ":
            if pos + 8 + 16 > len(raw):
                raise ValueError("Bloco fmt do WAV truncado.")
            audio_format, num_channels, sample_rate, _, _, bits_per_sample = struct.unpack_from(
                "<HHIIHH", raw, pos + 8
            )
        elif cid == b"data":
            data_offset = pos + 8
            data_size = min(csize, len(raw) - data_offset)
            break
        pos += 8 + csize + (csize & 1)

    if data_offset is None or data_size <= 0 or audio_format != 1 or bits_per_sample not in (8, 16):
        raise ValueError("Suporte apenas para WAV PCM linear de 8 ou 16 bits.")

    step = bits_per_sample // 8
    # Em PCM 16 bits (little-endian), usa apenas o byte menos significativo de cada amostra.
    positions = list(range(data_offset, data_offset + data_size - (step - 1), step))
    samples = bytearray(raw[idx] for idx in positions)

    def rebuild(modified_samples):
        out = bytearray(raw)
        for pos_idx, file_idx in enumerate(positions):
            out[file_idx] = modified_samples[pos_idx]
        return bytes(out)

    return CarrierData(
        format_name="WAV",
        description=f"WAV PCM {bits_per_sample}-bit ({sample_rate} Hz, {num_channels} ch)",
        samples=samples,
        max_radius=2,
        distance_fn=linear_distance,
        rebuild_fn=rebuild,
        metadata={"sample_rate": sample_rate, "channels": num_channels, "bits_per_sample": bits_per_sample},
    )


def load_au(raw):
    if len(raw) < 24 or raw[:4] != b".snd":
        raise ValueError("Arquivo AU invalido.")

    data_offset, data_size, encoding, sample_rate, channels = struct.unpack_from(">IIIII", raw, 4)
    if data_offset < 24 or data_offset >= len(raw):
        raise ValueError("Offset de dados AU invalido.")
    if encoding not in (1, 2, 3):
        raise ValueError("Codificacao AU nao suportada (use mu-law, PCM 8-bit ou PCM 16-bit).")

    actual_end = len(raw) if data_size == 0xFFFFFFFF else min(len(raw), data_offset + data_size)
    if encoding == 3:
        positions = list(range(data_offset + 1, actual_end, 2))
    else:
        positions = list(range(data_offset, actual_end))

    if not positions:
        raise ValueError("Arquivo AU sem amostras de audio.")

    samples = bytearray(raw[idx] for idx in positions)
    dist_fn = mulaw_distance if encoding == 1 else linear_distance
    enc_label = {1: "8-bit mu-law", 2: "8-bit PCM", 3: "16-bit PCM"}[encoding]

    def rebuild(modified_samples):
        out = bytearray(raw)
        for pos_idx, file_idx in enumerate(positions):
            out[file_idx] = modified_samples[pos_idx]
        return bytes(out)

    return CarrierData(
        format_name="AU",
        description=f"AU {enc_label} ({sample_rate} Hz, {channels} ch)",
        samples=samples,
        max_radius=2,
        distance_fn=dist_fn,
        rebuild_fn=rebuild,
        metadata={"sample_rate": sample_rate, "channels": channels, "encoding": encoding},
    )


def load_carrier_bytes(raw):
    if raw[:2] == b"BM":
        return load_bmp(raw)
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return load_png(raw)
    if raw[:4] == b"RIFF" and raw[8:12] == b"WAVE":
        return load_wav(raw)
    if raw[:4] == b".snd":
        return load_au(raw)
    raise ValueError("Formato nao suportado (use arquivos BMP, PNG, WAV ou AU).")


def generate_sample_bmp(width=160, height=120):
    row_stride = (width * 3 + 3) & ~3
    pixel_data = bytearray(row_stride * height)
    for y in range(height):
        for x in range(width):
            idx = y * row_stride + x * 3
            pixel_data[idx] = (x * 255 // max(1, width - 1)) & 0xFF
            pixel_data[idx + 1] = (y * 255 // max(1, height - 1)) & 0xFF
            pixel_data[idx + 2] = ((x + y) * 127 // max(1, width + height - 2)) & 0xFF
    file_size = 54 + len(pixel_data)
    header = struct.pack(
        "<2sIHHIiiiHHIIIIII",
        b"BM",
        file_size,
        0,
        0,
        54,
        40,
        width,
        height,
        1,
        24,
        0,
        len(pixel_data),
        2835,
        2835,
        0,
        0,
    )
    return header + bytes(pixel_data)


def generate_sample_png(width=160, height=120):
    raw_rows = bytearray()
    for y in range(height):
        raw_rows.append(0)
        for x in range(width):
            r = (x * 255 // max(1, width - 1)) & 0xFF
            g = (y * 255 // max(1, height - 1)) & 0xFF
            b = int(128 + 127 * math.sin((x + y) * 0.1)) & 0xFF
            raw_rows.extend((r, g, b))

    def chunk(ctype, cdata):
        crc = zlib.crc32(ctype + cdata) & 0xFFFFFFFF
        return struct.pack(">I", len(cdata)) + ctype + cdata + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(bytes(raw_rows), level=6)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def generate_sample_wav(num_samples=24000, sample_rate=22050):
    pcm = bytearray(num_samples * 2)
    for i in range(num_samples):
        val = int(16000 * math.sin(2.0 * math.pi * 440.0 * i / sample_rate))
        struct.pack_into("<h", pcm, i * 2, val)
    data_size = len(pcm)
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + data_size,
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        sample_rate,
        sample_rate * 2,
        2,
        16,
        b"data",
        data_size,
    )
    return header + bytes(pcm)


def generate_sample_au(num_samples=24000, sample_rate=8000):
    samples = bytearray(num_samples)
    for i in range(num_samples):
        rank = int(127 + 100 * math.sin(2.0 * math.pi * 300.0 * i / sample_rate))
        samples[i] = (0x7F - rank) if rank <= 127 else (0xFF - (rank - 127))
    header = struct.pack(">4sIIIII", b".snd", 24, num_samples, 1, sample_rate, 1)
    return header + bytes(samples)
