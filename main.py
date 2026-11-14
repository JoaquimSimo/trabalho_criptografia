import argparse
import getpass
import sys
from pathlib import Path

from core.crypto import SUPPORTED_ALGORITHMS, normalize_cipher_params
from core.engine import SteghideEngine
from core.steghide_api import SteghideAPI
from gradio_app import launch_gradio
from tkinter_app import launch_tkinter
from web.server import ensure_samples_exist, run_web_server


def prompt_passphrase(confirm=False):
    pw = getpass.getpass("Enter passphrase: ")
    if confirm:
        pw2 = getpass.getpass("Re-Enter passphrase: ")
        if pw != pw2:
            raise ValueError("As senhas digitadas nao conferem.")
    return pw


def parse_encryption_arg(tokens):
    if not tokens:
        return "rijndael-128", "cbc"
    if len(tokens) == 1:
        t = tokens[0].lower()
        if t in SUPPORTED_ALGORITHMS:
            return normalize_cipher_params(t, None)
        return normalize_cipher_params("rijndael-128", t)
    t0, t1 = tokens[0].lower(), tokens[1].lower()
    if t0 in SUPPORTED_ALGORITHMS:
        return normalize_cipher_params(t0, t1)
    if t1 in SUPPORTED_ALGORITHMS:
        return normalize_cipher_params(t1, t0)
    raise ValueError(f"Parametros de criptografia invalidos: {' '.join(tokens)}")


def cmd_encinfo():
    print("Algoritmos de criptografia e modos suportados:")
    for algo, meta in SUPPORTED_ALGORITHMS.items():
        modes_str = ", ".join(meta["modes"])
        print(f"  {algo}: {modes_str} (padrao: {meta['default_mode']})")
    bridge = SteghideAPI.get_status()
    print(f"\nBinario steghide.exe incluso em: {bridge['bundled_exe_path']}")
    return 0


def cmd_embed(args):
    cover_path = Path(args.coverfile)
    secret_path = Path(args.embedfile)
    stego_path = Path(args.stegofile) if args.stegofile else cover_path
    if args.no_password:
        passphrase = ""
        use_pw = False
    else:
        passphrase = args.passphrase if args.passphrase is not None else prompt_passphrase(confirm=True)
        use_pw = True

    algo, mode = parse_encryption_arg(args.encryption)
    comp_level = 0 if args.dontcompress else args.compress

    stego_bytes, report = SteghideAPI.embed(
        cover_bytes=cover_path.read_bytes(),
        cover_filename=cover_path.name,
        secret_bytes=secret_path.read_bytes(),
        secret_filename=secret_path.name,
        passphrase=passphrase,
        use_password=use_pw,
        algorithm=algo,
        mode=mode,
        encoding=args.encoding,
        compress_level=comp_level,
        embed_checksum=not args.nochecksum,
        embed_filename=not args.dontembedname,
        backend="steghide_bin" if args.legacy else "auto",
    )
    stego_path.write_bytes(stego_bytes)
    if not args.quiet:
        print(f'embedding "{secret_path.name}" in "{cover_path.name}" -> "{stego_path}"... done')
        if args.verbose:
            st = report["stats"]
            print(f"  formato: {report['description']}")
            print(f"  metodo: {st['encoding']} | preservacao do histograma: {st['histogram_preservation_pct']}%")
    return 0


def cmd_extract(args):
    stego_path = Path(args.stegofile)
    if args.no_password:
        passphrase = ""
        use_pw = False
    else:
        passphrase = args.passphrase if args.passphrase is not None else prompt_passphrase(confirm=False)
        use_pw = True

    res, meta = SteghideAPI.extract(
        stego_bytes=stego_path.read_bytes(),
        stego_filename=stego_path.name,
        passphrase=passphrase,
        use_password=use_pw,
        backend="steghide_bin" if args.legacy else "auto",
    )
    if not res["has_filename"] and not args.extractfile:
        raise ValueError("O arquivo foi gravado sem nome (-N). Informe o arquivo de saida usando -xf <nome>.")

    out_path = Path(args.extractfile) if args.extractfile else Path(res["filename"])
    if out_path.exists() and not args.force:
        raise FileExistsError(f'O arquivo "{out_path}" ja existe. Use -f para sobrescrever.')
    out_path.write_bytes(res["data"])
    if not args.quiet:
        print(f'wrote extracted data to "{out_path}".')
        if args.verbose:
            print(f"  criptografia: {res['algorithm']} ({res['mode']}) | CRC32: 0x{res['crc32']:08X}")
            print(f"  metodo: {meta['encoding']}")
    return 0


def cmd_info(args):
    fpath = Path(args.file)
    info = SteghideEngine.inspect_file(fpath.read_bytes(), passphrase=args.passphrase)
    print(f'"{fpath.name}":')
    print(f"  format: {info['description']}")
    print(f"  capacity (graph):  {info['capacity_graph_bytes'] / 1024:.2f} KB ({info['capacity_graph_bytes']} bytes)")
    print(f"  capacity (matrix): {info['capacity_matrix_bytes'] / 1024:.2f} KB ({info['capacity_matrix_bytes']} bytes)")
    print(f"  entropy:           {info['entropy_bits_per_sample']} bits/sample")

    if info["embedded"]:
        emb = info["embedded"]
        print(f'  embedded file "{emb["filename"]}":')
        print(f"    size: {emb['size_bytes']} bytes")
        print(f"    encrypted: {emb['algorithm']}, {emb['mode']}")
        print(f"    compressed: {'yes' if emb['compressed'] else 'no'}")
        print(f"    crc32: {emb['crc32']} (verified: {emb['checksum_verified']})")
    elif info.get("embedded_error"):
        print(f"  info: {info['embedded_error']}")
    return 0


def cmd_embed_multi(args):
    cover_path = Path(args.coverfile)
    stego_path = Path(args.stegofile)
    messages = []
    for item in args.message:
        if ":" not in item:
            raise ValueError(f'Formato invalido "{item}". Use arquivo:senha.')
        f_str, pw = item.rsplit(":", 1)
        p = Path(f_str)
        messages.append(
            {
                "secret_bytes": p.read_bytes(),
                "filename": p.name,
                "passphrase": pw,
                "encoding": args.encoding,
            }
        )
    stego_bytes, _ = SteghideEngine.embed_multi(cover_path.read_bytes(), messages)
    stego_path.write_bytes(stego_bytes)
    print(f'Gravadas {len(messages)} mensagens independentes em "{stego_path}".')
    return 0


def cmd_spread(args):
    secret_path = Path(args.embedfile)
    out_dir = Path(args.outdir)
    out_dir.mkdir(parents=True, exist_ok=True)
    covers = [(Path(c).name, Path(c).read_bytes()) for c in args.coverfiles]
    outputs, _ = SteghideEngine.spread_secret(
        cover_list=covers,
        secret_bytes=secret_path.read_bytes(),
        passphrase=args.passphrase,
        filename=secret_path.name,
    )
    for fname, fbytes in outputs:
        target = out_dir / fname
        target.write_bytes(fbytes)
        print(f'Parte gravada em "{target}"')
    return 0


def cmd_gather(args):
    stegos = [Path(s).read_bytes() for s in args.stegofiles]
    combined, orig_name, report = SteghideEngine.gather_secret(stegos, args.passphrase)
    out_path = Path(args.extractfile) if args.extractfile else Path(orig_name)
    out_path.write_bytes(combined)
    print(f'Arquivo reconstruido em "{out_path}" ({report["original_size"]} bytes, CRC32 {report["crc32"]}).')
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="steghide",
        description="Interface grafica e CLI para esteganografia baseada no Steghide",
    )
    sub = parser.add_subparsers(dest="command")

    p_gui = sub.add_parser("gui", help="Abre a interface web local")
    p_gui.add_argument("--host", default="127.0.0.1")
    p_gui.add_argument("--port", type=int, default=8080)

    p_gradio = sub.add_parser("gradio", help="Abre a interface web em Gradio")
    p_gradio.add_argument("--host", default="127.0.0.1")
    p_gradio.add_argument("--port", type=int, default=7860)

    sub.add_parser("tkinter", help="Abre a interface desktop em Tkinter")
    sub.add_parser("encinfo", help="Lista os algoritmos de criptografia")
    sub.add_parser("generate-samples", help="Gera arquivos de teste na pasta samples/")

    p_embed = sub.add_parser("embed", help="Oculta um arquivo dentro de uma imagem ou audio")
    p_embed.add_argument("-cf", "--coverfile", required=True)
    p_embed.add_argument("-ef", "--embedfile", required=True)
    p_embed.add_argument("-sf", "--stegofile")
    p_embed.add_argument("-p", "--passphrase")
    p_embed.add_argument("--no-password", action="store_true")
    p_embed.add_argument("-e", "--encryption", nargs="+")
    p_embed.add_argument("-z", "--compress", type=int, default=9)
    p_embed.add_argument("-Z", "--dontcompress", action="store_true")
    p_embed.add_argument("-K", "--nochecksum", action="store_true")
    p_embed.add_argument("-N", "--dontembedname", action="store_true")
    p_embed.add_argument("--encoding", choices=["graph", "matrix"], default="graph")
    p_embed.add_argument("--legacy", action="store_true")
    p_embed.add_argument("-v", "--verbose", action="store_true")
    p_embed.add_argument("-q", "--quiet", action="store_true")
    p_embed.add_argument("-f", "--force", action="store_true")

    p_extract = sub.add_parser("extract", help="Extrai os dados ocultos de um arquivo stego")
    p_extract.add_argument("-sf", "--stegofile", required=True)
    p_extract.add_argument("-xf", "--extractfile")
    p_extract.add_argument("-p", "--passphrase")
    p_extract.add_argument("--no-password", action="store_true")
    p_extract.add_argument("--legacy", action="store_true")
    p_extract.add_argument("-v", "--verbose", action="store_true")
    p_extract.add_argument("-q", "--quiet", action="store_true")
    p_extract.add_argument("-f", "--force", action="store_true")

    p_info = sub.add_parser("info", help="Mostra a capacidade e informacoes de um arquivo")
    p_info.add_argument("file")
    p_info.add_argument("-p", "--passphrase")

    p_multi = sub.add_parser("embed-multi", help="Oculta multiplas mensagens com senhas diferentes")
    p_multi.add_argument("-cf", "--coverfile", required=True)
    p_multi.add_argument("-sf", "--stegofile", required=True)
    p_multi.add_argument("-m", "--message", action="append", required=True, help="Formato: arquivo:senha")
    p_multi.add_argument("--encoding", choices=["graph", "matrix"], default="graph")

    p_spread = sub.add_parser("spread", help="Divide um arquivo secreto entre varios arquivos portadores")
    p_spread.add_argument("-ef", "--embedfile", required=True)
    p_spread.add_argument("-p", "--passphrase", required=True)
    p_spread.add_argument("-o", "--outdir", default=".")
    p_spread.add_argument("-cf", "--coverfiles", nargs="+", required=True)

    p_gather = sub.add_parser("gather", help="Junta as partes divididas para reconstruir o arquivo")
    p_gather.add_argument("-p", "--passphrase", required=True)
    p_gather.add_argument("-xf", "--extractfile")
    p_gather.add_argument("-sf", "--stegofiles", nargs="+", required=True)

    return parser


def main():
    parser = build_parser()
    if len(sys.argv) == 1:
        run_web_server("127.0.0.1", 8080)
        return 0

    args = parser.parse_args()
    try:
        if args.command == "gui":
            run_web_server(args.host, args.port)
            return 0
        if args.command == "gradio":
            launch_gradio(args.host, args.port)
            return 0
        if args.command == "tkinter":
            launch_tkinter()
            return 0
        if args.command == "encinfo":
            return cmd_encinfo()
        if args.command == "generate-samples":
            files = ensure_samples_exist()
            print("Arquivos gerados em samples/: " + ", ".join(files))
            return 0
        if args.command == "embed":
            return cmd_embed(args)
        if args.command == "extract":
            return cmd_extract(args)
        if args.command == "info":
            return cmd_info(args)
        if args.command == "embed-multi":
            return cmd_embed_multi(args)
        if args.command == "spread":
            return cmd_spread(args)
        if args.command == "gather":
            return cmd_gather(args)
        parser.print_help()
        return 1
    except Exception as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
