import base64
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from core.carriers import (
    generate_sample_au,
    generate_sample_bmp,
    generate_sample_png,
    generate_sample_wav,
)
from core.crypto import SUPPORTED_ALGORITHMS
from core.engine import SteghideEngine
from core.steghide_api import SteghideAPI

WEB_DIR = Path(__file__).resolve().parent
STATIC_DIR = WEB_DIR / "static"
SAMPLES_DIR = WEB_DIR.parent / "samples"


def try_text_preview(raw_bytes):
    try:
        decoded = raw_bytes.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in decoded[:500]):
            return decoded[:2000]
    except UnicodeDecodeError:
        pass
    return None


def ensure_samples_exist():
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    files = {
        "cover_gradient.bmp": generate_sample_bmp(160, 120),
        "cover_wave.png": generate_sample_png(160, 120),
        "cover_tone.wav": generate_sample_wav(24000, 22050),
        "cover_mulaw.au": generate_sample_au(24000, 8000),
        "segredo.txt": "Texto de exemplo para testar a ocultacao e extracao no Steghide.\n".encode("utf-8"),
    }
    for name, content in files.items():
        target = SAMPLES_DIR / name
        if not target.exists():
            target.write_bytes(content)
    return sorted(p.name for p in SAMPLES_DIR.iterdir() if p.is_file())


class SteghideHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def send_json(self, payload, status=200):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b"{}"
        return json.loads(body.decode("utf-8"))

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/api/status":
            sample_files = ensure_samples_exist()
            self.send_json(
                {
                    "ok": True,
                    "algorithms": SUPPORTED_ALGORITHMS,
                    "legacy_bridge": SteghideAPI.get_status(),
                    "samples": sample_files,
                }
            )
            return

        if path.startswith("/api/sample/"):
            fname = Path(path.replace("/api/sample/", "", 1)).name
            fpath = SAMPLES_DIR / fname
            if not fpath.is_file():
                self.send_json({"ok": False, "error": "Arquivo de exemplo nao encontrado."}, 404)
                return
            data = fpath.read_bytes()
            self.send_json(
                {
                    "ok": True,
                    "filename": fname,
                    "data_b64": base64.b64encode(data).decode("ascii"),
                    "size": len(data),
                }
            )
            return

        if path == "/" or path == "":
            path = "/index.html"

        target = (STATIC_DIR / path.lstrip("/")).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            self.send_error(404, "File Not Found")
            return

        ctype, _ = mimetypes.guess_type(str(target))
        raw = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype or "application/octet-stream")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        try:
            req = self.read_json()

            if path == "/api/embed":
                cover_bytes = base64.b64decode(req["cover_b64"])
                secret_bytes = base64.b64decode(req["secret_b64"])
                cover_name = Path(req.get("cover_filename", "cover.bmp")).name
                use_password = bool(req.get("use_password", True))
                stego_bytes, report = SteghideAPI.embed(
                    cover_bytes=cover_bytes,
                    cover_filename=cover_name,
                    secret_bytes=secret_bytes,
                    secret_filename=Path(req.get("secret_filename", "segredo.bin")).name,
                    passphrase=req.get("passphrase", ""),
                    use_password=use_password,
                    algorithm=req.get("algorithm", "rijndael-128"),
                    mode=req.get("mode", "cbc"),
                    encoding=req.get("encoding", "graph"),
                    compress_level=int(req.get("compress_level", 9)),
                    embed_checksum=bool(req.get("embed_checksum", True)),
                    embed_filename=bool(req.get("embed_filename", True)),
                )
                self.send_json(
                    {
                        "ok": True,
                        "stego_filename": f"stego_{cover_name}",
                        "stego_b64": base64.b64encode(stego_bytes).decode("ascii"),
                        "report": report,
                    }
                )
                return

            if path == "/api/extract":
                stego_bytes = base64.b64decode(req["stego_b64"])
                stego_name = Path(req.get("stego_filename", "stego.bmp")).name
                use_password = bool(req.get("use_password", True))
                passphrase = req.get("passphrase", "")
                res, meta = SteghideAPI.extract(
                    stego_bytes=stego_bytes,
                    stego_filename=stego_name,
                    passphrase=passphrase,
                    use_password=use_password,
                )
                self.send_json(
                    {
                        "ok": True,
                        "filename": res["filename"],
                        "data_b64": base64.b64encode(res["data"]).decode("ascii"),
                        "size_bytes": res["original_size"],
                        "algorithm": res["algorithm"],
                        "mode": res["mode"],
                        "compressed": res["compressed"],
                        "compression_level": res["compression_level"],
                        "crc32": f"0x{res['crc32']:08X}",
                        "checksum_verified": res["checksum_verified"],
                        "cli_command": res["cli_command"],
                        "carrier_meta": meta,
                        "preview_text": try_text_preview(res["data"]),
                    }
                )
                return

            if path == "/api/info":
                file_bytes = base64.b64decode(req["file_b64"])
                passphrase = req.get("passphrase") or None
                info = SteghideEngine.inspect_file(file_bytes, passphrase=passphrase)
                self.send_json({"ok": True, "info": info})
                return

            if path == "/api/embed-multi":
                cover_bytes = base64.b64decode(req["cover_b64"])
                cover_name = Path(req.get("cover_filename", "cover.bmp")).name
                raw_msgs = req.get("messages", [])
                messages = []
                for m in raw_msgs:
                    messages.append(
                        {
                            "secret_bytes": base64.b64decode(m["secret_b64"]),
                            "filename": Path(m.get("filename", "msg.txt")).name,
                            "passphrase": m["passphrase"],
                            "algorithm": m.get("algorithm", "rijndael-128"),
                            "encoding": m.get("encoding", "graph"),
                        }
                    )
                stego_bytes, report = SteghideEngine.embed_multi(cover_bytes, messages)
                self.send_json(
                    {
                        "ok": True,
                        "stego_filename": f"multi_{cover_name}",
                        "stego_b64": base64.b64encode(stego_bytes).decode("ascii"),
                        "report": report,
                    }
                )
                return

            if path == "/api/spread":
                covers = [
                    (Path(item["filename"]).name, base64.b64decode(item["data_b64"]))
                    for item in req.get("covers", [])
                ]
                secret_bytes = base64.b64decode(req["secret_b64"])
                outputs, report = SteghideEngine.spread_secret(
                    cover_list=covers,
                    secret_bytes=secret_bytes,
                    passphrase=req.get("passphrase", ""),
                    filename=Path(req.get("secret_filename", "segredo.bin")).name,
                    algorithm=req.get("algorithm", "rijndael-128"),
                    encoding=req.get("encoding", "graph"),
                )
                self.send_json(
                    {
                        "ok": True,
                        "files": [
                            {"filename": fname, "data_b64": base64.b64encode(fbytes).decode("ascii")}
                            for fname, fbytes in outputs
                        ],
                        "report": report,
                    }
                )
                return

            if path == "/api/gather":
                stego_list = [base64.b64decode(b64) for b64 in req.get("stego_b64_list", [])]
                passphrase = req.get("passphrase", "")
                combined, filename, report = SteghideEngine.gather_secret(stego_list, passphrase)
                self.send_json(
                    {
                        "ok": True,
                        "filename": filename,
                        "data_b64": base64.b64encode(combined).decode("ascii"),
                        "preview_text": try_text_preview(combined),
                        "report": report,
                    }
                )
                return

            self.send_json({"ok": False, "error": f"Rota desconhecida: {path}"}, 404)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, 400)


def run_web_server(host="127.0.0.1", port=8080):
    ensure_samples_exist()
    server = ThreadingHTTPServer((host, port), SteghideHTTPHandler)
    print(f"Servidor rodando em http://{host}:{port} (Ctrl+C para encerrar)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
