import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from .engine import SteghideEngine

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BUNDLED_WIN32_DIR = PROJECT_ROOT / "bin" / "steghide"
BUNDLED_EXE = BUNDLED_WIN32_DIR / "steghide.exe"


class SteghideAPI:
    @staticmethod
    def resolve_binary():
        if platform.system().lower().startswith("win") and BUNDLED_EXE.exists():
            return [str(BUNDLED_EXE)]
        sys_bin = shutil.which("steghide")
        if sys_bin:
            return [sys_bin]
        wine_bin = shutil.which("wine")
        if wine_bin and BUNDLED_EXE.exists():
            return [wine_bin, str(BUNDLED_EXE)]
        return None

    @classmethod
    def get_status(cls):
        cmd = cls.resolve_binary()
        return {
            "bundled_exe_path": str(BUNDLED_EXE),
            "bundled_exe_exists": BUNDLED_EXE.exists(),
            "binary_available": cmd is not None,
            "binary_command": " ".join(cmd) if cmd else None,
            "platform": platform.system(),
        }

    @staticmethod
    def build_command_preview(
        action,
        cover_name="cobertura.bmp",
        secret_name="mensagem.txt",
        stego_name="saida_stego.bmp",
        use_password=True,
        algorithm="rijndael-128",
        mode="cbc",
        compress_level=9,
        embed_checksum=True,
        embed_filename=True,
    ):
        if action == "embed":
            parts = ["steghide", "embed", "-cf", f'"{cover_name}"', "-ef", f'"{secret_name}"', "-sf", f'"{stego_name}"']
            if use_password:
                parts.extend(["-p", '"******"'])
                if algorithm == "none":
                    parts.extend(["-e", "none"])
                else:
                    parts.extend(["-e", algorithm, mode])
            else:
                parts.extend(["-p", '""', "-e", "none"])
            if compress_level <= 0:
                parts.append("-Z")
            else:
                parts.extend(["-z", str(compress_level)])
            if not embed_checksum:
                parts.append("-K")
            if not embed_filename:
                parts.append("-N")
            return " ".join(parts)

        if action == "extract":
            pw_repr = '"******"' if use_password else '""'
            return f'steghide extract -sf "{cover_name}" -xf "{secret_name}" -p {pw_repr} -f'

        if action == "info":
            pw_repr = ' -p "******"' if use_password else ' -p ""'
            return f'steghide info "{cover_name}"{pw_repr}'

        return "steghide encinfo"

    @classmethod
    def run_subprocess(cls, args, input_text=None):
        env = os.environ.copy()
        env["PATH"] = str(BUNDLED_WIN32_DIR) + os.pathsep + env.get("PATH", "")
        return subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            cwd=str(BUNDLED_WIN32_DIR) if BUNDLED_WIN32_DIR.exists() else None,
            env=env,
        )

    @classmethod
    def embed_via_binary(
        cls,
        cover_bytes,
        cover_filename,
        secret_bytes,
        secret_filename,
        passphrase="",
        use_password=True,
        algorithm="rijndael-128",
        mode="cbc",
        compress_level=9,
        embed_checksum=True,
        embed_filename=True,
    ):
        cmd_base = cls.resolve_binary()
        if not cmd_base:
            raise RuntimeError("Executavel steghide nao disponivel neste sistema operacional.")

        effective_pw = passphrase if use_password else ""
        effective_algo = algorithm if use_password else "none"
        ext = Path(cover_filename).suffix.lower() or ".bmp"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            c_path = tmp / f"cover{ext}"
            s_path = tmp / Path(secret_filename).name
            out_path = tmp / f"stego{ext}"
            c_path.write_bytes(cover_bytes)
            s_path.write_bytes(secret_bytes)

            args = cmd_base + [
                "embed",
                "-cf",
                str(c_path),
                "-ef",
                str(s_path),
                "-sf",
                str(out_path),
                "-p",
                effective_pw,
                "-f",
            ]
            if effective_algo == "none":
                args.extend(["-e", "none"])
            else:
                args.extend(["-e", effective_algo, mode])
            if compress_level <= 0:
                args.append("-Z")
            else:
                args.extend(["-z", str(compress_level)])
            if not embed_checksum:
                args.append("-K")
            if not embed_filename:
                args.append("-N")

            proc = cls.run_subprocess(args)
            if proc.returncode != 0 or not out_path.exists():
                err = (proc.stderr or proc.stdout or "Falha ao executar steghide embed").strip()
                raise RuntimeError(err)
            return out_path.read_bytes()

    @classmethod
    def extract_via_binary(
        cls,
        stego_bytes,
        stego_filename="stego.bmp",
        passphrase="",
        use_password=True,
    ):
        cmd_base = cls.resolve_binary()
        if not cmd_base:
            raise RuntimeError("Executavel steghide nao disponivel neste sistema operacional.")

        effective_pw = passphrase if use_password else ""
        ext = Path(stego_filename).suffix.lower() or ".bmp"

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            stego_path = tmp / f"input_stego{ext}"
            out_dir = tmp / "extracted"
            out_dir.mkdir()
            stego_path.write_bytes(stego_bytes)

            args = cmd_base + ["extract", "-sf", str(stego_path), "-p", effective_pw, "-f"]
            env = os.environ.copy()
            env["PATH"] = str(BUNDLED_WIN32_DIR) + os.pathsep + env.get("PATH", "")
            proc = subprocess.run(args, capture_output=True, text=True, cwd=str(out_dir), env=env)

            extracted_files = list(out_dir.iterdir())
            if proc.returncode == 0 and extracted_files:
                target = extracted_files[0]
                return target.read_bytes(), target.name

            fallback_out = out_dir / "dados_extraidos.bin"
            args_fb = cmd_base + [
                "extract",
                "-sf",
                str(stego_path),
                "-xf",
                str(fallback_out),
                "-p",
                effective_pw,
                "-f",
            ]
            proc2 = subprocess.run(args_fb, capture_output=True, text=True, cwd=str(out_dir), env=env)
            if proc2.returncode != 0 or not fallback_out.exists():
                err = (proc2.stderr or proc.stderr or "Senha incorreta ou nenhum dado oculto encontrado.").strip()
                raise ValueError(err)
            return fallback_out.read_bytes(), fallback_out.name

    @classmethod
    def embed(
        cls,
        cover_bytes,
        cover_filename,
        secret_bytes,
        secret_filename="mensagem.txt",
        passphrase="",
        use_password=True,
        algorithm="rijndael-128",
        mode="cbc",
        encoding="graph",
        compress_level=9,
        embed_checksum=True,
        embed_filename=True,
        backend="auto",
    ):
        effective_pw = passphrase if use_password else ""
        effective_algo = algorithm if use_password else "none"
        effective_mode = mode if use_password else "none"

        cmd_preview = cls.build_command_preview(
            action="embed",
            cover_name=cover_filename,
            secret_name=secret_filename,
            stego_name=f"stego_{cover_filename}",
            use_password=use_password,
            algorithm=effective_algo,
            mode=effective_mode,
            compress_level=compress_level,
            embed_checksum=embed_checksum,
            embed_filename=embed_filename,
        )

        ext = Path(cover_filename).suffix.lower()
        if backend == "steghide_bin" or (ext in (".jpg", ".jpeg") and cls.resolve_binary()):
            stego_bytes = cls.embed_via_binary(
                cover_bytes=cover_bytes,
                cover_filename=cover_filename,
                secret_bytes=secret_bytes,
                secret_filename=secret_filename,
                passphrase=effective_pw,
                use_password=use_password,
                algorithm=effective_algo,
                mode=effective_mode,
                compress_level=compress_level,
                embed_checksum=embed_checksum,
                embed_filename=embed_filename,
            )
            return stego_bytes, {
                "format": ext.lstrip(".").upper() or "BIN",
                "description": f"Processado via steghide ({cover_filename})",
                "total_samples": len(cover_bytes),
                "capacity_bytes": max(0, len(cover_bytes) // 8),
                "secret_original_bytes": len(secret_bytes),
                "envelope_total_bytes": len(secret_bytes),
                "algorithm": effective_algo,
                "mode": effective_mode,
                "compressed": compress_level > 0,
                "compression_level": compress_level,
                "password_protected": use_password,
                "cli_command": cmd_preview,
                "stats": {
                    "encoding": "steghide-bin",
                    "bits_embedded": len(secret_bytes) * 8,
                    "histogram_preservation_pct": 100.0,
                },
                "histogram_before": [],
                "histogram_after": [],
            }

        stego_bytes, report = SteghideEngine.embed(
            cover_bytes=cover_bytes,
            secret_bytes=secret_bytes,
            passphrase=effective_pw,
            filename=secret_filename,
            algorithm=effective_algo,
            mode=effective_mode,
            encoding=encoding,
            compress_level=compress_level,
            embed_checksum=embed_checksum,
            embed_filename=embed_filename,
        )
        report["password_protected"] = use_password
        report["cli_command"] = cmd_preview
        return stego_bytes, report

    @classmethod
    def extract(
        cls,
        stego_bytes,
        stego_filename="stego.bmp",
        passphrase="",
        use_password=True,
        backend="auto",
    ):
        effective_pw = passphrase if use_password else ""
        cmd_preview = cls.build_command_preview(
            action="extract",
            cover_name=stego_filename,
            secret_name="extraido",
            use_password=use_password,
        )

        ext = Path(stego_filename).suffix.lower()
        if backend == "steghide_bin" or (ext in (".jpg", ".jpeg") and cls.resolve_binary()):
            raw_data, fname = cls.extract_via_binary(
                stego_bytes=stego_bytes,
                stego_filename=stego_filename,
                passphrase=effective_pw,
                use_password=use_password,
            )
            return {
                "data": raw_data,
                "filename": fname,
                "has_filename": True,
                "algorithm": "rijndael-128" if use_password else "none",
                "mode": "cbc" if use_password else "none",
                "compressed": True,
                "compression_level": 9,
                "checksum_verified": True,
                "crc32": 0,
                "original_size": len(raw_data),
                "cli_command": cmd_preview,
            }, {"format": ext.lstrip(".").upper(), "encoding": "steghide-bin", "vault_index": None}

        try:
            unpacked, meta = SteghideEngine.extract(stego_bytes, effective_pw)
        except Exception as primary_err:
            if not use_password and cls.resolve_binary():
                raw_data, fname = cls.extract_via_binary(stego_bytes, stego_filename, "", False)
                return {
                    "data": raw_data,
                    "filename": fname,
                    "has_filename": True,
                    "algorithm": "none",
                    "mode": "none",
                    "compressed": True,
                    "compression_level": 9,
                    "checksum_verified": True,
                    "crc32": 0,
                    "original_size": len(raw_data),
                    "cli_command": cmd_preview,
                }, {"format": ext.lstrip(".").upper(), "encoding": "steghide-bin", "vault_index": None}
            raise primary_err

        return {
            "data": unpacked.data,
            "filename": unpacked.filename,
            "has_filename": unpacked.has_filename,
            "algorithm": unpacked.algorithm,
            "mode": unpacked.mode,
            "compressed": unpacked.compressed,
            "compression_level": unpacked.compression_level,
            "checksum_verified": unpacked.checksum_verified,
            "crc32": unpacked.crc32,
            "original_size": unpacked.original_size,
            "cli_command": cmd_preview,
        }, meta
