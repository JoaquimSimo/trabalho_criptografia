import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.carriers import (
    generate_sample_au,
    generate_sample_bmp,
    generate_sample_png,
    generate_sample_wav,
)
from core.engine import SteghideEngine
from core.steghide_api import SteghideAPI
from main import parse_encryption_arg


class SteghideTests(unittest.TestCase):
    def setUp(self):
        self.secret = b"Mensagem de exemplo para teste de ocultacao e extracao."

    def test_carriers_graph_and_matrix(self):
        carriers = [
            ("teste.bmp", generate_sample_bmp(80, 60)),
            ("teste.png", generate_sample_png(80, 60)),
            ("teste.wav", generate_sample_wav(8000, 22050)),
            ("teste.au", generate_sample_au(8000, 8000)),
        ]
        for name, raw in carriers:
            for encoding in ("graph", "matrix"):
                stego, _ = SteghideEngine.embed(
                    cover_bytes=raw,
                    secret_bytes=self.secret,
                    passphrase="senha-" + name,
                    filename="nota.txt",
                    encoding=encoding,
                )
                unpacked, meta = SteghideEngine.extract(stego, "senha-" + name)
                self.assertEqual(unpacked.data, self.secret)
                self.assertEqual(unpacked.filename, "nota.txt")
                self.assertEqual(meta["encoding"], encoding)
                self.assertTrue(unpacked.checksum_verified)

    def test_encryption_modes_and_validation(self):
        bmp = generate_sample_bmp(80, 60)
        for algo, mode in [
            ("rijndael-128", "cbc"),
            ("rijndael-128", "ctr"),
            ("aes-256", "cbc"),
            ("aes-256", "ctr"),
            ("chacha20", "stream"),
            ("none", "none"),
        ]:
            stego, _ = SteghideEngine.embed(
                cover_bytes=bmp,
                secret_bytes=self.secret,
                passphrase="chave-" + algo,
                algorithm=algo,
                mode=mode,
            )
            unpacked, _ = SteghideEngine.extract(stego, "chave-" + algo)
            self.assertEqual(unpacked.data, self.secret)
            self.assertEqual(unpacked.algorithm, algo)
            self.assertEqual(unpacked.mode, mode)

        self.assertEqual(parse_encryption_arg(["ctr", "aes-256"]), ("aes-256", "ctr"))
        with self.assertRaises(ValueError):
            SteghideEngine.embed(bmp, self.secret, "123", algorithm="rijndael-128", mode="ecb")

    def test_multi_messages(self):
        png = generate_sample_png(120, 90)
        stego, _ = SteghideEngine.embed_multi(
            png,
            [
                {"secret_bytes": b"Primeira mensagem", "filename": "m1.txt", "passphrase": "s1"},
                {"secret_bytes": b"Segunda mensagem", "filename": "m2.txt", "passphrase": "s2"},
            ],
        )
        u1, m1 = SteghideEngine.extract(stego, "s1")
        u2, m2 = SteghideEngine.extract(stego, "s2")
        self.assertEqual(u1.data, b"Primeira mensagem")
        self.assertEqual(u1.filename, "m1.txt")
        self.assertEqual(m1["vault_index"], 0)
        self.assertEqual(u2.data, b"Segunda mensagem")
        self.assertEqual(u2.filename, "m2.txt")
        self.assertEqual(m2["vault_index"], 1)

    def test_spread_and_gather(self):
        covers = [
            ("c1.bmp", generate_sample_bmp(80, 60)),
            ("c2.png", generate_sample_png(80, 60)),
            ("c3.wav", generate_sample_wav(8000, 22050)),
        ]
        payload = b"Bloco de dados " * 80
        outputs, _ = SteghideEngine.spread_secret(
            cover_list=covers,
            secret_bytes=payload,
            passphrase="123",
            filename="dados.bin",
        )
        reversed_stegos = [fbytes for _, fbytes in reversed(outputs)]
        reconstructed, fname, _ = SteghideEngine.gather_secret(reversed_stegos, "123")
        self.assertEqual(reconstructed, payload)
        self.assertEqual(fname, "dados.bin")

        other_outputs, _ = SteghideEngine.spread_secret(
            cover_list=covers[:2],
            secret_bytes=b"Outro arquivo diferente",
            passphrase="123",
            filename="outro.bin",
        )
        with self.assertRaises(ValueError):
            SteghideEngine.gather_secret([outputs[0][1], other_outputs[1][1]], "123")

    def test_dont_embed_filename_and_wrong_password(self):
        bmp = generate_sample_bmp(80, 60)
        stego, _ = SteghideEngine.embed(
            bmp,
            self.secret,
            "senha-correta",
            embed_filename=False,
        )
        unpacked, _ = SteghideEngine.extract(stego, "senha-correta")
        self.assertFalse(unpacked.has_filename)
        self.assertEqual(unpacked.data, self.secret)

        with self.assertRaises(ValueError):
            SteghideEngine.extract(stego, "senha-errada")

    def test_steghide_api_with_and_without_password(self):
        bmp = generate_sample_bmp(80, 60)
        stego_no_pw, rep_no_pw = SteghideAPI.embed(
            cover_bytes=bmp,
            cover_filename="teste.bmp",
            secret_bytes=self.secret,
            secret_filename="sem_senha.txt",
            passphrase="ignorada",
            use_password=False,
        )
        self.assertFalse(rep_no_pw["password_protected"])
        self.assertEqual(rep_no_pw["algorithm"], "none")

        extracted, _ = SteghideAPI.extract(
            stego_bytes=stego_no_pw,
            stego_filename="stego_teste.bmp",
            passphrase="",
            use_password=False,
        )
        self.assertEqual(extracted["data"], self.secret)
        self.assertEqual(extracted["filename"], "sem_senha.txt")

        info = SteghideEngine.inspect_file(stego_no_pw)
        self.assertIsNotNone(info["embedded"])
        self.assertEqual(info["embedded"]["filename"], "sem_senha.txt")
        self.assertFalse(info["embedded"]["password_protected"])


if __name__ == "__main__":
    unittest.main()
