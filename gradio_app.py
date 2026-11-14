import tempfile
from pathlib import Path

from core.engine import SteghideEngine
from core.steghide_api import SteghideAPI
from web.server import SAMPLES_DIR, ensure_samples_exist


def launch_gradio(host="127.0.0.1", port=7860):
    try:
        import gradio as gr
    except ImportError as exc:
        raise RuntimeError(
            "A biblioteca Gradio nao esta instalada. Instale com 'pip install gradio' "
            "ou use 'python3 main.py gui' para abrir a interface web nativa."
        ) from exc

    ensure_samples_exist()

    def handle_embed(
        cover_file,
        secret_mode,
        secret_text,
        secret_text_name,
        secret_file,
        use_password,
        passphrase,
        algorithm,
        mode,
        encoding,
        compress_level,
    ):
        if cover_file is not None:
            cover_path = Path(cover_file)
        else:
            cover_path = SAMPLES_DIR / "cover_gradient.bmp"

        cover_bytes = cover_path.read_bytes()

        if secret_mode == "Mensagem de texto":
            secret_bytes = (secret_text or "").encode("utf-8")
            secret_name = secret_text_name.strip() or "mensagem.txt"
        else:
            if secret_file is None:
                raise gr.Error("Selecione um arquivo para esconder.")
            s_path = Path(secret_file)
            secret_bytes = s_path.read_bytes()
            secret_name = s_path.name

        stego_bytes, report = SteghideAPI.embed(
            cover_bytes=cover_bytes,
            cover_filename=cover_path.name,
            secret_bytes=secret_bytes,
            secret_filename=secret_name,
            passphrase=passphrase or "",
            use_password=bool(use_password),
            algorithm=algorithm,
            mode=mode,
            encoding=encoding,
            compress_level=int(compress_level),
        )

        out_dir = Path(tempfile.mkdtemp())
        out_path = out_dir / f"stego_{cover_path.name}"
        out_path.write_bytes(stego_bytes)

        st = report["stats"]
        resumo = (
            f"Arquivo gerado: {out_path.name}\n"
            f"Formato: {report['description']}\n"
            f"Protegido por senha: {'Sim' if use_password else 'Nao'}\n"
            f"Criptografia: {report['algorithm']} ({report['mode']})\n"
            f"Preservacao do histograma: {st.get('histogram_preservation_pct', 100.0)}%\n"
            f"Comando equivalente: {report.get('cli_command', '')}"
        )
        return str(out_path), resumo

    def handle_extract(stego_file, use_password, passphrase):
        if stego_file is None:
            raise gr.Error("Envie o arquivo stego para recuperar a informacao.")
        s_path = Path(stego_file)
        res, meta = SteghideAPI.extract(
            stego_bytes=s_path.read_bytes(),
            stego_filename=s_path.name,
            passphrase=passphrase or "",
            use_password=bool(use_password),
        )
        out_dir = Path(tempfile.mkdtemp())
        out_path = out_dir / res["filename"]
        out_path.write_bytes(res["data"])

        texto_recuperado = ""
        try:
            decoded = res["data"].decode("utf-8")
            if all(ch.isprintable() or ch in "\r\n\t" for ch in decoded[:500]):
                texto_recuperado = decoded
        except UnicodeDecodeError:
            texto_recuperado = "[Arquivo binario extraido - faca o download abaixo]"

        detalhes = (
            f"Arquivo recuperado: {res['filename']} ({res['original_size']} bytes)\n"
            f"Criptografia: {res['algorithm']} ({res['mode']})\n"
            f"Metodo: {meta['encoding']}\n"
            f"Comando equivalente: {res['cli_command']}"
        )
        return texto_recuperado, str(out_path), detalhes

    def handle_info(target_file, passphrase):
        if target_file is None:
            t_path = SAMPLES_DIR / "cover_gradient.bmp"
        else:
            t_path = Path(target_file)
        pw = passphrase if passphrase else None
        info = SteghideEngine.inspect_file(t_path.read_bytes(), passphrase=pw)
        lines = [
            f"Arquivo: {t_path.name}",
            f"Formato: {info['description']}",
            f"Amostras portadoras: {info['total_samples']}",
            f"Capacidade (Grafo): {info['capacity_graph_bytes']} bytes",
            f"Capacidade (Matrix): {info['capacity_matrix_bytes']} bytes",
            f"Entropia de 1a ordem: {info['entropy_bits_per_sample']} bits/amostra",
        ]
        if info.get("embedded"):
            e = info["embedded"]
            lines.extend(
                [
                    "",
                    "--- Dados Ocultos Detectados ---",
                    f"Nome original: {e['filename']} ({e['size_bytes']} bytes)",
                    f"Criptografia: {e['algorithm']} ({e['mode']})",
                    f"CRC32: {e['crc32']}",
                ]
            )
        elif info.get("embedded_error"):
            lines.append(f"\nAviso: {info['embedded_error']}")
        return "\n".join(lines)

    with gr.Blocks(title="Steghide GUI") as demo:
        gr.Markdown("## Interface Grafica para o Steghide")
        gr.Markdown(
            "Permite esconder uma mensagem ou arquivo dentro de um arquivo de cobertura "
            "(BMP, PNG, WAV, AU, JPG) e recuperar a informacao, com ou sem senha."
        )

        with gr.Tabs():
            with gr.TabItem("Esconder Informacao (Embed)"):
                with gr.Row():
                    with gr.Column():
                        cover_in = gr.File(label="Arquivo de Cobertura (vazio usa BMP de teste)")
                        mode_in = gr.Radio(
                            ["Mensagem de texto", "Outro arquivo"],
                            value="Mensagem de texto",
                            label="Tipo de informacao a esconder",
                        )
                        text_in = gr.Textbox(
                            label="Mensagem secreta",
                            value="Mensagem secreta de exemplo.",
                            lines=3,
                        )
                        text_name_in = gr.Textbox(label="Nome para salvar a mensagem", value="mensagem.txt")
                        file_in = gr.File(label="Arquivo para esconder (se escolheu 'Outro arquivo')")
                    with gr.Column():
                        use_pw_in = gr.Checkbox(label="Proteger com senha", value=True)
                        pw_in = gr.Textbox(label="Senha (Passphrase)", type="password", value="")
                        algo_in = gr.Dropdown(
                            ["rijndael-128", "aes-256", "chacha20", "none"],
                            value="rijndael-128",
                            label="Algoritmo de criptografia",
                        )
                        cipher_mode_in = gr.Dropdown(["cbc", "ctr"], value="cbc", label="Modo")
                        enc_in = gr.Dropdown(
                            ["graph", "matrix"],
                            value="graph",
                            label="Metodo de esteganografia",
                        )
                        comp_in = gr.Slider(0, 9, value=9, step=1, label="Nivel de compressao zlib")
                        btn_embed = gr.Button("Esconder Informacao", variant="primary")

                with gr.Row():
                    stego_out = gr.File(label="Arquivo Stego Gerado (Download)")
                    embed_log = gr.Textbox(label="Resultado e Comando Steghide", lines=6)

                btn_embed.click(
                    handle_embed,
                    inputs=[
                        cover_in,
                        mode_in,
                        text_in,
                        text_name_in,
                        file_in,
                        use_pw_in,
                        pw_in,
                        algo_in,
                        cipher_mode_in,
                        enc_in,
                        comp_in,
                    ],
                    outputs=[stego_out, embed_log],
                )

            with gr.TabItem("Recuperar Informacao (Extract)"):
                with gr.Row():
                    stego_in = gr.File(label="Arquivo Stego")
                    with gr.Column():
                        use_pw_ext = gr.Checkbox(label="Arquivo protegido com senha", value=True)
                        pw_ext = gr.Textbox(label="Senha (Passphrase)", type="password", value="")
                        btn_extract = gr.Button("Recuperar Informacao", variant="primary")
                with gr.Row():
                    text_out = gr.Textbox(label="Mensagem recuperada (se for texto)", lines=5)
                    file_out = gr.File(label="Baixar arquivo recuperado")
                ext_log = gr.Textbox(label="Detalhes da extracao", lines=4)

                btn_extract.click(
                    handle_extract,
                    inputs=[stego_in, use_pw_ext, pw_ext],
                    outputs=[text_out, file_out, ext_log],
                )

            with gr.TabItem("Informacoes do Arquivo (Info)"):
                info_file_in = gr.File(label="Arquivo de cobertura ou stego")
                info_pw_in = gr.Textbox(label="Senha (opcional)", type="password")
                btn_info = gr.Button("Analisar Arquivo")
                info_out = gr.Textbox(label="Relatorio do arquivo", lines=10)
                btn_info.click(handle_info, inputs=[info_file_in, info_pw_in], outputs=[info_out])

    demo.launch(server_name=host, server_port=port)
