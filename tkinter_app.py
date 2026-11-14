from pathlib import Path

from core.engine import SteghideEngine
from core.steghide_api import SteghideAPI
from web.server import SAMPLES_DIR, ensure_samples_exist


def launch_tkinter():
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError as exc:
        raise RuntimeError(
            "O modulo tkinter nao esta instalado neste Python. "
            "No Linux instale o pacote 'tk' / 'python3-tk', ou execute 'python3 main.py gui' para usar no navegador."
        ) from exc

    ensure_samples_exist()

    root = tk.Tk()
    root.title("Steghide GUI")
    root.geometry("780x620")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    tab_embed = ttk.Frame(notebook, padding=12)
    tab_extract = ttk.Frame(notebook, padding=12)
    tab_info = ttk.Frame(notebook, padding=12)

    notebook.add(tab_embed, text="Esconder Informacao (Embed)")
    notebook.add(tab_extract, text="Recuperar Informacao (Extract)")
    notebook.add(tab_info, text="Informacoes (Info)")

    cover_var = tk.StringVar(value=str(SAMPLES_DIR / "cover_gradient.bmp"))
    secret_mode_var = tk.StringVar(value="text")
    secret_file_var = tk.StringVar(value="")
    use_pw_embed_var = tk.BooleanVar(value=True)
    pw_embed_var = tk.StringVar(value="")
    algo_var = tk.StringVar(value="rijndael-128")
    encoding_var = tk.StringVar(value="graph")

    ttk.Label(tab_embed, text="Arquivo de cobertura (.bmp, .png, .wav, .au, .jpg):").pack(anchor="w")
    row_cov = ttk.Frame(tab_embed)
    row_cov.pack(fill="x", pady=4)
    ttk.Entry(row_cov, textvariable=cover_var).pack(side="left", fill="x", expand=True, padx=(0, 6))
    ttk.Button(
        row_cov,
        text="Procurar...",
        command=lambda: cover_var.set(filedialog.askopenfilename() or cover_var.get()),
    ).pack(side="left")

    row_mode = ttk.Frame(tab_embed)
    row_mode.pack(fill="x", pady=6)
    ttk.Radiobutton(row_mode, text="Esconder mensagem de texto", variable=secret_mode_var, value="text").pack(
        side="left", padx=(0, 14)
    )
    ttk.Radiobutton(row_mode, text="Esconder outro arquivo", variable=secret_mode_var, value="file").pack(side="left")

    ttk.Label(tab_embed, text="Mensagem de texto (se selecionado acima):").pack(anchor="w")
    txt_secret = tk.Text(tab_embed, height=4)
    txt_secret.insert("1.0", "Mensagem secreta de exemplo.")
    txt_secret.pack(fill="x", pady=4)

    ttk.Label(tab_embed, text="Ou arquivo para esconder:").pack(anchor="w")
    row_sec = ttk.Frame(tab_embed)
    row_sec.pack(fill="x", pady=4)
    ttk.Entry(row_sec, textvariable=secret_file_var).pack(side="left", fill="x", expand=True, padx=(0, 6))
    ttk.Button(
        row_sec,
        text="Escolher arquivo...",
        command=lambda: secret_file_var.set(filedialog.askopenfilename() or secret_file_var.get()),
    ).pack(side="left")

    row_pw = ttk.Frame(tab_embed)
    row_pw.pack(fill="x", pady=8)
    ent_pw_embed = ttk.Entry(row_pw, textvariable=pw_embed_var, show="*", width=28)

    def toggle_embed_pw():
        ent_pw_embed.configure(state="normal" if use_pw_embed_var.get() else "disabled")

    ttk.Checkbutton(
        row_pw,
        text="Proteger com senha",
        variable=use_pw_embed_var,
        command=toggle_embed_pw,
    ).pack(side="left", padx=(0, 12))
    ttk.Label(row_pw, text="Senha:").pack(side="left", padx=(0, 4))
    ent_pw_embed.pack(side="left")

    row_opts = ttk.Frame(tab_embed)
    row_opts.pack(fill="x", pady=4)
    ttk.Label(row_opts, text="Criptografia:").pack(side="left", padx=(0, 4))
    ttk.Combobox(
        row_opts,
        textvariable=algo_var,
        values=["rijndael-128", "aes-256", "chacha20", "none"],
        state="readonly",
        width=14,
    ).pack(side="left", padx=(0, 14))
    ttk.Label(row_opts, text="Metodo:").pack(side="left", padx=(0, 4))
    ttk.Combobox(
        row_opts,
        textvariable=encoding_var,
        values=["graph", "matrix"],
        state="readonly",
        width=12,
    ).pack(side="left")

    txt_embed_log = tk.Text(tab_embed, height=6, state="disabled")

    def run_embed():
        try:
            c_path = Path(cover_var.get().strip())
            if not c_path.is_file():
                raise ValueError("Selecione um arquivo de cobertura valido.")
            if secret_mode_var.get() == "text":
                s_bytes = txt_secret.get("1.0", "end-1c").encode("utf-8")
                s_name = "mensagem.txt"
            else:
                s_path = Path(secret_file_var.get().strip())
                if not s_path.is_file():
                    raise ValueError("Selecione o arquivo que deseja esconder.")
                s_bytes = s_path.read_bytes()
                s_name = s_path.name

            out_file = filedialog.asksaveasfilename(
                title="Salvar arquivo Stego como",
                initialfile=f"stego_{c_path.name}",
                defaultextension=c_path.suffix,
            )
            if not out_file:
                return

            stego_bytes, report = SteghideAPI.embed(
                cover_bytes=c_path.read_bytes(),
                cover_filename=c_path.name,
                secret_bytes=s_bytes,
                secret_filename=s_name,
                passphrase=pw_embed_var.get(),
                use_password=use_pw_embed_var.get(),
                algorithm=algo_var.get(),
                encoding=encoding_var.get(),
            )
            Path(out_file).write_bytes(stego_bytes)
            st = report["stats"]
            msg = (
                f"Salvo em: {out_file}\n"
                f"Protegido com senha: {'Sim' if use_pw_embed_var.get() else 'Nao'}\n"
                f"Preservacao do histograma: {st.get('histogram_preservation_pct', 100.0)}%\n"
                f"Comando API: {report.get('cli_command', '')}"
            )
            txt_embed_log.configure(state="normal")
            txt_embed_log.delete("1.0", "end")
            txt_embed_log.insert("1.0", msg)
            txt_embed_log.configure(state="disabled")
            messagebox.showinfo("Sucesso", f"Informacao ocultada com sucesso em:\n{out_file}")
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    ttk.Button(tab_embed, text="Esconder Informacao e Salvar Arquivo", command=run_embed).pack(fill="x", pady=8)
    txt_embed_log.pack(fill="both", expand=True, pady=4)

    stego_ext_var = tk.StringVar(value="")
    use_pw_ext_var = tk.BooleanVar(value=True)
    pw_ext_var = tk.StringVar(value="")

    ttk.Label(tab_extract, text="Arquivo Stego:").pack(anchor="w")
    row_stego = ttk.Frame(tab_extract)
    row_stego.pack(fill="x", pady=4)
    ttk.Entry(row_stego, textvariable=stego_ext_var).pack(side="left", fill="x", expand=True, padx=(0, 6))
    ttk.Button(
        row_stego,
        text="Procurar...",
        command=lambda: stego_ext_var.set(filedialog.askopenfilename() or stego_ext_var.get()),
    ).pack(side="left")

    row_pw_ext = ttk.Frame(tab_extract)
    row_pw_ext.pack(fill="x", pady=8)
    ent_pw_ext = ttk.Entry(row_pw_ext, textvariable=pw_ext_var, show="*", width=28)

    def toggle_ext_pw():
        ent_pw_ext.configure(state="normal" if use_pw_ext_var.get() else "disabled")

    ttk.Checkbutton(
        row_pw_ext,
        text="Arquivo protegido com senha",
        variable=use_pw_ext_var,
        command=toggle_ext_pw,
    ).pack(side="left", padx=(0, 12))
    ttk.Label(row_pw_ext, text="Senha:").pack(side="left", padx=(0, 4))
    ent_pw_ext.pack(side="left")

    ttk.Label(tab_extract, text="Conteudo recuperado:").pack(anchor="w")
    txt_ext_out = tk.Text(tab_extract, height=10)

    def run_extract():
        try:
            s_path = Path(stego_ext_var.get().strip())
            if not s_path.is_file():
                raise ValueError("Selecione um arquivo Stego valido.")
            res, _ = SteghideAPI.extract(
                stego_bytes=s_path.read_bytes(),
                stego_filename=s_path.name,
                passphrase=pw_ext_var.get(),
                use_password=use_pw_ext_var.get(),
            )
            txt_ext_out.delete("1.0", "end")
            try:
                decoded = res["data"].decode("utf-8")
                txt_ext_out.insert("1.0", decoded)
            except UnicodeDecodeError:
                txt_ext_out.insert("1.0", f"[Arquivo binario de {res['original_size']} bytes recuperado]")

            if messagebox.askyesno(
                "Salvar arquivo recuperado",
                f"Arquivo '{res['filename']}' ({res['original_size']} bytes) recuperado.\nDeseja salva-lo no disco?",
            ):
                save_p = filedialog.asksaveasfilename(initialfile=res["filename"])
                if save_p:
                    Path(save_p).write_bytes(res["data"])
        except Exception as e:
            messagebox.showerror("Erro na extracao", str(e))

    ttk.Button(tab_extract, text="Recuperar Informacao", command=run_extract).pack(fill="x", pady=8)
    txt_ext_out.pack(fill="both", expand=True, pady=4)

    info_file_var = tk.StringVar(value=str(SAMPLES_DIR / "cover_gradient.bmp"))
    info_pw_var = tk.StringVar(value="")

    ttk.Label(tab_info, text="Arquivo para inspecionar:").pack(anchor="w")
    row_inf = ttk.Frame(tab_info)
    row_inf.pack(fill="x", pady=4)
    ttk.Entry(row_inf, textvariable=info_file_var).pack(side="left", fill="x", expand=True, padx=(0, 6))
    ttk.Button(
        row_inf,
        text="Procurar...",
        command=lambda: info_file_var.set(filedialog.askopenfilename() or info_file_var.get()),
    ).pack(side="left")

    row_inf_pw = ttk.Frame(tab_info)
    row_inf_pw.pack(fill="x", pady=6)
    ttk.Label(row_inf_pw, text="Senha (opcional):").pack(side="left", padx=(0, 6))
    ttk.Entry(row_inf_pw, textvariable=info_pw_var, show="*", width=28).pack(side="left")

    txt_info_out = tk.Text(tab_info, height=12)

    def run_info():
        try:
            p = Path(info_file_var.get().strip())
            if not p.is_file():
                raise ValueError("Selecione um arquivo valido.")
            pw = info_pw_var.get() if info_pw_var.get() else None
            info = SteghideEngine.inspect_file(p.read_bytes(), passphrase=pw)
            out_lines = [
                f"Arquivo: {p.name}",
                f"Formato: {info['description']}",
                f"Amostras: {info['total_samples']}",
                f"Capacidade (Grafo): {info['capacity_graph_bytes']} bytes",
                f"Capacidade (Matrix): {info['capacity_matrix_bytes']} bytes",
                f"Entropia: {info['entropy_bits_per_sample']} bits/amostra",
            ]
            if info.get("embedded"):
                e = info["embedded"]
                out_lines.extend(
                    [
                        "",
                        "Dados ocultos encontrados:",
                        f"  Arquivo: {e['filename']} ({e['size_bytes']} bytes)",
                        f"  Criptografia: {e['algorithm']} ({e['mode']})",
                        f"  CRC32: {e['crc32']}",
                    ]
                )
            elif info.get("embedded_error"):
                out_lines.append(f"\nErro: {info['embedded_error']}")
            txt_info_out.delete("1.0", "end")
            txt_info_out.insert("1.0", "\n".join(out_lines))
        except Exception as e:
            messagebox.showerror("Erro", str(e))

    ttk.Button(tab_info, text="Analisar Arquivo", command=run_info).pack(fill="x", pady=8)
    txt_info_out.pack(fill="both", expand=True, pady=4)

    root.mainloop()
