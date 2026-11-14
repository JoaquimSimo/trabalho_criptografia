const state = {
  embedCover: null,
  extractStego: null,
  infoFile: null,
  multiCover: null,
  spreadCovers: [],
  gatherStegos: [],
};

const ALGO_MODES = {
  "rijndael-128": ["cbc", "ctr"],
  "aes-256": ["cbc", "ctr"],
  "chacha20": ["stream"],
  "none": ["none"],
};

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function bytesToBase64(bytes) {
  const chunkSize = 0x8000;
  const parts = [];
  for (let i = 0; i < bytes.byteLength; i += chunkSize) {
    parts.push(String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize)));
  }
  return btoa(parts.join(""));
}

function textToBase64(text) {
  const encoded = new TextEncoder().encode(text);
  return bytesToBase64(encoded);
}

function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const b64 = reader.result.split(",")[1];
      resolve({ filename: file.name, data_b64: b64, size: file.size });
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

function renderHistogram(bins) {
  if (!bins || !bins.length) return "";
  const maxVal = Math.max(...bins, 1);
  const bars = bins
    .map((val) => {
      const h = Math.max(2, Math.round((val / maxVal) * 62));
      return `<div class="hist-bar" style="height:${h}px" title="${val} amostras"></div>`;
    })
    .join("");
  return `<div class="hist-bars">${bars}</div>`;
}

function triggerDownload(filename, b64Data) {
  const a = document.createElement("a");
  a.href = "data:application/octet-stream;base64," + b64Data;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

function switchTab(tabId) {
  document.querySelectorAll(".tab-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabId);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("active", p.id === `tab-${tabId}`);
  });
}

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});

document.getElementById("embedSecretMode").addEventListener("change", (e) => {
  const isText = e.target.value === "text";
  document.getElementById("embedTextGroup").classList.toggle("hidden", !isText);
  document.getElementById("embedFileGroup").classList.toggle("hidden", isText);
});

document.getElementById("embedUsePassword").addEventListener("change", (e) => {
  const usePw = e.target.checked;
  document.getElementById("embedPassGroup").classList.toggle("hidden", !usePw);
});

document.getElementById("extractUsePassword").addEventListener("change", (e) => {
  const usePw = e.target.checked;
  document.getElementById("extractPassGroup").classList.toggle("hidden", !usePw);
});

document.getElementById("embedAlgo").addEventListener("change", (e) => {
  const modes = ALGO_MODES[e.target.value] || ["cbc"];
  const modeSelect = document.getElementById("embedMode");
  modeSelect.innerHTML = modes.map((m) => `<option value="${m}">${m}</option>`).join("");
});

async function loadSample(sampleName) {
  const res = await fetch(`/api/sample/${encodeURIComponent(sampleName)}`);
  const data = await res.json();
  if (!data.ok) throw new Error(data.error || "Erro ao carregar arquivo de teste");
  return { filename: data.filename, data_b64: data.data_b64, size: data.size };
}

document.querySelectorAll(".chip[data-sample]").forEach((chip) => {
  chip.addEventListener("click", async () => {
    try {
      const item = await loadSample(chip.dataset.sample);
      const target = chip.dataset.target;
      state[target] = item;
      const labelEl = document.getElementById(`${target}Label`);
      if (labelEl) {
        labelEl.textContent = `Arquivo: ${item.filename} (${item.size} bytes)`;
      }
    } catch (err) {
      alert(err.message);
    }
  });
});

document.getElementById("embedCoverFile").addEventListener("change", async (e) => {
  if (e.target.files[0]) {
    state.embedCover = await readFileAsBase64(e.target.files[0]);
    document.getElementById("embedCoverLabel").textContent =
      `Arquivo: ${state.embedCover.filename} (${state.embedCover.size} bytes)`;
  }
});

document.getElementById("extractStegoFile").addEventListener("change", async (e) => {
  if (e.target.files[0]) {
    state.extractStego = await readFileAsBase64(e.target.files[0]);
    document.getElementById("extractStegoLabel").textContent =
      `Arquivo: ${state.extractStego.filename} (${state.extractStego.size} bytes)`;
  }
});

document.getElementById("infoFile").addEventListener("change", async (e) => {
  if (e.target.files[0]) {
    state.infoFile = await readFileAsBase64(e.target.files[0]);
    document.getElementById("infoFileLabel").textContent =
      `Arquivo: ${state.infoFile.filename} (${state.infoFile.size} bytes)`;
  }
});

document.getElementById("multiCoverFile").addEventListener("change", async (e) => {
  if (e.target.files[0]) {
    state.multiCover = await readFileAsBase64(e.target.files[0]);
    document.getElementById("multiCoverLabel").textContent =
      `Arquivo: ${state.multiCover.filename} (${state.multiCover.size} bytes)`;
  }
});

document.getElementById("spreadCoverFiles").addEventListener("change", async (e) => {
  const list = [];
  for (const f of e.target.files) {
    list.push(await readFileAsBase64(f));
  }
  state.spreadCovers = list;
  document.getElementById("spreadCoversLabel").textContent = `${list.length} arquivo(s) selecionado(s)`;
});

document.getElementById("gatherStegoFiles").addEventListener("change", async (e) => {
  const list = [];
  for (const f of e.target.files) {
    list.push(await readFileAsBase64(f));
  }
  state.gatherStegos = list;
  document.getElementById("gatherFilesLabel").textContent = `${list.length} arquivo(s) selecionado(s)`;
});

document.getElementById("btnLoadSpreadSamples").addEventListener("click", async () => {
  const s1 = await loadSample("cover_gradient.bmp");
  const s2 = await loadSample("cover_wave.png");
  const s3 = await loadSample("cover_tone.wav");
  state.spreadCovers = [s1, s2, s3];
  document.getElementById("spreadCoversLabel").textContent =
    `3 arquivos carregados (${s1.filename}, ${s2.filename}, ${s3.filename})`;
});

document.getElementById("btnRunEmbed").addEventListener("click", async () => {
  const out = document.getElementById("embedResultCard");
  out.classList.remove("hidden");
  try {
    if (!state.embedCover) {
      state.embedCover = await loadSample("cover_gradient.bmp");
      document.getElementById("embedCoverLabel").textContent =
        `Arquivo de teste: ${state.embedCover.filename}`;
    }

    const mode = document.getElementById("embedSecretMode").value;
    let secretB64 = "";
    let secretName = "segredo.txt";
    if (mode === "text") {
      secretB64 = textToBase64(document.getElementById("embedSecretText").value);
      secretName = document.getElementById("embedTextFilename").value || "segredo.txt";
    } else {
      const fInput = document.getElementById("embedSecretFile");
      if (!fInput.files[0]) throw new Error("Escolha um arquivo para ocultar.");
      const loaded = await readFileAsBase64(fInput.files[0]);
      secretB64 = loaded.data_b64;
      secretName = loaded.filename;
    }

    const usePw = document.getElementById("embedUsePassword").checked;
    const res = await fetch("/api/embed", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        cover_b64: state.embedCover.data_b64,
        cover_filename: state.embedCover.filename,
        secret_b64: secretB64,
        secret_filename: secretName,
        use_password: usePw,
        passphrase: document.getElementById("embedPassphrase").value,
        algorithm: document.getElementById("embedAlgo").value,
        mode: document.getElementById("embedMode").value,
        encoding: document.getElementById("embedEncoding").value,
        compress_level: Number(document.getElementById("embedCompress").value),
        embed_checksum: document.getElementById("embedChecksum").checked,
        embed_filename: document.getElementById("embedFilenameFlag").checked,
      }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error);

    const r = data.report;
    const st = r.stats;
    out.innerHTML = `
      <h2>Arquivo gerado: ${escapeHtml(data.stego_filename)}</h2>
      <div class="metrics-grid">
        <div class="metric-box"><div class="label">Formato</div><div class="value">${escapeHtml(r.format)}</div></div>
        <div class="metric-box"><div class="label">Protegido com senha</div><div class="value">${r.password_protected ? "Sim" : "Nao"}</div></div>
        <div class="metric-box"><div class="label">Dados gravados</div><div class="value">${r.envelope_total_bytes} bytes</div></div>
        <div class="metric-box"><div class="label">Histograma preservado</div><div class="value">${st.histogram_preservation_pct}%</div></div>
        <div class="metric-box"><div class="label">Bits gravados</div><div class="value">${st.bits_embedded}</div></div>
        <div class="metric-box"><div class="label">Trocas / alteracoes</div><div class="value">${
          st.direct_pair_swaps !== undefined ? `${st.direct_pair_swaps + st.pool_swaps} trocas` : `${st.modified_samples || 0} bits`
        }</div></div>
      </div>
      ${r.cli_command ? `<div class="code-preview">Comando API: ${escapeHtml(r.cli_command)}</div>` : ""}
      <p class="muted">Distribuicao de frequencias das amostras:</p>
      ${renderHistogram(r.histogram_after)}
      <div>
        <button class="btn-secondary" id="dlStegoBtn">Baixar ${escapeHtml(data.stego_filename)}</button>
        <button class="btn-secondary" id="sendToExtractBtn">Testar na aba Extrair</button>
        <button class="btn-secondary" id="sendToInfoBtn">Ver na aba Info</button>
      </div>
    `;
    document.getElementById("dlStegoBtn").onclick = () => triggerDownload(data.stego_filename, data.stego_b64);
    document.getElementById("sendToExtractBtn").onclick = () => {
      state.extractStego = { filename: data.stego_filename, data_b64: data.stego_b64, size: data.stego_b64.length };
      document.getElementById("extractStegoLabel").textContent = `Arquivo: ${data.stego_filename}`;
      document.getElementById("extractUsePassword").checked = usePw;
      document.getElementById("extractPassGroup").classList.toggle("hidden", !usePw);
      document.getElementById("extractPassphrase").value = document.getElementById("embedPassphrase").value;
      switchTab("extract");
    };
    document.getElementById("sendToInfoBtn").onclick = () => {
      state.infoFile = { filename: data.stego_filename, data_b64: data.stego_b64, size: data.stego_b64.length };
      document.getElementById("infoFileLabel").textContent = `Arquivo: ${data.stego_filename}`;
      document.getElementById("infoPassphrase").value = usePw ? document.getElementById("embedPassphrase").value : "";
      switchTab("info");
    };
  } catch (err) {
    out.innerHTML = `<p class="error-msg">Erro: ${escapeHtml(err.message)}</p>`;
  }
});

document.getElementById("btnRunExtract").addEventListener("click", async () => {
  const out = document.getElementById("extractResultCard");
  out.classList.remove("hidden");
  try {
    if (!state.extractStego) {
      throw new Error("Selecione um arquivo stego primeiro.");
    }
    const usePwExt = document.getElementById("extractUsePassword").checked;
    const res = await fetch("/api/extract", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        stego_b64: state.extractStego.data_b64,
        stego_filename: state.extractStego.filename,
        use_password: usePwExt,
        passphrase: document.getElementById("extractPassphrase").value,
      }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error);

    out.innerHTML = `
      <h2>Arquivo extraido: ${escapeHtml(data.filename)}</h2>
      <div class="metrics-grid">
        <div class="metric-box"><div class="label">Nome</div><div class="value">${escapeHtml(data.filename)}</div></div>
        <div class="metric-box"><div class="label">Tamanho</div><div class="value">${data.size_bytes} bytes</div></div>
        <div class="metric-box"><div class="label">Criptografia</div><div class="value">${escapeHtml(data.algorithm)} (${escapeHtml(data.mode)})</div></div>
        <div class="metric-box"><div class="label">CRC32</div><div class="value">${escapeHtml(data.crc32)} (${data.checksum_verified ? "OK" : "Erro"})</div></div>
        <div class="metric-box"><div class="label">Metodo</div><div class="value">${escapeHtml(data.carrier_meta.encoding)}</div></div>
      </div>
      ${data.cli_command ? `<div class="code-preview">Comando API: ${escapeHtml(data.cli_command)}</div>` : ""}
      ${data.preview_text ? `<div class="code-preview">${escapeHtml(data.preview_text)}</div>` : ""}
      <button class="btn-secondary" id="dlExtractedBtn">Baixar ${escapeHtml(data.filename)}</button>
    `;
    document.getElementById("dlExtractedBtn").onclick = () => triggerDownload(data.filename, data.data_b64);
  } catch (err) {
    out.innerHTML = `<p class="error-msg">Erro: ${escapeHtml(err.message)}</p>`;
  }
});

document.getElementById("btnRunInfo").addEventListener("click", async () => {
  const out = document.getElementById("infoResultCard");
  out.classList.remove("hidden");
  try {
    if (!state.infoFile) {
      state.infoFile = await loadSample("cover_gradient.bmp");
      document.getElementById("infoFileLabel").textContent = `Arquivo de teste: ${state.infoFile.filename}`;
    }
    const res = await fetch("/api/info", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        file_b64: state.infoFile.data_b64,
        passphrase: document.getElementById("infoPassphrase").value,
      }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error);
    const info = data.info;
    let embHtml = `<p class="muted">Nenhuma senha informada (exibindo apenas dados do arquivo portador).</p>`;
    if (info.embedded) {
      const e = info.embedded;
      embHtml = `
        <div class="subcard">
          <h3>Dados ocultos encontrados</h3>
          <p><strong>Arquivo:</strong> ${escapeHtml(e.filename)} (${e.size_bytes} bytes)</p>
          <p><strong>Criptografia:</strong> ${escapeHtml(e.algorithm)}, ${escapeHtml(e.mode)} | <strong>Comprimido:</strong> ${e.compressed ? "sim" : "nao"}</p>
          <p><strong>CRC32:</strong> ${escapeHtml(e.crc32)} | <strong>Metodo:</strong> ${escapeHtml(e.encoding)}</p>
        </div>
      `;
    } else if (info.embedded_error) {
      embHtml = `<p class="error-msg">${escapeHtml(info.embedded_error)}</p>`;
    }

    out.innerHTML = `
      <h2>Informacoes: ${escapeHtml(info.description)}</h2>
      <div class="metrics-grid">
        <div class="metric-box"><div class="label">Formato</div><div class="value">${escapeHtml(info.format)}</div></div>
        <div class="metric-box"><div class="label">Amostras</div><div class="value">${info.total_samples}</div></div>
        <div class="metric-box"><div class="label">Capacidade (Grafo)</div><div class="value">${info.capacity_graph_bytes} bytes</div></div>
        <div class="metric-box"><div class="label">Capacidade (Matrix)</div><div class="value">${info.capacity_matrix_bytes} bytes</div></div>
        <div class="metric-box"><div class="label">Entropia</div><div class="value">${info.entropy_bits_per_sample} bits</div></div>
      </div>
      ${embHtml}
      <p class="muted">Histograma de frequencias:</p>
      ${renderHistogram(info.histogram)}
    `;
  } catch (err) {
    out.innerHTML = `<p class="error-msg">Erro: ${escapeHtml(err.message)}</p>`;
  }
});

document.getElementById("btnRunMulti").addEventListener("click", async () => {
  const out = document.getElementById("multiResultCard");
  out.classList.remove("hidden");
  try {
    if (!state.multiCover) {
      state.multiCover = await loadSample("cover_gradient.bmp");
      document.getElementById("multiCoverLabel").textContent = `Arquivo de teste: ${state.multiCover.filename}`;
    }
    const messages = [
      {
        passphrase: document.getElementById("multiPass1").value,
        filename: document.getElementById("multiName1").value,
        secret_b64: textToBase64(document.getElementById("multiText1").value),
      },
      {
        passphrase: document.getElementById("multiPass2").value,
        filename: document.getElementById("multiName2").value,
        secret_b64: textToBase64(document.getElementById("multiText2").value),
      },
    ];
    const res = await fetch("/api/embed-multi", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        cover_b64: state.multiCover.data_b64,
        cover_filename: state.multiCover.filename,
        messages,
      }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error);

    out.innerHTML = `
      <h2>Arquivo gerado: ${escapeHtml(data.stego_filename)}</h2>
      <p class="muted">As duas mensagens foram gravadas. Teste a extracao com cada uma das senhas:</p>
      <button class="btn-secondary" id="dlMultiBtn">Baixar ${escapeHtml(data.stego_filename)}</button>
      <button class="btn-secondary" id="testVault1Btn">Extrair com Senha 1</button>
      <button class="btn-secondary" id="testVault2Btn">Extrair com Senha 2</button>
    `;
    document.getElementById("dlMultiBtn").onclick = () => triggerDownload(data.stego_filename, data.stego_b64);
    document.getElementById("testVault1Btn").onclick = () => {
      state.extractStego = { filename: data.stego_filename, data_b64: data.stego_b64, size: data.stego_b64.length };
      document.getElementById("extractStegoLabel").textContent = `Arquivo: ${data.stego_filename}`;
      document.getElementById("extractPassphrase").value = document.getElementById("multiPass1").value;
      switchTab("extract");
    };
    document.getElementById("testVault2Btn").onclick = () => {
      state.extractStego = { filename: data.stego_filename, data_b64: data.stego_b64, size: data.stego_b64.length };
      document.getElementById("extractStegoLabel").textContent = `Arquivo: ${data.stego_filename}`;
      document.getElementById("extractPassphrase").value = document.getElementById("multiPass2").value;
      switchTab("extract");
    };
  } catch (err) {
    out.innerHTML = `<p class="error-msg">Erro: ${escapeHtml(err.message)}</p>`;
  }
});

document.getElementById("btnRunSpread").addEventListener("click", async () => {
  const out = document.getElementById("spreadResultCard");
  out.classList.remove("hidden");
  try {
    if (!state.spreadCovers.length) {
      const s1 = await loadSample("cover_gradient.bmp");
      const s2 = await loadSample("cover_wave.png");
      state.spreadCovers = [s1, s2];
      document.getElementById("spreadCoversLabel").textContent = `2 arquivos de teste carregados`;
    }
    const secretB64 = textToBase64(document.getElementById("spreadSecretText").value);
    const res = await fetch("/api/spread", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        covers: state.spreadCovers,
        secret_b64: secretB64,
        secret_filename: "dividido.txt",
        passphrase: document.getElementById("spreadPassphrase").value,
      }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error);

    state.gatherStegos = data.files;
    document.getElementById("gatherFilesLabel").textContent =
      `${data.files.length} partes carregadas para juntar`;
    document.getElementById("gatherPassphrase").value = document.getElementById("spreadPassphrase").value;

    const btns = data.files
      .map(
        (f, idx) =>
          `<button class="btn-secondary dl-shard" data-idx="${idx}">Baixar parte ${idx + 1} (${escapeHtml(f.filename)})</button>`
      )
      .join("");
    out.innerHTML = `
      <h3>Dividido em ${data.files.length} arquivos</h3>
      <p class="muted">As partes ja foram carregadas no quadro ao lado para teste.</p>
      <div>${btns}</div>
    `;
    out.querySelectorAll(".dl-shard").forEach((b) => {
      b.onclick = () => {
        const f = data.files[Number(b.dataset.idx)];
        triggerDownload(f.filename, f.data_b64);
      };
    });
  } catch (err) {
    out.innerHTML = `<p class="error-msg">Erro: ${escapeHtml(err.message)}</p>`;
  }
});

document.getElementById("btnRunGather").addEventListener("click", async () => {
  const out = document.getElementById("gatherResultCard");
  out.classList.remove("hidden");
  try {
    if (!state.gatherStegos.length) {
      throw new Error("Selecione os arquivos com as partes primeiro.");
    }
    const res = await fetch("/api/gather", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        stego_b64_list: state.gatherStegos.map((f) => f.data_b64),
        passphrase: document.getElementById("gatherPassphrase").value,
      }),
    });
    const data = await res.json();
    if (!data.ok) throw new Error(data.error);
    out.innerHTML = `
      <h3>Arquivo remontado (${escapeHtml(data.report.crc32)} OK)</h3>
      ${data.preview_text ? `<div class="code-preview">${escapeHtml(data.preview_text)}</div>` : ""}
      <button class="btn-secondary" id="dlGatheredBtn">Baixar ${escapeHtml(data.filename)}</button>
    `;
    document.getElementById("dlGatheredBtn").onclick = () => triggerDownload(data.filename, data.data_b64);
  } catch (err) {
    out.innerHTML = `<p class="error-msg">Erro: ${escapeHtml(err.message)}</p>`;
  }
});

(async function init() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    if (data.ok) {
      document.getElementById("engineStatus").textContent = "Servidor local ativo";
    }
  } catch (e) {
    document.getElementById("engineStatus").textContent = "Offline";
  }
})();
