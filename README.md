# Interface Gráfica e API para o Steghide

Aplicação em Python 3 desenvolvida para ocultação e recuperação de informações (mensagens de texto ou arquivos) em arquivos de cobertura de imagem e áudio, utilizando o Steghide como base.

## Funcionalidades

- **Ocultar informação (`embed`)**: Esconde uma mensagem digitada ou qualquer arquivo dentro de arquivos `.bmp`, `.png`, `.wav`, `.au` e `.jpg`.
- **Recuperar informação (`extract`)**: Extrai o conteúdo oculto, exibindo mensagens de texto diretamente na interface e permitindo o download do arquivo original.
- **Com ou sem senha**: Permite proteger os dados com senha (`rijndael-128`/AES, `aes-256`, `chacha20`) ou ocultar sem senha (`-p "" -e none`).
- **Inspeção (`info`)**: Analisa a capacidade em bytes, a entropia de 1ª ordem, o histograma de frequências e verifica a presença de arquivos embutidos.
- **Recursos adicionais**:
  - Preservação do histograma de 1ª ordem por troca de pares em grafo e codificação *Matrix Encoding* (Hamming).
  - Ocultação de múltiplas mensagens independentes no mesmo arquivo com senhas distintas.
  - Divisão de um arquivo secreto entre múltiplos arquivos de cobertura (*Spread* / *Gather*) com verificação `CRC32`.

## Como Executar

### 1. Instalar dependências (opcional)
```bash
pip install -r requirements.txt
```

### 2. Executar a Interface Web Local (não requer pacotes externos)
```bash
python3 main.py gui --port 8080
```
Acesse no navegador: `http://127.0.0.1:8080`

### 3. Executar a Interface em Gradio (Web App)
```bash
python3 main.py gradio
```
Acesse no navegador: `http://127.0.0.1:7860`

### 4. Executar a Interface Desktop em Tkinter
```bash
python3 main.py tkinter
```

### 5. Executar os Testes
```bash
python3 tests/test_suite.py -v
```
