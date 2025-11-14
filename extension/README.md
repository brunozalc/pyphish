# PyPhish Sentinel — Extensão Firefox

Extensão que analisa páginas em tempo real utilizando a API local do PyPhish.

---

## Requisitos

- Backend PyPhish ativo em `http://localhost:5000` (veja o README na raiz).
- Firefox Desktop compatível com Manifest V2.
- `web-ext` instalado globalmente para empacotar (`npm install --global web-ext`).

---

## Como carregar

### Modo rápido (temporário)

1. Abra `about:debugging` no Firefox.
2. Clique em `This Firefox` → `Load Temporary Add-on`.
3. Escolha qualquer arquivo dentro da pasta `extension/`.

### Modo desenvolvimento (web-ext)

```bash
web-ext run --source-dir extension/ --firefox-binary \
  "/Applications/Firefox.app/Contents/MacOS/firefox"
```

- Pressione `r` no terminal para recarregar.
- Encerre com `Ctrl+C`.

---

## Empacotamento para entrega

```bash
cd extension
web-ext build --overwrite-dest
```

- O `.zip` final ficará em `extension/web-ext-artifacts/`.
- Alternativa rápida: `zip -r pyphish-extension.zip extension/`.

---

## Configurações essenciais

- **API Base URL:** Ajuste em `Opções → API Base URL` se a API estiver em outro host/porta.
- **Sensibilidade:** Níveis Baixo, Médio e Alto controlam o bloqueio automático.
- **Whitelist:** Domínios confiáveis (aceita curingas, ex.: `*.example.com`).

---

## Capturas de tela

![Print 1 – Popup](../docs/screenshots/extension-popup.png)

![Print 2 – Alerta de bloqueio](../docs/screenshots/extension-warning.png)

![Print 3 – Configurações](../docs/screenshots/extension-options.png)

---

## Solução rápida de problemas

- **Erro de rede:** Confirme a API com `curl http://localhost:5000/health`.
- **Badge exibindo `--`:** Verifique o console do background (`about:debugging → Inspect`).
- **Sem análise em uma página:** Certifique-se de que o site é HTTP/HTTPS e não está na whitelist.

---

## Estrutura principal

```text
extension/
├── background/   # Lógica do service worker
├── content/      # Scripts injetados nas páginas
├── ui/           # Popup, opções e tela de alerta
├── shared/       # Mensagens e constantes reutilizadas
├── assets/       # Ícones
└── manifest.json
```

Pronto para avaliação: suba o backend e carregue o `.zip` gerado no Firefox.
