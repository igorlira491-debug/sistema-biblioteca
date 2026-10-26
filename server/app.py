"""Servidor HTTP local — stdlib apenas (http.server + sqlite3).

Dois papéis, mesma origem (http://127.0.0.1:<porta>):
  1. Servir os arquivos estáticos do sistema (app/index.html, vendor/, logo)
     com Cache-Control: no-store no HTML (reabertura rápida, sem cache velho);
  2. Expor a API chave-valor /api/kv/* que substitui o localStorage.

Somente 127.0.0.1 — o sistema não expõe nada na rede local.

Formato dos valores: string opaca idêntica à do localStorage. O cliente
busca/escreve a MESMA string que guardaria no navegador; envelopes cifrados
{iv,data} chegam ao servidor já opacos (nada de PII em claro no banco).
"""

import json
import mimetypes
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import backup

APP_DIR = Path(__file__).resolve().parent.parent / "app"
MAX_BODY = 64 * 1024 * 1024          # 64 MiB — arrays grandes (auditoria 20k linhas)
KEY_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")   # cobre bpa_*_corrompido; bloqueia traversal
DEFAULT_PORT = 8765
PORT_FALLBACK_RANGE = 15             # 8765..8780


class ClientActivity:
    """Última requisição /api/kv/* de uma aba — usada pelo run.py para reaproveitar a aba aberta."""

    def __init__(self):
        self.last = None                 # time.monotonic() da última requisição de aba
        self.event = threading.Event()   # setado na primeira requisição de aba

    def touch(self):
        self.last = time.monotonic()
        self.event.set()


def make_server(start_port, db, explicit_port=False, activity=None, data_dir=None):
    """Cria o servidor; porta ocupada → próxima livre (a menos que o usuário tenha fixado)."""
    ports = [start_port] if explicit_port else range(start_port, start_port + PORT_FALLBACK_RANGE)
    last_err = None
    for port in ports:
        try:
            handler = _make_handler(db, activity, data_dir)
            server = ThreadingHTTPServer(("127.0.0.1", port), handler)
            server.daemon_threads = True
            return server, port
        except OSError as e:
            last_err = e
    raise RuntimeError(f"Nenhuma porta livre a partir de {start_port}: {last_err}")


def _make_handler(db, activity=None, data_dir=None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "BibliotecaLocal/1.0"

        # Log enxuto no terminal (uma linha por requisição só em erros)
        def log_message(self, fmt, *args):
            if args and str(args[1]).startswith(("4", "5")):
                super().log_message(fmt, *args)

        # ---------- helpers ----------
        def _json(self, obj, status=200):
            # Aba viva = pedido /api/kv ACEITO (/api/health é do run.py --verificar e dos testes)
            path = urlparse(self.path).path
            if activity and status < 400 and (path == "/api/kv" or path.startswith("/api/kv/")):
                activity.touch()
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if status >= 400:
                # Erro pode sair sem ler o corpo do pedido: fechar evita que a sobra
                # embaralhe o próximo pedido da mesma conexão (keep-alive)
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                raise ValueError("corpo vazio")
            if length > MAX_BODY:
                raise OverflowError("corpo excede 64 MiB")
            return self.rfile.read(length)

        def _key(self, raw):
            """Valida a chave; devolve (key, None) ou (None, resposta de erro)."""
            key = urlparse(raw).path.rsplit("/", 1)[-1]
            if not KEY_RE.match(key):
                return None, ("chave inválida (esperado [A-Za-z0-9_]{1,64})", 400)
            return key, None

        def _static(self, raw_path):
            path = urlparse(raw_path).path
            if path in ("/", "/index.html"):
                rel = "index.html"
            else:
                rel = path.lstrip("/")
            target = (APP_DIR / rel).resolve()
            # Nada fora de app/ (path traversal → 403); is_relative_to compara por pasta
            # inteira — startswith deixaria passar uma vizinha como "app_x/"
            if not target.is_relative_to(APP_DIR.resolve()):
                self._json({"error": "acesso negado"}, 403)
                return
            if not target.is_file():
                self._json({"error": "não encontrado"}, 404)
                return
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            # Só as libs de vendor/ podem ficar em cache; HTML e app.js mudam juntos
            # (app.js em cache rodaria o JS de ontem com o HTML de hoje)
            em_vendor = (APP_DIR / "vendor").resolve() in target.parents
            self.send_header(
                "Cache-Control",
                "public, max-age=86400" if em_vendor else "no-store",
            )
            self.end_headers()
            self.wfile.write(data)

        # ---------- API ----------
        def _api_get(self, raw):
            parsed = urlparse(raw)
            if parsed.path == "/api/health":
                return self._json({"ok": True, "api": 1})
            # Falha de backup volta 200 com "erro": 5xx acenderia a faixa "banco fora" do cliente
            if parsed.path == "/api/backup/status" and data_dir:
                return self._json(backup.status(data_dir))
            # leitura em batch: GET /api/kv?keys=a,b,c
            keys = parse_qs(parsed.query).get("keys") if parsed.path == "/api/kv" else None
            if parsed.path != "/api/kv" and not parsed.path.startswith("/api/kv/"):
                return self._json({"error": "rota desconhecida"}, 404)
            if parsed.path == "/api/kv" and not keys:
                return self._json({"error": "rota desconhecida (use /api/kv/<chave> ou ?keys=)"}, 404)
            if keys:
                wanted = [k for k in keys[0].split(",") if k]
                if any(not KEY_RE.match(k) for k in wanted):
                    return self._json({"error": "chave inválida"}, 400)
                return self._json({"values": db.get_many(wanted)})
            key, err = self._key(raw)
            if err:
                return self._json({"error": err[0]}, err[1])
            return self._json({"key": key, "value": db.get(key)})

        def _api_put(self, raw):
            key, err = self._key(raw)
            if err:
                return self._json({"error": err[0]}, err[1])
            try:
                payload = json.loads(self._read_body())
            except OverflowError:
                return self._json({"error": "corpo excede 64 MiB"}, 413)
            except (ValueError, json.JSONDecodeError):
                return self._json({"error": "JSON inválido"}, 400)
            value = payload.get("value")
            if not isinstance(value, str):
                return self._json({"error": '"value" deve ser string'}, 400)
            db.put(key, value)
            return self._json({"ok": True})

        def _api_delete(self, raw):
            key, err = self._key(raw)
            if err:
                return self._json({"error": err[0]}, err[1])
            db.delete(key)
            return self._json({"ok": True})

        def _api_batch(self):
            try:
                payload = json.loads(self._read_body())
            except OverflowError:
                return self._json({"error": "corpo excede 64 MiB"}, 413)
            except (ValueError, json.JSONDecodeError):
                return self._json({"error": "JSON inválido"}, 400)
            puts = payload.get("put") or {}
            deletes = payload.get("delete") or []
            if not isinstance(puts, dict) or not isinstance(deletes, list):
                return self._json({"error": 'esperado {"put":{...},"delete":[...]}'}, 400)
            if any(not KEY_RE.match(str(k)) for k in puts) or any(
                not KEY_RE.match(str(k)) for k in deletes
            ):
                return self._json({"error": "chave inválida"}, 400)
            if any(not isinstance(v, str) for v in puts.values()):
                return self._json({"error": '"value" deve ser string'}, 400)
            db.put_many(puts, [str(k) for k in deletes])
            return self._json({"ok": True})

        # ---------- verbos ----------
        def do_GET(self):
            path = urlparse(self.path).path
            if path.startswith("/api/"):
                if not self._origem_ok():
                    return self._json({"error": "origem não permitida"}, 403)
                return self._api_get(self.path)
            return self._static(self.path)

        def do_PUT(self):
            if not self._origem_ok():
                return self._json({"error": "origem não permitida"}, 403)
            if not urlparse(self.path).path.startswith("/api/kv/"):
                return self._json({"error": "rota desconhecida"}, 404)
            return self._api_put(self.path)

        def do_DELETE(self):
            if not self._origem_ok():
                return self._json({"error": "origem não permitida"}, 403)
            if not urlparse(self.path).path.startswith("/api/kv/"):
                return self._json({"error": "rota desconhecida"}, 404)
            return self._api_delete(self.path)

        def _abrir_pasta_backups(self):
            try:
                proc = subprocess.Popen(["xdg-open", str(backup.backup_dir(data_dir))],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                try:
                    codigo = proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    codigo = 0   # ainda abrindo o gerenciador de arquivos: segue como sucesso
            except OSError as e:
                return self._json({"ok": False, "erro": f"não foi possível abrir a pasta ({e})"})
            if codigo != 0:
                return self._json({"ok": False, "erro": f"o gerenciador de arquivos não abriu (xdg-open saiu com código {codigo})"})
            return self._json({"ok": True})

        def _origem_ok(self):
            """Só a própria página do sistema: bloqueia outro site aberto no navegador (CSRF) e DNS rebinding."""
            host = self.headers.get("Host", "")
            if host.rsplit(":", 1)[0] not in ("127.0.0.1", "localhost"):
                return False
            origin = self.headers.get("Origin")
            return origin is None or origin == f"http://{host}"

        def do_POST(self):
            if not self._origem_ok():
                return self._json({"error": "origem não permitida"}, 403)
            if urlparse(self.path).path == "/api/kv/batch":
                return self._api_batch()
            if urlparse(self.path).path == "/api/backup/abrir-pasta" and data_dir:
                return self._abrir_pasta_backups()
            return self._json({"error": "rota desconhecida"}, 404)

    return Handler
