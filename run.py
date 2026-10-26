#!/usr/bin/env python3
"""Sistema de Registro — Biblioteca Pública Municipal (backend local).

Uso (no terminal da máquina da biblioteca):

    python3 run.py

Sobe o servidor local, cria o banco em data/biblioteca.db (se não existir)
e abre o navegador em http://127.0.0.1:8765/. Encerre com Ctrl+C.

Flags:
    --porta N       usa exatamente a porta N (sem fallback)
    --sem-navegador não abre o navegador automaticamente
    --verificar     abre, checa o banco (integrity_check) e sai
    --restaurar ARQ restaura um backup (com o sistema FECHADO) e sai

Backup automático: um por dia em data/backups/ (guarda os 30 últimos) —
ao ligar, de hora em hora e ao encerrar com Ctrl+C.
"""

import argparse
import os
import sqlite3
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

from server import backup  # noqa: E402
from server.app import DEFAULT_PORT, ClientActivity, make_server  # noqa: E402
from server.db import Database  # noqa: E402

# Reabrir a mesma aba: no Ctrl+C anotamos se havia aba viva; no start seguinte
# esperamos ela reconectar (re-sonda a cada 10 s — Bloco 4) antes de abrir outra.
# A marca é um arquivo em data/ (fora da API do navegador) com a porta da aba.
MARCA_ABA = ".aba_aberta"
ABA_ATIVA_S = 90     # sonda da aba é a cada 10 s; folga para aba em 2º plano (timers estrangulados)
ESPERA_ABA_S = 15    # > intervalo da sonda da aba (CFG.DB_PROBE_MS = 10 s em app/index.html)

# shortcut: env só para testes encurtarem o laço; na operação vale 1 h
INTERVALO_BACKUP_S = int(os.environ.get("BPA_BACKUP_INTERVALO_S", 3600))


def _backup_seguro(acao, db, data_dir):
    """Backup + limpeza; falha vira aviso (terminal + aba Segurança), nunca derruba o servidor."""
    try:
        acao(db, data_dir)
        backup.prune(data_dir)
        backup.ultimo_erro = None
    except Exception as e:
        backup.ultimo_erro = str(e)
        print(f"[backup] falhou: {e}", file=sys.stderr)


def _laco_backup(db, data_dir):
    while True:
        _backup_seguro(backup.ensure_today, db, data_dir)   # ao ligar e quando virar o dia
        time.sleep(INTERVALO_BACKUP_S)


# Servidor no ar sobre esta pasta de dados = arquivo com o PID (vale em qualquer porta).
MARCA_SERVIDOR = ".servidor_pid"


def _sistema_aberto(data_dir):
    try:
        pid = int((data_dir / MARCA_SERVIDOR).read_text().strip())
        # Marca velha de queda de energia: o PID pode ter sido reusado por outro programa
        return b"run.py" in Path(f"/proc/{pid}/cmdline").read_bytes()
    except (OSError, ValueError):
        return False


def _restaurar(args, data_dir, db_path):
    if _sistema_aberto(data_dir):
        print("[erro] Feche o sistema (Ctrl+C no terminal dele) antes de restaurar.", file=sys.stderr)
        return 2
    db = Database(db_path)
    try:
        seguranca = backup.restore(args.restaurar, db, data_dir)
    except (ValueError, sqlite3.Error, OSError) as e:
        print(f"[erro] Não foi possível restaurar: {e}", file=sys.stderr)
        return 1
    finally:
        db.close()
    print(f"Backup restaurado: {args.restaurar}")
    print(f"O banco anterior foi guardado em: {seguranca}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Sistema da Biblioteca — servidor local")
    parser.add_argument("--porta", type=int, default=DEFAULT_PORT, help="porta inicial (padrão 8765)")
    parser.add_argument("--sem-navegador", action="store_true", help="não abre o navegador")
    parser.add_argument("--verificar", action="store_true", help="sobe, checa a integridade e sai")
    parser.add_argument("--data", type=Path, default=None, help="diretório do banco (padrão: <projeto>/data)")
    parser.add_argument("--restaurar", type=Path, default=None, metavar="ARQUIVO", help="restaura um backup e sai")
    args = parser.parse_args()

    data_dir = args.data if args.data else (BASE / "data")
    db_path = data_dir / "biblioteca.db"
    if args.restaurar:
        return _restaurar(args, data_dir, db_path)
    db = Database(db_path)
    try:
        activity = ClientActivity()
        server, port = make_server(args.porta, db, explicit_port=args.porta != DEFAULT_PORT,
                                   activity=activity, data_dir=data_dir)
    except RuntimeError as e:
        print(f"[erro] {e}", file=sys.stderr)
        db.close()
        return 1

    url = f"http://127.0.0.1:{port}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()

    if args.verificar:
        status = db.integrity_check()
        try:
            with urllib.request.urlopen(url + "api/health", timeout=3) as r:
                health = r.status == 200
        except OSError:
            health = False
        print(f"banco: {status} | api: {'ok' if health else 'FALHOU'} | porta: {port}")
        server.shutdown()
        server.server_close()
        db.close()
        return 0 if status == "ok" and health else 1

    print("=" * 58)
    print("  Sistema de Registro — Biblioteca Pública Municipal")
    print(f"  Endereço : {url}")
    print(f"  Banco    : {db_path}")
    print(f"  Porta    : {port}")
    if args.porta != DEFAULT_PORT:
        print("  (porta fixada por --porta)")
    print("  Encerre com Ctrl+C (segure até o servidor desligar)")
    print("=" * 58)

    (data_dir / MARCA_SERVIDOR).write_text(str(os.getpid()))
    threading.Thread(target=_laco_backup, args=(db, data_dir), daemon=True, name="backup-diario").start()

    # Marca de uso único: lida e apagada já. Só vale na MESMA porta (a aba antiga não acha outra).
    marca = data_dir / MARCA_ABA
    try:
        aba_anterior = marca.read_text().strip() == str(port)
        marca.unlink()
    except OSError:
        aba_anterior = False

    try:
        if not args.sem_navegador:
            if aba_anterior:
                print(f"  Aguardando a aba que já estava aberta reconectar (até {ESPERA_ABA_S} s)...")
            if aba_anterior and activity.event.wait(ESPERA_ABA_S):
                print("  A aba que já estava aberta reconectou — nenhuma aba nova aberta.")
            else:
                # Socket já está aceitando e a thread já serve — browser nunca chega antes
                time.sleep(0.3)
                webbrowser.open(url)
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nEncerrando (checkpoint do banco)...")
    finally:
        # Ctrl+C segurado repete o SIGINT: o db.close() (checkpoint) roda aconteça o que acontecer antes.
        try:
            server.shutdown()
            server.server_close()
            _backup_seguro(backup.make_backup, db, data_dir)   # regrava o de hoje: estado do fim do dia
            if activity.last is not None and time.monotonic() - activity.last < ABA_ATIVA_S:
                (data_dir / MARCA_ABA).write_text(str(port))
        except (OSError, KeyboardInterrupt):
            pass  # marca é conveniência: nunca pode impedir o fechamento do banco
        finally:
            db.close()
            (data_dir / MARCA_SERVIDOR).unlink(missing_ok=True)
        print("Servidor encerrado. Até a próxima!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
