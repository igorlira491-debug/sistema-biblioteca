"""Backup diário automático do banco (Bloco 6) — stdlib apenas.

O banco já guarda envelopes cifrados no cliente, então o backup é uma cópia
do arquivo SQLite (sem ver PII em claro). Um arquivo por dia em
<data>/backups/backup_AAAA-MM-DD.db; os 30 mais recentes são mantidos.

À prova de queda de energia: grava num .tmp, confere (integrity_check),
fsync e só então renomeia para o nome final (os.replace é atômico). Uma queda
no meio deixa só a sobra .tmp — nunca um backup pela metade com nome de válido.
"""

import os
import sqlite3
import threading
from datetime import date, datetime
from pathlib import Path

MANTER = 30
ultimo_erro = None            # texto da última falha (exibido na aba Segurança); None = ok
_lock = threading.Lock()      # laço de 1 h e backup do Ctrl+C nunca disputam o mesmo .tmp


def backup_dir(data_dir):
    d = Path(data_dir) / "backups"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _fsync_dir(d):
    fd = os.open(d, os.O_RDONLY)
    try:
        os.fsync(fd)          # o rename só é durável depois do fsync do diretório
    finally:
        os.close(fd)


_SOBRAS = ("", "-wal", "-shm", "-journal")   # o .tmp e os arquivos que o SQLite cria ao lado dele


def _limpar_tmp(tmp):
    for suf in _SOBRAS:
        Path(str(tmp) + suf).unlink(missing_ok=True)


def _snapshot(db, final):
    """Cópia do banco em `final` à prova de queda: .tmp → verifica → fsync → rename atômico."""
    tmp = final.parent / f".{final.name}.tmp"
    try:
        _limpar_tmp(tmp)
        db.backup_to(tmp)
        check = sqlite3.connect(str(tmp))
        try:
            resultado = check.execute("PRAGMA integrity_check").fetchone()[0]
        finally:
            check.close()
        if resultado != "ok":
            raise RuntimeError(f"backup não passou na verificação ({resultado})")
        with open(tmp, "rb+") as f:
            os.fsync(f.fileno())
        os.replace(tmp, final)
        _fsync_dir(final.parent)
    finally:
        _limpar_tmp(tmp)
    return final


def make_backup(db, data_dir, today=None):
    """Grava (ou regrava) o backup do dia. Devolve o caminho final."""
    with _lock:
        d = backup_dir(data_dir)
        return _snapshot(db, d / f"backup_{(today or date.today()).isoformat()}.db")


def ensure_today(db, data_dir, today=None):
    """Cria o backup do dia se ainda não existe. Devolve o caminho criado ou None."""
    d = backup_dir(data_dir)
    with _lock:
        for sobra in d.glob(".*.db.tmp*"):   # backup cortado por queda de energia (+ -wal/-shm/-journal)
            sobra.unlink(missing_ok=True)
    final = d / f"backup_{(today or date.today()).isoformat()}.db"
    if final.exists():
        return None
    return make_backup(db, data_dir, today)


def _backups(d):
    # Só backup_AAAA-MM-DD.db: antes_restaurar_* e arquivos do operador nunca entram na conta
    return sorted(p for p in d.glob("backup_????-??-??.db") if p.stem[7:].replace("-", "").isdigit())


def prune(data_dir, keep=MANTER, today=None):
    """Apaga os backups mais antigos além dos `keep` mais recentes."""
    hoje = f"backup_{(today or date.today()).isoformat()}.db"
    with _lock:
        # O de hoje nunca sai: com o relógio errado (bateria da placa-mãe) ele pode ordenar como o mais velho
        velhos = [p for p in _backups(backup_dir(data_dir))[:-keep] if p.name != hoje]
        for p in velhos:
            p.unlink(missing_ok=True)
        return velhos


def status(data_dir):
    try:
        com_hora = [(p.stat().st_mtime, p) for p in _backups(backup_dir(data_dir))]
    except OSError as e:   # inclui arquivo apagado entre a listagem e o stat
        return {"ultimo": None, "arquivo": None, "total": 0, "erro": ultimo_erro or str(e)}
    # "Último" = gravado por último (não o maior nome: relógio errado daria nome fora de ordem)
    mtime, ultimo = max(com_hora, key=lambda t: t[0]) if com_hora else (None, None)
    return {
        "ultimo": datetime.fromtimestamp(mtime).isoformat(timespec="seconds") if ultimo else None,
        "arquivo": ultimo.name if ultimo else None,
        "total": len(com_hora),
        "erro": ultimo_erro,
    }


def restore(src, db, data_dir):
    """Restaura `src` sobre o banco `db` (servidor parado). Devolve a cópia de segurança do banco atual."""
    src = Path(src)
    valido = False
    if src.is_file():
        try:
            con = sqlite3.connect(str(src))
            try:
                valido = (con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                          and con.execute("SELECT 1 FROM kv WHERE key = 'bpa_system'").fetchone() is not None)
            finally:
                con.close()
        except sqlite3.DatabaseError:
            valido = False
    if not valido:
        raise ValueError(f"arquivo não é um backup válido do sistema: {src}")
    with _lock:
        seguranca = _snapshot(db, backup_dir(data_dir) / f"antes_restaurar_{datetime.now():%Y-%m-%d_%H%M%S}.db")
        db.restore_from(src)
    return seguranca
