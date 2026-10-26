"""Camada de persistência do Sistema da Biblioteca — SQLite durável.

Desenhado para sobreviver a cortes de energia:
  - journal_mode=WAL      → escritas vão ao WAL file e viram commit atômico;
  - synchronous=FULL      → cada commit é fsync'ado no disco antes de confirmar
                            (pior caso numa queda: o último commit existe ou não,
                             nunca um estado parcial/corrompido);
  - busy_timeout          → leituras/escritas de outras threads esperam o lock;
  - lock de processo      → o ThreadingHTTPServer atende em várias threads,
                            então toda operação passa por um threading.Lock.

O valor armazenado é uma STRING opaca (exatamente a string que o
localStorage guardaria) — envelopes JSON {iv,data} chegam aqui já cifrados
no cliente. O servidor nunca vê PII em claro.
"""

import sqlite3
import threading
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
)
"""


class Database:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")   # efetivo no arquivo, uma vez
        self._conn.execute("PRAGMA synchronous=FULL")   # durabilidade sob corte de energia
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(_SCHEMA)
        self._conn.execute("PRAGMA user_version=1")
        self._conn.commit()

    def get(self, key):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)
            ).fetchone()
        return row[0] if row else None

    def put(self, key, value):
        with self._lock:
            self._conn.execute(
                "INSERT INTO kv (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            self._conn.commit()

    def delete(self, key):
        with self._lock:
            self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))
            self._conn.commit()

    def get_many(self, keys):
        out = {k: None for k in keys}
        if not keys:
            return out
        with self._lock:
            ph = ",".join("?" * len(keys))
            for row in self._conn.execute(
                f"SELECT key, value FROM kv WHERE key IN ({ph})", list(keys)
            ):
                out[row[0]] = row[1]
        return out

    def put_many(self, pairs, deletes=()):
        """Transação única — usado na restauração de backup (tudo-ou-nada)."""
        with self._lock:
            try:
                for key, value in pairs.items():
                    self._conn.execute(
                        "INSERT INTO kv (key, value) VALUES (?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        (key, value),
                    )
                for key in deletes:
                    self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    def integrity_check(self):
        with self._lock:
            return self._conn.execute("PRAGMA integrity_check").fetchone()[0]

    def backup_to(self, path):
        """Cópia consistente do banco (online, com o sistema em uso) num arquivo único."""
        with self._lock:
            dst = sqlite3.connect(str(path))
            try:
                self._conn.backup(dst)
                # Arquivo autocontido (sem -wal/-shm ao lado): seguro para Ctrl+C / Ctrl+V
                dst.execute("PRAGMA journal_mode=DELETE")
            finally:
                dst.close()

    def restore_from(self, path):
        """Substitui todo o conteúdo do banco pelo do arquivo (commit único do SQLite)."""
        with self._lock:
            src = sqlite3.connect(str(path))
            try:
                src.backup(self._conn)
            finally:
                src.close()

    def close(self):
        with self._lock:
            # Checkpoint do WAL + fechamento limpo (Ctrl+C → arquivos -wal/-shm resolvidos)
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._conn.close()
