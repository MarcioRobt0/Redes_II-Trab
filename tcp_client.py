import socket
import hashlib
import os
import sys
import csv
import logging
import time
import argparse
from datetime import datetime
from typing import Optional

# Constantes
# -------------------------------------
DEFAULT_HOST    = "127.0.0.1"
DEFAULT_PORT    = 5001
CHUNK_SIZE      = 4096         # bytes por envio no stream TCP
META_TERMINATOR = b"\r\n\r\n"
RESPONSE_BUFFER = 64           # bytes para ler a resposta OK/AUTH_FAIL
LOG_FILE        = "logs_tcp.csv"


# Logging
# -------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [TCP-CLIENT] %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("tcp_client")


# Exceções customizadas
# -------------------------------------
class TCPTransferError(Exception):
    """Erro irrecuperável durante a transferência TCP"""


class AuthenticationError(TCPTransferError):
    """Servidor rejeitou o X-Custom-Auth"""


# Helpers
# -------------------------------------

def build_auth_token(matricula: str, nome: str) -> str:
    """Gera SHA-256 hex de 'matricula+nome' — identidade do aluno"""
    raw = (matricula + nome).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_metadata(auth_token: str, filename: str, file_size: int) -> bytes:
    """
    Monta o bloco de metadados no formato de cabeçalhos HTTP-like:
        X-Custom-Auth: <sha256hex>\r\n
        File-Name: <nome_do_arquivo>\r\n
        File-Size: <bytes>\r\n
        \r\n
    """
    lines = [
        f"X-Custom-Auth: {auth_token}",
        f"File-Name: {os.path.basename(filename)}",
        f"File-Size: {file_size}",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8")


def recv_response(sock: socket.socket, expected: bytes = b"OK\r\n") -> str:
    # Lê a resposta do servidor após envio de metadados
    # Retorna a string recebida (stripped)
    # Levanta AuthenticationError se o servidor recusar

    raw = b""
    while not raw.endswith(b"\r\n"):
        chunk = sock.recv(RESPONSE_BUFFER)
        if not chunk:
            raise TCPTransferError("Servidor encerrou a conexão antes de responder.")
        raw += chunk

    response = raw.strip().decode("utf-8", errors="replace")
    log.debug("Resposta do servidor: '%s'", response)

    if raw.strip() == b"AUTH_FAIL":
        raise AuthenticationError("Servidor recusou a autenticação (X-Custom-Auth inválido).")
    if raw.strip() != b"OK":
        raise TCPTransferError(f"Resposta inesperada do servidor: '{response}'")

    return response


def save_log(record: dict, log_file: str = LOG_FILE) -> None:
    ''' Salva métricas no CSV de log '''

    file_exists = os.path.isfile(log_file)
    fieldnames  = [
        "timestamp", "scenario", "filename", "file_size_bytes",
        "elapsed_s", "throughput_mbps", "chunks_sent",
    ]

    with open(log_file, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(record)

    log.info("Métricas salvas em '%s'.", log_file)


# Cliente TCP
# -------------------------------------
class TCPClient:
    """
    Cliente TCP de transferência de arquivos com coleta de métricas.

    Parâmetros
        server_host : IP ou hostname do servidor
        server_port : porta TCP do servidor
        matricula   : matrícula do aluno (compõe X-Custom-Auth)
        nome        : nome do aluno
        chunk_size  : tamanho de cada bloco de envio (bytes)
        log_file    : caminho do CSV de métricas
        scenario    : rótulo do cenário de teste (ex: "A", "B", "C")
    """

    def __init__(
        self,
        server_host: str = DEFAULT_HOST,
        server_port: int = DEFAULT_PORT,
        matricula: str   = "20239000313",
        nome: str        = "Marcio Rodrigues",
        chunk_size: int  = CHUNK_SIZE,
        log_file: str    = LOG_FILE,
        scenario: str    = "A",
    ):
        self.server_addr  = (server_host, server_port)
        self.matricula    = matricula
        self.nome         = nome
        self.chunk_size   = chunk_size
        self.log_file     = log_file
        self.scenario     = scenario
        self.auth_token   = build_auth_token(matricula, nome)

        log.info("Cliente TCP → %s:%d", *self.server_addr)
        log.info("X-Custom-Auth : %s", self.auth_token)

    # interface
    def send_file(self, filepath: str) -> dict:
        """
        Envia um arquivo completo ao servidor TCP.

        Retorna
            dict com métricas:
            {
                "timestamp":        str,    # ISO-8601
                "scenario":         str,    # rótulo do cenário
                "filename":         str,    # nome do arquivo
                "file_size_bytes":  int,    # tamanho original
                "elapsed_s":        float,  # segundos (apenas transferência de dados)
                "throughput_mbps":  float,  # Megabits por segundo
                "chunks_sent":      int,    # número de chunks enviados
            }

        Levanta
        FileNotFoundError   - arquivo não encontrado
        TCPTransferError    - falha de conexão ou envio
        AuthenticationError - servidor recusou auth
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Arquivo não encontrado: {filepath}")

        file_size = os.path.getsize(filepath)
        filename  = os.path.basename(filepath)
        log.info("Arquivo: '%s' | %d bytes", filename, file_size)

        # Monta metadados
        metadata = build_metadata(self.auth_token, filename, file_size)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # Conecta
            log.info("Conectando a %s:%d…", *self.server_addr)
            try:
                sock.connect(self.server_addr)
            except (ConnectionRefusedError, socket.timeout) as err:
                raise TCPTransferError(f"Falha ao conectar: {err}") from err

            log.info("Conexão estabelecida.")

            # Envia metadados
            log.debug("Enviando metadados (%d bytes)…", len(metadata))
            sock.sendall(metadata)

            # Aguarda confirmação do servidor 
            recv_response(sock)   # levanta AuthenticationError se falhar
            log.info("Autenticação confirmada pelo servidor. Iniciando transferência…")

            # Transferência de dados 
            bytes_sent   = 0
            chunks_sent  = 0
            t_start      = time.perf_counter()   # início do timer

            with open(filepath, "rb") as fh:
                while True:
                    chunk = fh.read(self.chunk_size)
                    if not chunk:
                        break
                    try:
                        sock.sendall(chunk)
                    except socket.error as err:
                        raise TCPTransferError(f"Erro ao enviar dados: {err}") from err
                    bytes_sent  += len(chunk)
                    chunks_sent += 1
                    log.debug(
                        "Enviado chunk %d | %d/%d bytes (%.1f%%)",
                        chunks_sent, bytes_sent, file_size,
                        100.0 * bytes_sent / file_size if file_size else 100.0,
                    )

            t_end = time.perf_counter()     # fim do timer

            # Calcula métricas 
            elapsed         = t_end - t_start
            throughput_bps  = (bytes_sent * 8) / elapsed if elapsed > 0 else 0
            throughput_mbps = throughput_bps / 1_000_000

            stats = {
                "timestamp":       datetime.now().isoformat(timespec="seconds"),
                "scenario":        self.scenario,
                "filename":        filename,
                "file_size_bytes": file_size,
                "elapsed_s":       round(elapsed, 6),
                "throughput_mbps": round(throughput_mbps, 6),
                "chunks_sent":     chunks_sent,
            }

            return stats

        finally:
            sock.close()
            log.debug("Socket encerrado.")

    def run(self, filepath: str) -> dict:
        """ Executa send_file(), exibe resumo no terminal e salva no CSV """
        stats = self.send_file(filepath)

        # Exibe no terminal
        print("\n" + "=" * 50)
        print("      MÉTRICAS — TRANSFERÊNCIA TCP")
        print("=" * 50)
        print(f"  Arquivo       : {stats['filename']}")
        print(f"  Tamanho       : {stats['file_size_bytes']:,} bytes")
        print(f"  Cenário       : {stats['scenario']}")
        print(f"  Tempo total   : {stats['elapsed_s']:.6f} s")
        print(f"  Throughput    : {stats['throughput_mbps']:.4f} Mbps")
        print(f"  Chunks env.   : {stats['chunks_sent']}")
        print("=" * 50 + "\n")

        # Salva no CSV
        save_log(stats, self.log_file)

        return stats


# Interface do terminal
# -------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Cliente TCP Baseline — Redes II UFPI")
    p.add_argument("filepath",                         help="Caminho do arquivo a enviar")
    p.add_argument("--host",      default=DEFAULT_HOST,help="IP do servidor")
    p.add_argument("--port",      type=int, default=DEFAULT_PORT, help="Porta TCP")
    p.add_argument("--matricula", default="20239000313", help="Matrícula do aluno")
    p.add_argument("--nome",      default="Marcio Rodrigues",help="Nome do aluno")
    p.add_argument("--chunk",     type=int, default=CHUNK_SIZE,
                   help=f"Tamanho do chunk em bytes (padrão: {CHUNK_SIZE})")
    p.add_argument("--log-file",  default=LOG_FILE,    help="Arquivo CSV de métricas")
    p.add_argument("--scenario",  default="A",
                   help="Rótulo do cenário de teste (A, B ou C)")
    return p.parse_args()


if __name__ == "__main__":
    args   = parse_args()
    client = TCPClient(
        server_host = args.host,
        server_port = args.port,
        matricula   = args.matricula,
        nome        = args.nome,
        chunk_size  = args.chunk,
        log_file    = args.log_file,
        scenario    = args.scenario,
    )
    try:
        client.run(args.filepath)
    except (FileNotFoundError, TCPTransferError, AuthenticationError) as err:
        log.error("ERRO FATAL: %s", err)
        sys.exit(1)