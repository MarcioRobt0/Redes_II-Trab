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
from dns_client import resolve_dns

# Constantes
# -------------------------------------
DEFAULT_HOST    = "127.0.0.1"
DEFAULT_PORT    = 5001
CHUNK_SIZE      = 4096         # bytes por envio no stream TCP
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


def save_log(record: dict, log_file: str = LOG_FILE) -> None:
    ''' Salva métricas no CSV de log '''
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

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
    Cliente TCP de transferência de arquivos (HTTP GET) com coleta de métricas.
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
        self.server_host  = server_host
        self.server_port  = server_port
        self.matricula    = matricula
        self.nome         = nome
        self.chunk_size   = chunk_size
        self.log_file     = log_file
        self.scenario     = scenario
        self.auth_token   = build_auth_token(matricula, nome)

        log.info("Cliente TCP → %s:%d", self.server_host, self.server_port)
        log.info("X-Custom-Auth : %s", self.auth_token)

    # interface
    def send_file(self, filepath: str) -> dict:
        """
        Requisita um arquivo via HTTP GET e o salva localmente.
        (Mantido nome 'send_file' para compatibilidade com os scripts de teste).
        """
        filename = os.path.basename(filepath)
        log.info("Requisitando arquivo via HTTP GET: '%s'", filename)

        # 1. Resolução DNS local
        try:
            resolved_ip = resolve_dns(self.server_host)
        except Exception as e:
            raise TCPTransferError(f"DNS Resolution failed: {e}") from e

        server_addr = (resolved_ip, self.server_port)
        log.info("DNS resolvido: %s -> %s", self.server_host, resolved_ip)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            # conecta
            log.info("Conectando a %s:%d…", *server_addr)
            try:
                sock.connect(server_addr)
            except (ConnectionRefusedError, socket.timeout) as err:
                raise TCPTransferError(f"Falha ao conectar: {err}") from err

            log.info("Conexão estabelecida.")

            # Envia HTTP GET request
            request = f"GET /{filename} HTTP/1.1\r\nHost: {self.server_host}\r\nUser-Agent: HTTPClient\r\n\r\n"
            sock.sendall(request.encode("utf-8"))

            # Lê cabeçalhos HTTP
            header_bytes = b""
            while b"\r\n\r\n" not in header_bytes:
                chunk = sock.recv(1)
                if not chunk:
                    raise TCPTransferError("Conexão encerrada pelo servidor antes dos cabeçalhos.")
                header_bytes += chunk

            header_part, _, remaining_data = header_bytes.partition(b"\r\n\r\n")
            headers_str = header_part.decode("utf-8", errors="replace")
            lines = headers_str.split("\r\n")

            # Status line
            status_line = lines[0]
            parts = status_line.split()
            if len(parts) < 3:
                raise TCPTransferError(f"Resposta HTTP inválida: {status_line}")
            status_code = int(parts[1])

            # Parser de cabeçalhos
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            if status_code == 404:
                raise TCPTransferError(f"Erro 404: Arquivo '{filename}' não encontrado no servidor.")
            elif status_code != 200:
                raise TCPTransferError(f"Erro HTTP {status_code}: {status_line}")

            content_length = int(headers.get("content-length", 0))
            server_auth = headers.get("x-custom-auth", "")

            log.info("Cabeçalhos HTTP recebidos | Content-Length=%d | X-Custom-Auth=%s", content_length, server_auth)

            # Recebe o corpo da resposta HTTP 
            output_dir = "received_tcp"
            os.makedirs(output_dir, exist_ok=True)
            saved_path = os.path.join(output_dir, filename)

            bytes_recv = 0
            chunks_sent = 0
            t_start = time.perf_counter()

            with open(saved_path, "wb") as fh:
                if remaining_data:
                    fh.write(remaining_data)
                    bytes_recv += len(remaining_data)
                    chunks_sent += 1

                while bytes_recv < content_length:
                    remaining = content_length - bytes_recv
                    to_read = min(self.chunk_size, remaining)
                    chunk = sock.recv(to_read)
                    if not chunk:
                        raise TCPTransferError("Servidor fechou a conexão prematuramente durante o download.")
                    fh.write(chunk)
                    bytes_recv += len(chunk)
                    chunks_sent += 1

            t_end = time.perf_counter()
            elapsed = t_end - t_start
            throughput_bps = (bytes_recv * 8) / elapsed if elapsed > 0 else 0
            throughput_mbps = throughput_bps / 1_000_000

            stats = {
                "timestamp":       datetime.now().isoformat(timespec="seconds"),
                "scenario":        self.scenario,
                "filename":        filename,
                "file_size_bytes": bytes_recv,
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
        print("      MÉTRICAS — TRANSFERÊNCIA HTTP/TCP")
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
    p = argparse.ArgumentParser(description="Cliente TCP HTTP/1.1 — Redes II UFPI")
    p.add_argument("filepath",                         help="Nome do arquivo a requisitar")
    p.add_argument("--host",      default=DEFAULT_HOST,help="Hostname do servidor")
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