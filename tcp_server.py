import socket
import hashlib
import os
import sys
import logging
import time
import argparse
import threading
from typing import Optional

# Constantes
# ------------------------- 
DEFAULT_HOST        = ""          # bind em todas as interfaces
DEFAULT_PORT        = 5001
RECV_BUFFER         = 4096
OUTPUT_DIR          = "received_tcp"


# Logging
# -------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [TCP-SERVER] %(levelname)-8s [%(threadName)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("tcp_server")


# Helpers
# -------------------------

def build_auth_token(matricula: str, nome: str) -> str:
    """Gera SHA-256 hex de 'matricula+nome' - identidade do aluno"""
    raw = (matricula + nome).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# Handler de cada conexão (thread isolada)
# -------------------------
def handle_client(conn: socket.socket, addr: tuple, expected_auth: str) -> None:
    """
    Processa uma conexão HTTP TCP completa:
      1. Lê e interpreta a requisição HTTP GET
      2. Valida o recurso solicitado
      3. Responde com 200 OK + arquivo ou 404 Not Found.
    """
    log.info("Conexão recebida de %s:%d", *addr)
    start_time   = time.perf_counter()

    try:
        # Lê a requisição HTTP até achar o terminador \r\n\r\n
        req_data = b""
        while b"\r\n\r\n" not in req_data:
            chunk = conn.recv(1024)
            if not chunk:
                break
            req_data += chunk

        if not req_data:
            log.warning("Conexão fechada sem dados de requisição.")
            return

        request_text = req_data.decode("utf-8", errors="replace")
        lines = request_text.split("\r\n")
        request_line = lines[0]
        parts = request_line.split()

        if len(parts) < 3 or parts[0].upper() != "GET":
            log.warning("Requisição inválida ou método não suportado: '%s'", request_line)
            # Retorna 400 Bad Request simplificado
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return

        path = parts[1]
        filename = path.lstrip("/")
        
        log.info("Recurso solicitado: '%s'", filename)

        if os.path.isfile(filename):
            file_size = os.path.getsize(filename)
            # Constrói cabeçalho 200 OK
            header = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {file_size}\r\n"
                f"X-Custom-Auth: {expected_auth}\r\n"
                f"\r\n"
            )
            conn.sendall(header.encode("utf-8"))

            # Envia conteúdo do arquivo em chunks
            bytes_sent = 0
            with open(filename, "rb") as fh:
                while True:
                    chunk = fh.read(RECV_BUFFER)
                    if not chunk:
                        break
                    conn.sendall(chunk)
                    bytes_sent += len(chunk)
            
            elapsed = time.perf_counter() - start_time
            log.info("Servido '%s' (%d bytes) com sucesso em %.4f s.", filename, bytes_sent, elapsed)

        else:
            log.warning("Recurso '%s' não encontrado. Retornando 404.", filename)
            error_body = "<html><body><h1>404 Not Found</h1></body></html>"
            header = (
                f"HTTP/1.1 404 Not Found\r\n"
                f"Content-Type: text/html\r\n"
                f"Content-Length: {len(error_body)}\r\n"
                f"X-Custom-Auth: {expected_auth}\r\n"
                f"\r\n"
            )
            conn.sendall(header.encode("utf-8") + error_body.encode("utf-8"))

    except Exception as err:
        log.error("Erro inesperado ao tratar %s:%d → %s", *addr, err)

    finally:
        conn.close()
        log.info("Conexão com %s:%d encerrada.", *addr)


# Servidor principal
# -------------------------

class TCPServer:
    """
    Servidor TCP de transferência de arquivos (Mini-Servidor HTTP/1.1)
    """

    def __init__(
        self,
        host: str       = DEFAULT_HOST,
        port: int       = DEFAULT_PORT,
        output_dir: str = OUTPUT_DIR,
        matricula: str  = "20239000313",
        nome: str       = "Marcio Rodrigues",
    ):
        self.host          = host
        self.port          = port
        self.output_dir    = output_dir
        self.expected_auth = build_auth_token(matricula, nome)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(5)

        log.info("Servidor HTTP/TCP escutando em %s:%d", host or "0.0.0.0", port)
        log.info("Token de auth esperado : %s", self.expected_auth)

    def serve_forever(self) -> None:
        log.info("Aguardando requisições HTTP…  (Ctrl+C para parar)")
        try:
            while True:
                try:
                    conn, addr = self.sock.accept()
                except socket.error as err:
                    log.error("Erro ao aceitar conexão: %s", err)
                    continue

                t = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, self.expected_auth),
                    daemon=True,
                    name=f"client-{addr[0]}:{addr[1]}",
                )
                t.start()

        except KeyboardInterrupt:
            log.info("Servidor encerrado pelo usuário.")
        finally:
            self.sock.close()


# Interface do terminal
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Servidor HTTP/TCP — Redes II UFPI")
    p.add_argument("--host", default=DEFAULT_HOST, help="Interface de bind")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="Porta TCP")
    p.add_argument("--output-dir", default=OUTPUT_DIR, help="Diretório de saída (não usado em HTTP GET, mas mantido por compatibilidade)")
    p.add_argument("--matricula", default="20239000313", help="Matrícula do aluno")
    p.add_argument("--nome", default="Marcio Rodrigues", help="Nome do aluno")
    return p.parse_args()


if __name__ == "__main__":
    args   = parse_args()
    server = TCPServer(
        host       = args.host,
        port       = args.port,
        output_dir = args.output_dir,
        matricula  = args.matricula,
        nome       = args.nome,
    )
    server.serve_forever()