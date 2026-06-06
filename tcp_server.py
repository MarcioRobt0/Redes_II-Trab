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
RECV_BUFFER         = 4096        # bytes por recvfrom no corpo do arquivo
META_BUFFER         = 4096        # bytes máximos para o bloco de metadados
META_TERMINATOR     = b"\r\n\r\n"
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


def parse_metadata(raw: bytes) -> dict:
    """
    Parseia o bloco de metadados enviado pelo cliente

    Formato esperado (terminado em b'\\r\\n\\r\\n'):
        X-Custom-Auth: <valor>\r\n
        File-Name: <nome>\r\n
        File-Size: <int>\r\n

    Retorna dict com chaves em minúsculas: 'x-custom-auth', 'file-name', 'file-size'
    Levanta ValueError se algum campo obrigatório estiver ausente
    """

    # Remove o terminador e divide em linhas
    text  = raw.rstrip(b"\r\n").decode("utf-8", errors="replace")
    lines = [l.strip() for l in text.split("\r\n") if l.strip()]

    fields: dict = {}
    for line in lines:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip().lower()] = value.strip()

    required = ("x-custom-auth", "file-name", "file-size")
    missing  = [f for f in required if f not in fields]
    if missing:
        raise ValueError(f"Metadados incompletos. Faltando: {missing}")

    fields["file-size"] = int(fields["file-size"])
    return fields


def recvall_until(sock: socket.socket, terminator: bytes, max_bytes: int = META_BUFFER) -> bytes:
    """
    Lê do socket byte a byte (ou em pequenos buffers) até encontrar `terminator`
    ou atingir `max_bytes`

    Retorna os bytes lidos (incluindo o terminador) ou levanta RuntimeError
    """
    buf = b""
    while len(buf) < max_bytes:
        chunk = sock.recv(1)
        if not chunk:
            raise RuntimeError("Conexão encerrada antes de receber metadados completos.")
        buf += chunk
        if buf.endswith(terminator):
            return buf
    raise RuntimeError(f"Metadados excederam {max_bytes} bytes sem encontrar terminador.")


# Handler de cada conexão (thread isolada)
# -------------------------
def handle_client(conn: socket.socket, addr: tuple, expected_auth: str, output_dir: str) -> None:
    """
    Processa uma conexão TCP completa:
      1. Lê e valida metadados
      2. Recebe o arquivo
      3. Salva no disco e loga métricas

    Executado em thread separada para permitir conexões simultâneas
    """
    log.info("Conexão recebida de %s:%d", *addr)
    start_time   = time.perf_counter()
    file_handle  = None
    saved_path   = None

    try:
        # Lê metadados
        try:
            raw_meta = recvall_until(conn, META_TERMINATOR)
        except RuntimeError as err:
            log.error("Erro lendo metadados: %s", err)
            return

        try:
            meta = parse_metadata(raw_meta)
        except ValueError as err:
            log.error("Metadados inválidos: %s", err)
            conn.sendall(b"AUTH_FAIL\r\n")
            return

        log.info(
            "Metadados recebidos | arquivo='%s' | tamanho=%d bytes | auth='%s…'",
            meta["file-name"],
            meta["file-size"],
            meta["x-custom-auth"][:16],
        )

        # Valida X-Custom-Auth 
        if meta["x-custom-auth"] != expected_auth:
            log.warning(
                "AUTH FALHOU | recebido=%s | esperado=%s",
                meta["x-custom-auth"],
                expected_auth,
            )
            conn.sendall(b"AUTH_FAIL\r\n")
            return

        log.info("Autenticação OK.")
        conn.sendall(b"OK\r\n")

        # Recebe o arquivo
        file_size  = meta["file-size"]
        safe_name  = os.path.basename(meta["file-name"]) or f"recv_{int(time.time())}.bin"
        saved_path = os.path.join(output_dir, safe_name)

        bytes_recv = 0
        file_handle = open(saved_path, "wb")

        data_start = time.perf_counter()   # mede apenas o tempo de transferência de dados

        while bytes_recv < file_size:
            remaining = file_size - bytes_recv
            to_read   = min(RECV_BUFFER, remaining)
            chunk     = conn.recv(to_read)
            if not chunk:
                log.warning("Conexão encerrada prematuramente (%d/%d bytes).", bytes_recv, file_size)
                break
            file_handle.write(chunk)
            bytes_recv += len(chunk)

        data_end = time.perf_counter()

        file_handle.close()
        file_handle = None

        # Métricas 
        total_elapsed = data_end - data_start
        throughput_bps  = (bytes_recv * 8) / total_elapsed if total_elapsed > 0 else 0
        throughput_mbps = throughput_bps / 1_000_000

        if bytes_recv == file_size:
            log.info(
                "Arquivo '%s' recebido com sucesso | %d bytes | %.4f s | %.4f Mbps",
                saved_path, bytes_recv, total_elapsed, throughput_mbps,
            )
        else:
            log.warning(
                "Arquivo INCOMPLETO '%s' | %d/%d bytes recebidos",
                saved_path, bytes_recv, file_size,
            )

    except Exception as err:
        log.error("Erro inesperado ao tratar %s:%d → %s", *addr, err)

    finally:
        if file_handle and not file_handle.closed:
            file_handle.close()
        conn.close()
        log.info("Conexão com %s:%d encerrada.", *addr)


# Servidor principal
# -------------------------

class TCPServer:
    """
    Servidor TCP de transferência de arquivos

    Aceita múltiplas conexões sequenciais (ou simultâneas via threads)
    Cada cliente é atendido em uma thread daemon independente
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

        os.makedirs(output_dir, exist_ok=True)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(5)

        log.info("Servidor TCP escutando em %s:%d", host or "0.0.0.0", port)
        log.info("Token de auth esperado : %s", self.expected_auth)

    def serve_forever(self) -> None:
        """Aceita conexões em loop. Cada cliente é despachado para uma thread"""
        log.info("Aguardando clientes…  (Ctrl+C para parar)")
        try:
            while True:
                try:
                    conn, addr = self.sock.accept()
                except socket.error as err:
                    log.error("Erro ao aceitar conexão: %s", err)
                    continue

                t = threading.Thread(
                    target=handle_client,
                    args=(conn, addr, self.expected_auth, self.output_dir),
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
    p = argparse.ArgumentParser(description="Servidor TCP Baseline — Redes II UFPI")
    p.add_argument("--host", default=DEFAULT_HOST, help="Interface de bind")
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help="Porta TCP")
    p.add_argument("--output-dir", default=OUTPUT_DIR, help="Diretório de saída")
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