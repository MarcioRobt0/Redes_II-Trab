import socket
import struct
import binascii
import hashlib
import os
import sys
import logging
import time
import argparse
from typing import Tuple

# Constantes do protocolo
# -----------------------------
FLAG_DATA = 0x01
FLAG_ACK  = 0x02
FLAG_FIN  = 0x03

HEADER_FORMAT = "!IBI"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 9 bytes

AUTH_SEPARATOR = b"\n"

SERVER_TIMEOUT = 15.0 #segundos


# Logging
# -----------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [SERVER] %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("rudp_server")


# Helpers de cabeçalho
# -----------------------------
def build_auth_token(matricula: str, nome: str) -> bytes:
    raw = (matricula + nome).encode("utf-8")
    return hashlib.sha256(raw).hexdigest().encode("ascii")   # 64 bytes hex


def compute_checksum(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def pack_header(seq_num: int, flag: int, checksum: int) -> bytes:
    return struct.pack(HEADER_FORMAT, seq_num, flag, checksum)


def unpack_header(raw: bytes):
    return struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])


def build_packet(seq_num: int, flag: int, auth_token: bytes, payload: bytes) -> bytes:
    crc    = compute_checksum(payload)
    header = pack_header(seq_num, flag, crc)
    return header + auth_token + AUTH_SEPARATOR + payload


def parse_packet(raw_packet: bytes):
    if len(raw_packet) < HEADER_SIZE:
        raise ValueError(f"Pacote muito curto: {len(raw_packet)} bytes")

    seq_num, flag, checksum = unpack_header(raw_packet)
    rest = raw_packet[HEADER_SIZE:]

    sep_idx = rest.find(AUTH_SEPARATOR)
    if sep_idx == -1:
        auth_token = b""
        payload    = rest
    else:
        auth_token = rest[:sep_idx]
        payload    = rest[sep_idx + len(AUTH_SEPARATOR):]

    return seq_num, flag, checksum, auth_token, payload


def parse_ack(raw_packet: bytes) -> Tuple[int, int]:
    if len(raw_packet) < HEADER_SIZE:
        raise ValueError("ACK muito curto")
    seq_num, flag, _ = unpack_header(raw_packet)
    return seq_num, flag


# Servidor
# -----------------------------

class RUDPServer:
    """
    Servidor HTTP sobre R-UDP (Stop-and-Wait)
    """

    def __init__(
        self,
        host: str       = "",
        port: int       = 9000,
        output_dir: str = "received_files",
        matricula: str  = "20239000313",
        nome: str       = "Marcio Rodrigues",
    ):
        self.host       = host
        self.port       = port
        self.output_dir = output_dir
        self.matricula  = matricula
        self.nome       = nome

        self.expected_auth = build_auth_token(matricula, nome)

        os.makedirs(output_dir, exist_ok=True)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.settimeout(SERVER_TIMEOUT)

        log.info("Servidor R-UDP aguardando em %s:%d", host or "0.0.0.0", port)
        log.info("Token de auth esperado : %s", self.expected_auth.decode())

    def _send_ack(self, addr: tuple, seq_num: int) -> None:
        """Monta e envia um pacote ACK para o cliente"""
        ack_payload  = b""
        ack_checksum = compute_checksum(ack_payload)
        header       = pack_header(seq_num, FLAG_ACK, ack_checksum)
        ack_packet   = header + self.expected_auth + AUTH_SEPARATOR + ack_payload
        self.sock.sendto(ack_packet, addr)
        log.debug("ACK seq=%d → %s:%d", seq_num, *addr)

    def _send_packet_saw(self, client_addr: tuple, packet: bytes, expected_seq: int, max_retries: int = 20) -> None:
        """Envia `packet` e aguarda ACK com seq == expected_seq via Stop-and-Wait"""
        timeout = 2.0
        
        orig_timeout = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        
        for attempt in range(1, max_retries + 1):
            try:
                self.sock.sendto(packet, client_addr)
                log.debug("[SERVER-SND] → PKT seq=%d (tentativa %d/%d) para %s:%d", expected_seq, attempt, max_retries, *client_addr)
            except socket.error as err:
                log.error("Erro ao enviar seq=%d para %s:%d: %s", expected_seq, client_addr[0], client_addr[1], err)
                break

            # Aguarda ACK
            while True:
                try:
                    raw_ack, addr = self.sock.recvfrom(65535)
                except socket.timeout:
                    log.warning("[SERVER-SND] Timeout seq=%d (tentativa %d)", expected_seq, attempt)
                    break
                except socket.error as err:
                    log.error("[SERVER-SND] Erro socket aguardando ACK seq=%d: %s", expected_seq, err)
                    break

                if addr != client_addr:
                    continue

                try:
                    ack_seq, ack_flag = parse_ack(raw_ack)
                except (ValueError, struct.error) as err:
                    log.warning("[SERVER-SND] ACK malformado: %s", err)
                    continue

                if ack_flag != FLAG_ACK:
                    continue

                if ack_seq != expected_seq:
                    log.warning("[SERVER-SND] ACK seq=%d ≠ esperado=%d — ignorado.", ack_seq, expected_seq)
                    continue

                log.debug("[SERVER-SND] ✓ ACK seq=%d recebido.", ack_seq)
                self.sock.settimeout(orig_timeout)
                return

        self.sock.settimeout(orig_timeout)
        raise RuntimeError(f"Falha de retransmissão após {max_retries} tentativas para o seq={expected_seq}")

    def serve_forever(self) -> None:
        log.info("Servidor pronto. Aguardando transações HTTP/R-UDP…")
        while True:
            try:
                self._handle_request()
            except KeyboardInterrupt:
                log.info("Servidor encerrado pelo usuário.")
                break
            except Exception as exc:
                log.error("Erro inesperado: %s — aguardando próxima transação.", exc)

        self.sock.close()

    def _handle_request(self) -> None:
        log.info("Aguardando primeiro pacote da requisição…")
        
        client_addr = None
        expected_seq = 0
        request_bytes = b""

        while True:
            try:
                raw_packet, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                if client_addr is None:
                    continue
                log.warning("Timeout de inatividade aguardando requisição de %s:%d.", *client_addr)
                break
            except socket.error as err:
                log.error("Erro de socket ao receber: %s", err)
                break

            if client_addr is None:
                client_addr = addr
                log.info("Nova requisição HTTP/R-UDP de %s:%d", *addr)

            if addr != client_addr:
                log.warning("Pacote ignorado de %s:%d (transação em curso)", *addr)
                continue

            try:
                seq_num, flag, recv_checksum, auth_token, payload = parse_packet(raw_packet)
            except (ValueError, struct.error) as err:
                log.warning("Pacote malformado ignorado: %s", err)
                continue

            # Valida auth token (apenas log)
            if auth_token and auth_token != self.expected_auth:
                log.warning("Token de auth inválido recebido do cliente.")

            # Fim da transmissão do request
            if flag == FLAG_FIN:
                log.info("FIN recebido da requisição (seq=%d).", seq_num)
                self._send_ack(client_addr, seq_num)
                break

            if flag == FLAG_DATA:
                calc_checksum = compute_checksum(payload)
                if calc_checksum != recv_checksum:
                    log.warning("Checksum INVÁLIDO seq=%d.", seq_num)
                    continue

                if seq_num == expected_seq:
                    request_bytes += payload
                    self._send_ack(client_addr, seq_num)
                    expected_seq += 1
                elif seq_num < expected_seq:
                    self._send_ack(client_addr, seq_num)

        if not request_bytes:
            log.warning("Nenhum byte de requisição recebido.")
            return

        # Processa requisição HTTP GET
        request_text = request_bytes.decode("utf-8", errors="replace")
        lines = request_text.split("\r\n")
        request_line = lines[0]
        parts = request_line.split()

        if len(parts) < 3 or parts[0].upper() != "GET":
            log.warning("Requisição inválida: '%s'", request_line)
            response_bytes = b"HTTP/1.1 400 Bad Request\r\n\r\n"
        else:
            filename = parts[1].lstrip("/")
            log.info("Recurso solicitado via R-UDP: '%s'", filename)

            if os.path.isfile(filename):
                file_size = os.path.getsize(filename)
                header = (
                    f"HTTP/1.1 200 OK\r\n"
                    f"Content-Type: application/octet-stream\r\n"
                    f"Content-Length: {file_size}\r\n"
                    f"X-Custom-Auth: {self.expected_auth.decode()}\r\n"
                    f"\r\n"
                )
                with open(filename, "rb") as fh:
                    file_content = fh.read()
                response_bytes = header.encode("utf-8") + file_content
                log.info("Servindo arquivo '%s' (%d bytes) via R-UDP.", filename, file_size)
            else:
                log.warning("Arquivo '%s' não encontrado (404) via R-UDP.", filename)
                error_body = "<html><body><h1>404 Not Found</h1></body></html>"
                header = (
                    f"HTTP/1.1 404 Not Found\r\n"
                    f"Content-Type: text/html\r\n"
                    f"Content-Length: {len(error_body)}\r\n"
                    f"X-Custom-Auth: {self.expected_auth.decode()}\r\n"
                    f"\r\n"
                )
                response_bytes = header.encode("utf-8") + error_body.encode("utf-8")

        # Envia a resposta HTTP de volta para o cliente usando R-UDP
        log.info("Enviando resposta HTTP...")
        chunk_size = 1024
        total_len = len(response_bytes)
        offset = 0
        seq_num = 0

        while offset < total_len:
            chunk = response_bytes[offset:offset+chunk_size]
            packet = build_packet(seq_num, FLAG_DATA, self.expected_auth, chunk)
            self._send_packet_saw(client_addr, packet, seq_num)
            offset += len(chunk)
            seq_num += 1

        # Envia FIN (com limite de retentativas menor para o encerramento)
        fin_packet = build_packet(seq_num, FLAG_FIN, self.expected_auth, b"")
        self._send_packet_saw(client_addr, fin_packet, seq_num, max_retries=5)
        log.info("Transação R-UDP concluída para %s:%d.", *client_addr)


# Interface do terminal
# -----------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Servidor HTTP/R-UDP — Redes II UFPI")
    p.add_argument("--host", default="", help="Interface de bind (padrão: todas)")
    p.add_argument("--port", type=int, default=9000, help="Porta UDP (padrão: 9000)")
    p.add_argument("--output-dir", default="received_files", help="Diretório de saída (não usado em HTTP GET)")
    p.add_argument("--matricula", default="20239000313", help="Matrícula do aluno")
    p.add_argument("--nome", default="Marcio Rodrigues", help="Nome do aluno")
    return p.parse_args()


if __name__ == "__main__":
    args   = parse_args()
    server = RUDPServer(
        host       = args.host,
        port       = args.port,
        output_dir = args.output_dir,
        matricula  = args.matricula,
        nome       = args.nome,
    )
    server.serve_forever()