import socket
import struct
import binascii
import hashlib
import os
import sys
import csv
import logging
import time
import argparse
from datetime import datetime, timezone
from typing import Tuple
from dns_client import resolve_dns

# Constantes do protocolo
# -----------------------------
FLAG_DATA   = 0x01
FLAG_ACK    = 0x02
FLAG_FIN    = 0x03

HEADER_FORMAT = "!IBI"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 9 bytes

AUTH_SEPARATOR = b"\n"

CHUNK_SIZE   = 1024    # bytes por pacote de dados
TIMEOUT      = 5.0     # segundos de espera por ACK
MAX_RETRIES  = 20      # máximo de retransmissões por pacote
LOG_FILE     = "logs_rudp.csv"


# Logging
# -----------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [CLIENT] %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("rudp_client")


# Exceções customizadas
# -----------------------------
class RUDPTransferError(Exception):
    """Levantada quando a transferência falha irrecuperavelmente"""


# Helpers de cabeçalho
# -----------------------------

def build_auth_token(matricula: str, nome: str) -> bytes:
    """Gera o hash SHA-256 de 'matricula+nome'
    """
    raw = (matricula + nome).encode("utf-8")
    return hashlib.sha256(raw).hexdigest().encode("ascii")   # 64 bytes


def compute_checksum(data: bytes) -> int:
    """CRC-32 sem sinal sobre os bytes de payload"""
    return binascii.crc32(data) & 0xFFFFFFFF


def pack_header(seq_num: int, flag: int, checksum: int) -> bytes:
    return struct.pack(HEADER_FORMAT, seq_num, flag, checksum)


def unpack_header(raw: bytes) -> Tuple[int, int, int]:
    return struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])


def build_packet(seq_num: int, flag: int, auth_token: bytes, payload: bytes) -> bytes:
    """Constrói o pacote completo"""
    crc    = compute_checksum(payload)
    header = pack_header(seq_num, flag, crc)
    return header + auth_token + AUTH_SEPARATOR + payload


def parse_ack(raw_packet: bytes) -> Tuple[int, int]:
    if len(raw_packet) < HEADER_SIZE:
        raise ValueError("ACK muito curto")
    seq_num, flag, _ = unpack_header(raw_packet)
    return seq_num, flag


def parse_packet(raw_packet: bytes):
    """Decompõe um pacote R-UDP completo em suas partes"""
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


def save_log(record: dict, log_file: str = LOG_FILE) -> None:
    """Salva métricas de transferência R-UDP em CSV"""
    log_dir = os.path.dirname(log_file)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    file_exists = os.path.isfile(log_file)
    fieldnames = [
        "timestamp",
        "scenario",
        "filename",
        "file_size_bytes",
        "elapsed_s",
        "throughput_mbps",
        "chunks_sent",
        "retransmits",
    ]

    with open(log_file, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow(record)

    log.info("Métricas salvas em '%s'.", log_file)


# Cliente
# -----------------------------

class RUDPClient:
    """
    Cliente HTTP sobre R-UDP (Stop-and-Wait)
    """

    def __init__(
        self,
        server_host: str  = "127.0.0.1",
        server_port: int  = 9000,
        matricula: str    = "20239000313",
        nome: str         = "Marcio Rodrigues",
        timeout: float    = TIMEOUT,
        max_retries: int  = MAX_RETRIES,
        chunk_size: int   = CHUNK_SIZE,
        scenario: str     = "A",
        log_file: str     = LOG_FILE,
    ):
        self.server_host  = server_host
        self.server_port  = server_port
        self.matricula    = matricula
        self.nome         = nome
        self.timeout      = timeout
        self.max_retries  = max_retries
        self.chunk_size   = chunk_size
        self.scenario     = scenario
        self.log_file     = log_file

        self.auth_token   = build_auth_token(matricula, nome)

        # Cria socket UDP, timeout dinâmico
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)

        # Usado para enviar requisição (endereço IP resolvido dinamicamente)
        self.server_addr  = (server_host, server_port)

        log.info("Cliente HTTP/R-UDP → %s:%d", self.server_host, self.server_port)
        log.info("X-Custom-Auth : %s", self.auth_token.decode())

    def _send_ack(self, addr: tuple, seq_num: int) -> None:
        """Monta e envia um pacote ACK para o servidor"""
        ack_payload  = b""
        ack_checksum = compute_checksum(ack_payload)
        header       = pack_header(seq_num, FLAG_ACK, ack_checksum)
        ack_packet   = header + self.auth_token + AUTH_SEPARATOR + ack_payload
        self.sock.sendto(ack_packet, addr)

    def _send_packet_saw(self, packet: bytes, expected_seq: int) -> None:
        """Envia `packet` e aguarda ACK com seq == expected_seq com Stop-and-Wait"""
        if not hasattr(self, "_rtx_count"):
            self._rtx_count = 0

        for attempt in range(1, self.max_retries + 1):
            try:
                self.sock.sendto(packet, self.server_addr)
                log.debug("→ PKT seq=%d (tentativa %d/%d)", expected_seq, attempt, self.max_retries)
            except socket.error as err:
                raise RUDPTransferError(f"Erro ao enviar seq={expected_seq}: {err}") from err

            if attempt > 1:
                self._rtx_count += 1

            # Aguarda ACK
            while True:
                try:
                    raw_ack, _ = self.sock.recvfrom(65535)
                except socket.timeout:
                    log.warning("⏱ Timeout seq=%d (tentativa %d)", expected_seq, attempt)
                    break   # tenta enviar novamente
                except socket.error as err:
                    raise RUDPTransferError(f"Erro socket aguardando ACK seq={expected_seq}: {err}") from err

                try:
                    ack_seq, ack_flag = parse_ack(raw_ack)
                except (ValueError, struct.error) as err:
                    log.warning("ACK malformado: %s", err)
                    continue

                if ack_flag != FLAG_ACK:
                    log.warning("Resposta não é ACK (flag=0x%02X) — ignorada.", ack_flag)
                    continue

                if ack_seq != expected_seq:
                    log.warning("ACK seq=%d ≠ esperado=%d — ignorado.", ack_seq, expected_seq)
                    continue

                log.debug("✓ ACK seq=%d recebido.", ack_seq)
                return

        raise RUDPTransferError(
            f"Falha após {self.max_retries} tentativas no seq={expected_seq}."
        )

    # interface
    def send_file(self, filepath: str) -> dict:
        """
        Requisita um arquivo via HTTP GET sobre R-UDP.
        """
        filename = os.path.basename(filepath)
        log.info("Iniciando requisição HTTP/R-UDP de '%s'", filename)

        # Resolução DNS
        try:
            resolved_ip = resolve_dns(self.server_host)
        except Exception as e:
            raise RUDPTransferError(f"DNS Resolution failed: {e}") from e

        self.server_addr = (resolved_ip, self.server_port)
        log.info("DNS resolvido: %s -> %s", self.server_host, resolved_ip)

        self._rtx_count = 0
        start_time = time.time()

        try:
            # Envia HTTP GET request via R-UDP
            request_str = f"GET /{filename} HTTP/1.1\r\nHost: {self.server_host}\r\nUser-Agent: HTTPClient\r\n\r\n"
            request_bytes = request_str.encode("utf-8")
            
            req_packet = build_packet(0, FLAG_DATA, self.auth_token, request_bytes)
            self._send_packet_saw(req_packet, 0)
            
            fin_packet = build_packet(1, FLAG_FIN, self.auth_token, b"")
            self._send_packet_saw(fin_packet, 1)

            # Transição para receptor: aguarda resposta do servidor
            log.info("Requisição enviada. Aguardando resposta HTTP do servidor via R-UDP...")
            
            response_bytes = b""
            expected_seq = 0
            chunks_received = 0
            timeout_count = 0
            
            # Define um timeout temporário de 10s para a recepção dos dados, evitando warnings espúrios 
            # de timeouts causados pelas retransmissões do servidor (que ocorrem a cada 2s).
            self.sock.settimeout(10.0)
            
            while True:
                try:
                    raw_packet, addr = self.sock.recvfrom(65535)
                    timeout_count = 0
                except socket.timeout:
                    timeout_count += 1
                    log.warning("Timeout aguardando pacote de dados do servidor (inatividade %d/10)", timeout_count)
                    if timeout_count >= 10:
                        raise RUDPTransferError("Conexão perdida com o servidor (timeout de inatividade).")
                    continue
                except socket.error as err:
                    raise RUDPTransferError(f"Erro de socket ao receber resposta: {err}") from err

                try:
                    seq_num, flag, recv_checksum, auth_token, payload = parse_packet(raw_packet)
                except (ValueError, struct.error) as err:
                    log.warning("Pacote malformado ignorado: %s", err)
                    continue

                if flag == FLAG_FIN:
                    log.info("FIN recebido do servidor (seq=%d). Encerrando recepção.", seq_num)
                    self._send_ack(addr, seq_num)
                    
                    # Estado TIME_WAIT simplificado para garantir a entrega do ACK final ao servidor
                    log.info("Entrando em estado TIME_WAIT (1.5s)...")
                    time_wait_start = time.time()
                    self.sock.settimeout(0.3)
                    while time.time() - time_wait_start < 1.5:
                        try:
                            tw_packet, tw_addr = self.sock.recvfrom(65535)
                            try:
                                tw_seq, tw_flag, _, _, _ = parse_packet(tw_packet)
                                if tw_flag == FLAG_FIN:
                                    log.debug("Retransmissão de FIN do servidor detectada no TIME_WAIT. Reenviando ACK.")
                                    self._send_ack(tw_addr, tw_seq)
                            except Exception:
                                pass
                        except socket.timeout:
                            continue
                        except Exception:
                            break
                    break

                if flag == FLAG_DATA:
                    calc_checksum = compute_checksum(payload)
                    if calc_checksum != recv_checksum:
                        log.warning("Checksum INVÁLIDO seq=%d. Ignorando.", seq_num)
                        continue

                    if seq_num == expected_seq:
                        response_bytes += payload
                        self._send_ack(addr, seq_num)
                        expected_seq += 1
                        chunks_received += 1
                    elif seq_num < expected_seq:
                        self._send_ack(addr, seq_num)
            
            # Restaura o timeout original do socket
            self.sock.settimeout(self.timeout)

            # Processa a resposta HTTP
            if not response_bytes:
                raise RUDPTransferError("Nenhuma resposta HTTP recebida do servidor.")

            header_part, _, body_part = response_bytes.partition(b"\r\n\r\n")
            headers_str = header_part.decode("utf-8", errors="replace")
            lines = headers_str.split("\r\n")

            status_line = lines[0]
            parts = status_line.split()
            if len(parts) < 3:
                raise RUDPTransferError(f"Resposta HTTP inválida do servidor: {status_line}")
            
            status_code = int(parts[1])

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            if status_code == 404:
                raise RUDPTransferError(f"Erro 404: Arquivo '{filename}' não encontrado no servidor.")
            elif status_code != 200:
                raise RUDPTransferError(f"Erro HTTP {status_code}: {status_line}")

            # Salva o arquivo recebido
            output_dir = "received_files"
            os.makedirs(output_dir, exist_ok=True)
            saved_path = os.path.join(output_dir, filename)

            with open(saved_path, "wb") as fh:
                fh.write(body_part)

            file_size = len(body_part)
            log.info("Download concluído com sucesso. Salvo em '%s' (%d bytes).", saved_path, file_size)

        except RUDPTransferError as err:
            elapsed    = time.time() - start_time
            log_record = {
                "timestamp":       datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "scenario":        self.scenario,
                "filename":        filename,
                "file_size_bytes": 0,
                "elapsed_s":       elapsed,
                "throughput_mbps": 0.0,
                "chunks_sent":     0,
                "retransmits":     self._retransmit_counter,
            }
            save_log(log_record, self.log_file)
            log.error("Transferência HTTP/R-UDP falhou.")
            raise

        elapsed    = time.time() - start_time
        throughput = file_size / elapsed if elapsed > 0 else 0

        stats = {
            "file":        filepath,
            "bytes_sent":  file_size,
            "chunks":      chunks_received,
            "retransmits": self._retransmit_counter,
            "elapsed":     elapsed,
            "throughput":  throughput,
        }

        log_record = {
            "timestamp":       datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "scenario":        self.scenario,
            "filename":        filename,
            "file_size_bytes": file_size,
            "elapsed_s":       elapsed,
            "throughput_mbps": (throughput * 8) / 1_000_000,
            "chunks_sent":     chunks_received,
            "retransmits":     self._retransmit_counter,
        }
        save_log(log_record, self.log_file)

        return stats

    @property
    def _retransmit_counter(self) -> int:
        return getattr(self, "_rtx_count", 0)

    def close(self) -> None:
        """Fecha o socket UDP"""
        self.sock.close()
        log.info("Socket RUDP fechado.")


# Interface de terminal
# -----------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Cliente HTTP/R-UDP — Redes II UFPI")
    p.add_argument("filepath",               help="Nome do arquivo a requisitar")
    p.add_argument("--host",    default="127.0.0.1", help="Hostname do servidor")
    p.add_argument("--port",    type=int, default=9000, help="Porta UDP (padrão: 9000)")
    p.add_argument("--matricula", default="20239000313", help="Matrícula do aluno")
    p.add_argument("--nome",      default="Marcio Rodrigues",help="Nome do aluno")
    p.add_argument("--timeout",  type=float, default=TIMEOUT,
                   help=f"Timeout em segundos (padrão: {TIMEOUT})")
    p.add_argument("--retries",  type=int,   default=MAX_RETRIES,
                   help=f"Máximo de retransmissões (padrão: {MAX_RETRIES})")
    p.add_argument("--chunk",    type=int,   default=CHUNK_SIZE,
                   help=f"Tamanho do chunk em bytes (padrão: {CHUNK_SIZE})")
    p.add_argument("--scenario", default="A",
                   help="Rótulo do cenário de teste (ex: A, B, C)")
    p.add_argument("--log-file", default=LOG_FILE,
                   help="Caminho do CSV de métricas de R-UDP")
    return p.parse_args()


if __name__ == "__main__":
    args   = parse_args()
    client = RUDPClient(
        server_host = args.host,
        server_port = args.port,
        matricula   = args.matricula,
        nome        = args.nome,
        timeout     = args.timeout,
        max_retries = args.retries,
        chunk_size  = args.chunk,
        scenario    = args.scenario,
        log_file    = args.log_file,
    )
    try:
        stats = client.send_file(args.filepath)
        print("\n===== ESTATÍSTICAS DA TRANSFERÊNCIA =====")
        print(f"  Arquivo       : {stats['file']}")
        print(f"  Bytes recebidos: {stats['bytes_sent']:,}")
        print(f"  Chunks        : {stats['chunks']}")
        print(f"  Retransmissões: {stats['retransmits']}")
        print(f"  Tempo total   : {stats['elapsed']:.4f} s")
        print(f"  Throughput    : {stats['throughput'] / 1024:.2f} KB/s")
        print("==========================================\n")
    except (FileNotFoundError, RUDPTransferError) as err:
        log.error("ERRO FATAL: %s", err)
        sys.exit(1)
    finally:
        client.close()