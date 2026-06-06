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
from datetime import datetime
from typing import Tuple

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


# Helpers de cabeçalho (idênticos ao servidor)
# -----------------------------

def build_auth_token(matricula: str, nome: str) -> bytes:
    """
    Gera o hash SHA-256 de 'matricula+nome'
    Deve ser idêntico ao token gerado pelo servidor para a mesma identidade
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
    """
    Constrói o pacote completo:
        [cabeçalho 9 bytes] + [auth_token 64 bytes] + ['\n'] + [payload]

    O checksum é calculado apenas sobre o payload (dados brutos do chunk)
    """
    crc    = compute_checksum(payload)
    header = pack_header(seq_num, flag, crc)
    return header + auth_token + AUTH_SEPARATOR + payload


def parse_ack(raw_packet: bytes) -> Tuple[int, int]:
    """
    Extrai (seq_num, flag) de um pacote ACK recebido
    Lança ValueError/struct.error se o pacote for inválido
    """
    if len(raw_packet) < HEADER_SIZE:
        raise ValueError("ACK muito curto")
    seq_num, flag, _ = unpack_header(raw_packet)
    return seq_num, flag


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
    Cliente de transferência de arquivos sobre R-UDP (Stop-and-Wait)

    Parâmetros
        server_host : endereço IP ou hostname do servidor
        server_port : porta UDP do servidor
        matricula   : matrícula de aluno (compõe o X-Custom-Auth)
        nome        : nome de aluno
        timeout     : segundos de espera por ACK
        max_retries : tentativas máximas antes de falhar
        chunk_size  : tamanho de cada fragmento de dados em bytes
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
        self.server_addr  = (server_host, server_port)
        self.matricula    = matricula
        self.nome         = nome
        self.timeout      = timeout
        self.max_retries  = max_retries
        self.chunk_size   = chunk_size
        self.scenario     = scenario
        self.log_file     = log_file

        # Token gerado uma única vez para toda a sessão
        self.auth_token   = build_auth_token(matricula, nome)

        # Cria socket UDP, timeout definido uma vez para toda a sessão
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)

        log.info("Cliente R-UDP → %s:%d", *self.server_addr)
        log.info("X-Custom-Auth : %s", self.auth_token.decode())

    # Stop-and-Wait: envia e aguarda ACK 
    def _send_and_wait_ack(self, packet: bytes, expected_seq: int) -> None:
        """
        Envia `packet` e aguarda ACK com seq == expected_seq

        Repete até MAX_RETRIES vezes em caso de timeout ou ACK duplicado
        Levanta RUDPTransferError se todas as tentativas falharem
        """
        for attempt in range(1, self.max_retries + 1):
            # envia 
            try:
                self.sock.sendto(packet, self.server_addr)
                log.debug("Enviado seq=%d (tentativa %d/%d)", expected_seq, attempt, self.max_retries)
            except socket.error as err:
                raise RUDPTransferError(f"Erro ao enviar pacote seq={expected_seq}: {err}") from err

            # aguarda ACK 
            while True:
                try:
                    raw_ack, addr = self.sock.recvfrom(65535)
                except socket.timeout:
                    log.warning("Timeout esperando ACK seq=%d (tentativa %d)", expected_seq, attempt)
                    break
                except socket.error as err:
                    raise RUDPTransferError(f"Erro de socket ao aguardar ACK: {err}") from err

                # parseia ACK (extrai/interpreta mensagem)
                try:
                    ack_seq, ack_flag = parse_ack(raw_ack)
                except (ValueError, struct.error) as err:
                    log.warning("ACK malformado ignorado: %s", err)
                    continue

                if ack_flag != FLAG_ACK:
                    log.warning("Pacote recebido não é ACK (flag=0x%02X) — ignorado.", ack_flag)
                    continue

                if ack_seq != expected_seq:
                    log.warning(
                        "ACK fora de ordem: recebido seq=%d esperado seq=%d — ignorado.",
                        ack_seq, expected_seq,
                    )
                    continue

                # ACK correto recebido
                log.debug("ACK seq=%d confirmado.", ack_seq)
                return 

        # esgotou as tentativas (sem sucesso)
        raise RUDPTransferError(
            f"Máximo de retransmissões ({self.max_retries}) atingido para seq={expected_seq}."
        )

    # interface
    def send_file(self, filepath: str) -> dict:
        """
        Envia um arquivo completo ao servidor via Stop-and-Wait

        Retorna:
            dict com métricas da transferência:
            {
                "file":        str,    # caminho do arquivo
                "bytes_sent":  int,    # bytes de dados enviados
                "chunks":      int,    # número de chunks
                "retransmits": int,    # total de retransmissões
                "elapsed":     float,  # segundos totais
                "throughput":  float,  # bytes/segundo
            }

        Levanta:
            FileNotFoundError - se o arquivo não existir
            RUDPTransferError - se a transferência falhar
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Arquivo não encontrado: {filepath}")

        file_size = os.path.getsize(filepath)
        log.info("Iniciando envio de '%s' (%d bytes)", filepath, file_size)

        seq_num      = 0
        bytes_sent   = 0
        chunks_count = 0
        retransmits  = 0
        start_time   = time.time()

        try:
            with open(filepath, "rb") as fh:
                while True:
                    chunk = fh.read(self.chunk_size)
                    if not chunk:
                        break 

                    # monta pacote DATA 
                    packet = build_packet(seq_num, FLAG_DATA, self.auth_token, chunk)

                    # envia com Stop-and-wait 
                    attempts_before = self._retransmit_counter
                    self._send_packet_saw(packet, seq_num)
                    retransmits += (self._retransmit_counter - attempts_before)

                    bytes_sent   += len(chunk)
                    chunks_count += 1
                    seq_num      += 1

                    log.info(
                        "Progresso: %.1f%% (%d/%d bytes) | seq=%d",
                        100.0 * bytes_sent / file_size if file_size else 100.0,
                        bytes_sent, file_size, seq_num - 1,
                    )

            # envia FIN 
            log.info("Enviando FIN (seq=%d)…", seq_num)
            fin_packet = build_packet(seq_num, FLAG_FIN, self.auth_token, b"")
            self._send_and_wait_ack(fin_packet, seq_num)
            log.info("FIN confirmado pelo servidor.")

        except RUDPTransferError as err:
            elapsed    = time.time() - start_time
            throughput = bytes_sent / elapsed if elapsed > 0 else 0

            log_record = {
                "timestamp":       datetime.utcnow().isoformat() + "Z",
                "scenario":        self.scenario,
                "filename":        os.path.basename(filepath),
                "file_size_bytes": file_size,
                "elapsed_s":       elapsed,
                "throughput_mbps": (throughput * 8) / 1_000_000,
                "chunks_sent":     chunks_count,
                "retransmits":     retransmits,
            }
            save_log(log_record, self.log_file)

            log.error("Transferência abortada por falha no Stop-and-Wait.")
            raise

        elapsed    = time.time() - start_time
        throughput = bytes_sent / elapsed if elapsed > 0 else 0

        stats = {
            "file":        filepath,
            "bytes_sent":  bytes_sent,
            "chunks":      chunks_count,
            "retransmits": retransmits,
            "elapsed":     elapsed,
            "throughput":  throughput,
        }

        log_record = {
            "timestamp":       datetime.utcnow().isoformat() + "Z",
            "scenario":        self.scenario,
            "filename":        os.path.basename(filepath),
            "file_size_bytes": file_size,
            "elapsed_s":       elapsed,
            "throughput_mbps": (throughput * 8) / 1_000_000,
            "chunks_sent":     chunks_count,
            "retransmits":     retransmits,
        }
        save_log(log_record, self.log_file)

        log.info(
            "Transferência concluída | %d bytes | %d chunks | %d retransmissões | "
            "%.3f s | %.2f KB/s",
            bytes_sent, chunks_count, retransmits, elapsed, throughput / 1024,
        )

        return stats

    # contador interno de retransmissões
    @property
    def _retransmit_counter(self) -> int:
        """Contador interno acumulado - inicializado no __init__"""
        return getattr(self, "_rtx_count", 0)

    def _send_packet_saw(self, packet: bytes, expected_seq: int) -> None:
        """
        Wrapper de _send_and_wait_ack que contabiliza retransmissões
        Cada chamada após a primeira (tentativa 1) incrementa _rtx_count.
        """
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

    def close(self) -> None:
        """Fecha o socket UDP"""
        self.sock.close()
        log.info("Socket fechado.")


# Interface de terminal
# -----------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Cliente R-UDP — Redes II UFPI")
    p.add_argument("filepath",               help="Caminho do arquivo a enviar")
    p.add_argument("--host",    default="127.0.0.1", help="IP do servidor (padrão: 127.0.0.1)")
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
        print(f"  Bytes enviados: {stats['bytes_sent']:,}")
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