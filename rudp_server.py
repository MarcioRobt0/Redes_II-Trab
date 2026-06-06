import socket
import struct
import binascii
import hashlib
import os
import sys
import logging
import time
import argparse

# Constantes do protocolo
# -----------------------------
FLAG_DATA = 0x01
FLAG_ACK  = 0x02
FLAG_FIN  = 0x03

# Formato do cabeçalho: !IBI - network-byte-order | uint32 | uint8 | uint32
HEADER_FORMAT = "!IBI"
HEADER_SIZE   = struct.calcsize(HEADER_FORMAT)   # 9 bytes

# Separador que termina o campo X-Custom-Auth no payload
AUTH_SEPARATOR = b"\n"

# Tempo limite de inatividade para permitir reset de transferências abortadas.
SERVER_TIMEOUT = 10.0  # segundos


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
    """
    Gera o hash SHA-256 de 'matricula+nome' como token de autenticação
    O mesmo token deve ser usado pelo cliente
    """
    raw = (matricula + nome).encode("utf-8")
    return hashlib.sha256(raw).hexdigest().encode("ascii")   # 64 bytes hex


def compute_checksum(data: bytes) -> int:
    """CRC-32 sem sinal sobre os bytes de dados do payload."""
    return binascii.crc32(data) & 0xFFFFFFFF


def pack_header(seq_num: int, flag: int, checksum: int) -> bytes:
    """Empacota os 9 bytes do cabeçalho."""
    return struct.pack(HEADER_FORMAT, seq_num, flag, checksum)


def unpack_header(raw: bytes):
    """
    Desempacota os primeiros HEADER_SIZE bytes
    Retorna (seq_num, flag, checksum) ou lança struct.error
    """
    return struct.unpack(HEADER_FORMAT, raw[:HEADER_SIZE])


def parse_packet(raw_packet: bytes):
    """
    Decompõe um pacote R-UDP completo em suas partes

    Retorna:
    (seq_num, flag, checksum, auth_token, payload)
    auth_token: bytes com o hash SHA-256 recebido
    payload: bytes de dados (vazio em ACK/FIN sem dados)
    Lança ValueError se o pacote for curto demais.
    """
    if len(raw_packet) < HEADER_SIZE:
        raise ValueError(f"Pacote muito curto: {len(raw_packet)} bytes")

    seq_num, flag, checksum = unpack_header(raw_packet)
    rest = raw_packet[HEADER_SIZE:]

    # X-Custom-Auth vai até o primeiro '\n'
    sep_idx = rest.find(AUTH_SEPARATOR)
    if sep_idx == -1:
        # Pacote sem campo de auth
        auth_token = b""
        payload    = rest
    else:
        auth_token = rest[:sep_idx]
        payload    = rest[sep_idx + len(AUTH_SEPARATOR):]

    return seq_num, flag, checksum, auth_token, payload


# Servidor
# -----------------------------

class RUDPServer:
    """
    Servidor de transferência de arquivos sobre R-UDP (Stop-and-Wait)

    Parâmetros
    ----------
    host         : endereço de bind ('' = todas as interfaces)
    port         : porta UDP de escuta
    output_dir   : diretório onde os arquivos recebidos serão salvos
    matricula    : matrícula do aluno (para validação do X-Custom-Auth)
    nome         : nome do aluno
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

        # Token de autenticação esperado
        self.expected_auth = build_auth_token(matricula, nome)

        os.makedirs(output_dir, exist_ok=True)

        # Cria socket UDP
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.settimeout(SERVER_TIMEOUT)

        log.info("Servidor R-UDP aguardando em %s:%d", host or "0.0.0.0", port)
        log.info("Token de auth esperado : %s", self.expected_auth.decode())

    # envio de ACK
    def _send_ack(self, addr: tuple, seq_num: int) -> None:
        """Monta e envia um pacote ACK para o cliente"""

        # ACK não carrega dados, checksum calculado sobre bytes vazios
        ack_payload  = b""
        ack_checksum = compute_checksum(ack_payload)
        header       = pack_header(seq_num, FLAG_ACK, ack_checksum)
        # X-Custom-Auth também vai no ACK (rastreável no Wireshark)
        ack_packet   = header + self.expected_auth + AUTH_SEPARATOR + ack_payload
        self.sock.sendto(ack_packet, addr)
        log.debug("ACK seq=%d → %s:%d", seq_num, *addr)

    # loop principal ---------- 
    def serve_forever(self) -> None:
        """
        Loop de recepção. Aguarda conexões de clientes indefinidamente
        Cada transferência completa é tratada em sequência (single-thread)
        """
        log.info("Servidor pronto. Aguardando transferências…")

        while True:
            try:
                self._receive_file()
            except KeyboardInterrupt:
                log.info("Servidor encerrado pelo usuário.")
                break
            except Exception as exc:
                log.error("Erro inesperado: %s — aguardando próxima transferência.", exc)

        self.sock.close()

    def _receive_file(self) -> None:
        """
        Recebe um arquivo completo de um único cliente via Stop-and-Wait
        Retorna quando a flag FIN é processada ou ocorre um erro fatal
        """
        expected_seq = 0
        output_path  = None
        file_handle  = None
        client_addr  = None
        total_bytes  = 0
        start_time   = None

        log.info("Aguardando primeiro pacote…")

        try:
            while True:
                # recebe datagrama
                try:
                    raw_packet, addr = self.sock.recvfrom(65535)
                except socket.timeout:
                    if client_addr is None:
                        continue
                    log.warning(
                        "Timeout de recepção para %s:%d — transferênia abortada por inatividade.",
                        *client_addr,
                    )
                    break
                except socket.error as err:
                    log.error("Erro de socket ao receber: %s", err)
                    break

                #registra cliente
                if client_addr is None:
                    client_addr = addr
                    log.info("Nova transferência de %s:%d", *addr)
                    start_time  = time.time()

                # Ignora pacotes de endereços diferentes durante a transferência
                if addr != client_addr:
                    log.warning("Pacote ignorado de %s:%d (transferência em curso)", *addr)
                    continue

                # parseia pacote
                try:
                    seq_num, flag, recv_checksum, auth_token, payload = parse_packet(raw_packet)
                except (ValueError, struct.error) as err:
                    log.warning("Pacote malformado ignorado: %s", err)
                    continue

                log.debug(
                    "PKT seq=%d flag=0x%02X crc=0x%08X len_payload=%d",
                    seq_num, flag, recv_checksum, len(payload),
                )

                # valida X-Custom-Auth 
                if auth_token and auth_token != self.expected_auth:
                    log.warning(
                        "X-Custom-Auth inválido! recebido=%s esperado=%s",
                        auth_token.decode(errors="replace"),
                        self.expected_auth.decode(),
                    )

                # flag FIN
                if flag == FLAG_FIN:
                    log.info("FIN recebido (seq=%d). Encerrando transferência.", seq_num)
                    self._send_ack(client_addr, seq_num)

                    if file_handle:
                        file_handle.close()
                        elapsed = time.time() - start_time
                        throughput = (total_bytes / elapsed) if elapsed > 0 else 0
                        log.info(
                            "Arquivo salvo em '%s' | %d bytes | %.3f s | %.2f KB/s",
                            output_path,
                            total_bytes,
                            elapsed,
                            throughput / 1024,
                        )
                    break  # encerra essa transferência, volta ao loop externo

                # flag DATA
                if flag == FLAG_DATA:

                    # Abre o arquivo no primeiro pacote de dados (seq == 0)
                    if file_handle is None:
                        filename    = f"recv_{int(time.time())}.bin"
                        output_path = os.path.join(self.output_dir, filename)
                        file_handle = open(output_path, "wb")
                        log.info("Gravando em '%s'", output_path)

                    # valida checksum
                    calc_checksum = compute_checksum(payload)
                    if calc_checksum != recv_checksum:
                        log.warning(
                            "Checksum INVÁLIDO seq=%d (esperado=0x%08X recebido=0x%08X) — NACK implícito (sem ACK)",
                            seq_num, calc_checksum, recv_checksum,
                        )
                        continue

                    # valida número de sequência
                    if seq_num == expected_seq:
                        file_handle.write(payload)
                        total_bytes += len(payload)
                        log.debug("Gravados %d bytes (seq=%d).", len(payload), seq_num)
                        self._send_ack(client_addr, seq_num)
                        expected_seq += 1

                    elif seq_num < expected_seq:
                        log.debug("Duplicata seq=%d (esperado=%d) — reenviando ACK.", seq_num, expected_seq)
                        self._send_ack(client_addr, seq_num)

                    else:
                        log.warning("Seq fora de ordem: recebido=%d esperado=%d — ignorado.", seq_num, expected_seq)

                else:
                    log.warning("Flag desconhecida 0x%02X — pacote ignorado.", flag)

        finally:
            if file_handle and not file_handle.closed:
                file_handle.close()
                log.warning("Handle de arquivo fechado no finally (transferência incompleta?).")


# Interface do terminal
# -----------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Servidor R-UDP — Redes II UFPI")
    p.add_argument("--host", default="", help="Interface de bind (padrão: todas)")
    p.add_argument("--port", type=int, default=9000, help="Porta UDP (padrão: 9000)")
    p.add_argument("--output-dir", default="received_files", help="Diretório de saída dos arquivos")
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