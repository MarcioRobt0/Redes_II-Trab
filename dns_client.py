import os
import socket
import struct
import random
import logging

log = logging.getLogger("dns_client")

DNS_SERVER_HOST = os.environ.get("DNS_SERVER_HOST", "172.20.0.12")
DNS_SERVER_PORT = int(os.environ.get("DNS_SERVER_PORT", 5353))
DNS_TIMEOUT = float(os.environ.get("DNS_TIMEOUT", 1.0))
DNS_MAX_RETRIES = int(os.environ.get("DNS_MAX_RETRIES", 5))

def resolve_dns(hostname: str) -> str:
    """
    Resolve o hostname para IP usando o servidor DNS local via UDP nativo.
    """
    
    # Se já for um IP válido, retorna direto
    try:
        socket.inet_aton(hostname)
        return hostname
    except socket.error:
        pass

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(DNS_TIMEOUT)

    query_id = random.randint(1, 4294967295)
    nome_bytes = hostname.encode("utf-8")
    header = struct.pack("!IH", query_id, len(nome_bytes))
    query_packet = header + nome_bytes

    for attempt in range(1, DNS_MAX_RETRIES + 1):
        try:
            log.info(f"[DNS] Resolvendo '{hostname}' (tentativa {attempt}/{DNS_MAX_RETRIES})...")
            sock.sendto(query_packet, (DNS_SERVER_HOST, DNS_SERVER_PORT))
            
            data, addr = sock.recvfrom(1024)
            if len(data) < 6:
                continue
            
            resp_id, len_nome = struct.unpack("!IH", data[:6])
            if resp_id != query_id:
                continue
            
            offset = 6
            resp_nome = data[offset:offset+len_nome].decode("utf-8")
            offset += len_nome
            
            if len(data) < offset + 2:
                continue
            len_ip, = struct.unpack("!H", data[offset:offset+2])
            offset += 2
            
            resp_ip = data[offset:offset+len_ip].decode("utf-8")
            
            log.info(f"[DNS] Resolvido: {hostname} -> {resp_ip}")
            sock.close()
            return resp_ip
        except socket.timeout:
            log.warning(f"[DNS] Timeout na tentativa {attempt}.")
        except Exception as e:
            log.warning(f"[DNS] Erro na tentativa {attempt}: {e}")

    sock.close()
    raise RuntimeError(f"Falha de resolucao DNS para o host '{hostname}'")
