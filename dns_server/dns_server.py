#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_server.py
==============
Servidor DNS Local simplificado sobre UDP nativo.

Disciplina : Redes de Computadores II - 3a Avaliacao
Objetivo   : Resolver nomes de host para IPv4 (registro tipo A) consultando
             um arquivo de zona estatico (hosts.txt), respondendo via
             socket UDP puro (sem bibliotecas de alto nivel de DNS).

Protocolo simplificado (cabecalho customizado, NAO eh o protocolo DNS real):

    REQUISICAO (Cliente -> Servidor):
        [ ID (4 bytes, unsigned int) | NAME (string, tamanho variavel) ]

    RESPOSTA (Servidor -> Cliente):
        [ ID (4 bytes, unsigned int) | NAME (mesmo tamanho da query) | IP (string) ]

    Empacotamento feito com `struct`, no formato:
        Header fixo : "!I H"  -> ID (uint32) + tamanho do NAME (uint16)
        Payload     : NAME (bytes utf-8) [+ IP (bytes utf-8) na resposta]

    Caso o nome nao seja encontrado na zona, o servidor responde com
    IP = "0.0.0.0" (equivalente a um NXDOMAIN simplificado), permitindo
    que o cliente saiba que a consulta foi processada (e nao apenas perdida).

Tratamento de perdas:
    A responsabilidade de retransmissao e TIMEOUT eh do CLIENTE
    (ver dns_client_module.py). O servidor aqui eh "stateless": ele apenas
    responde ao que recebe. Se o pacote de resposta for descartado pelo
    `tc qdisc` simulando perda, o cliente percebera via timeout e fara
    uma nova consulta -- o servidor simplesmente processara novamente
    (a logica de retransmissao nao precisa de estado no servidor,
    pois a consulta eh idempotente).
"""

import socket
import struct
import os
import sys
import signal

# CONFIGURACOES GERAIS
# ---------------------------------------------------------------------------
DNS_PORT = int(os.environ.get("DNS_PORT", 5353))

# Endereco de bind: 0.0.0.0 para aceitar conexoes de qualquer interface
DNS_HOST = os.environ.get("DNS_HOST", "0.0.0.0")

HOSTS_FILE = os.environ.get("HOSTS_FILE", "/app/hosts.txt")

BUFFER_SIZE = 1024

HEADER_FORMAT = "!IH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

IP_NOT_FOUND = "0.0.0.0"


# CARGA DO ARQUIVO DE ZONA (hosts.txt)
# ---------------------------------------------------------------------------
def carregar_zona(caminho_arquivo):
    """
    Ler o arquivo hosts.txt e construir um dicionario {nome: ip}.
        <nome_dominio>  A  <ip>

    Linhas vazias ou iniciadas com '#' são ignoradas.
    """
    zona = {}

    if not os.path.exists(caminho_arquivo):
        print(f"[ERRO] Arquivo de zona '{caminho_arquivo}' nao encontrado.")
        sys.exit(1)

    with open(caminho_arquivo, "r", encoding="utf-8") as f:
        for numero_linha, linha in enumerate(f, start=1):
            linha = linha.strip()

            # Ignora linhas vazias e comentarios
            if not linha or linha.startswith("#"):
                continue

            partes = linha.split()

            # NOME TIPO IP  (ex: www.redes.ufpi A 172.20.0.3)
            if len(partes) != 3:
                print(f"[AVISO] Linha {numero_linha} mal formatada, ignorada: '{linha}'")
                continue

            nome, tipo, ip = partes

            if tipo.upper() != "A":
                print(f"[AVISO] Linha {numero_linha}: tipo '{tipo}' nao suportado (apenas A), ignorada.")
                continue

            zona[nome.lower()] = ip

    print(f"[OK] Zona carregada com {len(zona)} registro(s) de '{caminho_arquivo}':")
    for nome, ip in zona.items():
        print(f"     {nome}  ->  {ip}")

    return zona


# (DES)EMPACOTAMENTO DE MENSAGENS (PROTOCOLO SIMPLIFICADO)
# ---------------------------------------------------------------------------

def desempacotar_query(dados):
    """
    Recebe os bytes brutos da query do cliente e extrai (id_consulta, nome).    
    """
    if len(dados) < HEADER_SIZE:
        raise ValueError("Pacote recebido menor que o cabecalho esperado.")

    id_consulta, tamanho_nome = struct.unpack(HEADER_FORMAT, dados[:HEADER_SIZE])

    nome_bytes = dados[HEADER_SIZE:HEADER_SIZE + tamanho_nome]
    nome = nome_bytes.decode("utf-8")

    return id_consulta, nome


def empacotar_resposta(id_consulta, nome, ip):
    """
    Monta os bytes da resposta.
    """
    nome_bytes = nome.encode("utf-8")
    ip_bytes = ip.encode("utf-8")

    cabecalho = struct.pack(HEADER_FORMAT, id_consulta, len(nome_bytes))
    bloco_ip = struct.pack("!H", len(ip_bytes)) + ip_bytes

    return cabecalho + nome_bytes + bloco_ip


# LOOP PRINCIPAL DO SERVIDOR
# ---------------------------------------------------------------------------

def iniciar_servidor():
    zona = carregar_zona(HOSTS_FILE)

    # AF_INET = IPv4 | SOCK_DGRAM = UDP (datagrama, sem conexao)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind((DNS_HOST, DNS_PORT))
    print(f"[DNS SERVER] Escutando em {DNS_HOST}:{DNS_PORT} (UDP)...")
    print(f"[DNS SERVER] Aguardando consultas... (CTRL+C para sair)\n")

    # Tratamento de encerramento gracioso
    def handler_saida(sig, frame):
        print("\n[DNS SERVER] Encerrando servidor...")
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, handler_saida)
    signal.signal(signal.SIGTERM, handler_saida)

    while True:
        try:
            # recvfrom bloqueia até chegar um datagrama, retorna dados + endereco do cliente
            dados, endereco_cliente = sock.recvfrom(BUFFER_SIZE)

            try:
                id_consulta, nome_consultado = desempacotar_query(dados)
            except (struct.error, ValueError, UnicodeDecodeError) as e:
                print(f"[ERRO] Pacote malformado recebido de {endereco_cliente}: {e}")
                continue

            nome_normalizado = nome_consultado.lower()
            ip_resolvido = zona.get(nome_normalizado, IP_NOT_FOUND)

            status = "ENCONTRADO" if ip_resolvido != IP_NOT_FOUND else "NAO ENCONTRADO"
            print(f"[QUERY] ID={id_consulta} | Nome='{nome_consultado}' | "
                  f"De={endereco_cliente} | Status={status} | IP={ip_resolvido}")

            resposta = empacotar_resposta(id_consulta, nome_consultado, ip_resolvido)

        
            # PONTO DE SIMULACAO DE PERDA (apenas para testes manuais)
            # import random
            # if random.random() < 0.3:
            #     print(f"[SIMULACAO] Resposta para ID={id_consulta} descartada propositalmente.")
            #     continue

            sock.sendto(resposta, endereco_cliente)

        except Exception as e:
            # Captura generica para nao derrubar o servidor por um erro pontual
            print(f"[ERRO INESPERADO] {e}")
            continue


if __name__ == "__main__":
    iniciar_servidor()