FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# 1. Atualiza índice e instala dependências de sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    iproute2 \
    tcpdump \
    tshark \
    net-tools \
    iputils-ping \
    iputils-tracepath \
    curl \
    vim \
    bash \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# 2. Instala dependências Python para análise de dados e geração de gráficos
RUN pip3 install --no-cache-dir --break-system-packages \
    pandas \
    matplotlib \
    numpy 


# 3. Permite que usuários não-root usem tcpdump / tshark
RUN groupadd -f pcap \
    && usermod -aG pcap root \
    && chgrp pcap /usr/bin/tcpdump \
    && chmod 750  /usr/bin/tcpdump \
    && setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump \
    # tshark: aceita captura por usuários do grupo wireshark/pcap
    && chmod +x /usr/bin/tshark || true


# 3. Diretório de trabalho e cópia dos scripts Python
WORKDIR /app

# Copia todos os arquivos do projeto para dentro do container
# (o .dockerignore deve excluir received_tcp/, received_files/, logs/, etc.)
COPY . .
RUN chmod +x /app/start_servers.sh || true


# 4. Cria as pastas de saída com permissões adequadas
RUN mkdir -p /app/received_tcp \
             /app/received_files \
             /app/logs/tcp \
             /app/logs/rudp \
             /app/pcaps/tcp \
             /app/pcaps/rudp \
    && chmod -R 777 /app/logs /app/pcaps /app/received_tcp /app/received_files


# 5. Gera o arquivo de teste se não existir
RUN python3 gerar_arquivo_teste.py --size 0.095367 --name test_payload_100KB.bin && \
    python3 gerar_arquivo_teste.py --size 1 && \
    python3 gerar_arquivo_teste.py --size 10


# 6. Ponto de entrada padrão — substituído pelo command: no compose
CMD ["bash"]