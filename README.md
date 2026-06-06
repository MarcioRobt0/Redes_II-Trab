# Redes II — Laboratório de Protocolos R-UDP vs TCP

Projeto de análise comparativa entre **R-UDP (Reliable UDP - Stop-and-Wait)** e **TCP** para transferência de arquivos sob diferentes condições de rede (latência e perda de pacotes).

## 📋 Descrição

Implementação em Python de dois protocolos de transferência de arquivos:

- **R-UDP**: Protocolo Stop-and-Wait confiável baseado em UDP com retransmissão de pacotes perdidos
- **TCP**: Baseline para comparação (protocolo padrão do sistema operacional)

Testes executados em **3 cenários** com 15 execuções cada:
- **Cenário A**: 0% perda, 10ms latência
- **Cenário B**: 5% perda, 50ms latência  
- **Cenário C**: 10% perda, 100ms latência

**Saída**: Métricas de throughput, tempo de transferência, discrepâncias e gráficos comparativos.

## 🚀 Como Usar

### Pré-requisitos

```bash
docker --version        # Docker 20.10+
docker compose --version # Docker Compose 2.0+
```

### 1. Iniciar ambiente

```bash
# Clone o repositório
git clone <URL_DO_REPOSITORIO>
cd Redes_II-Trab

# Build e suba os containers
docker compose build
docker compose up -d

# Verifique se ambos estão rodando
docker compose ps
```

### 2. Rodar testes (todos os cenários)

```bash
# Dentro do container cliente
docker compose exec redes_client bash /app/rodar_testes.sh
```

### 3. Gerar relatório e gráficos

```bash
# Gera CSV consolidado + 4 gráficos PNG
docker compose exec redes_client bash /app/gerar_relatorio_completo.sh
```

**Saída**:
```
logs/dados/metricas_consolidadas.csv         ← Tabela com todas as métricas
graficos_resultado/
  ├─ grafico1_throughput_medio.png
  ├─ grafico2_tempo_transferencia.png
  ├─ grafico3_discrepancia_app_rede.png
  └─ tabela_resumo_estatistico.png
```

## 📁 Estrutura do Projeto

```
.
├── rudp_client.py              # Cliente R-UDP (envia arquivos, registra métricas)
├── rudp_server.py              # Servidor R-UDP (recebe, valida sequência, ACK)
├── tcp_client.py               # Cliente TCP (baseline)
├── tcp_server.py               # Servidor TCP (threaded)
├── rodar_testes.sh             # Orquestrador de testes (executa 15 runs/cenário)
├── validacao_cruzada.py        # Correlaciona métricas de app + rede (tshark)
├── gerar_graficos.py           # Gera 4 gráficos PNG a partir do CSV
├── gerar_relatorio_completo.sh # Pipeline completo (validação + gráficos)
├── docker-compose.yml          # Orquestração dos containers
├── Dockerfile                  # Imagem base (Python 3, pandas, matplotlib, tcpdump)
├── logs/                       # Métricas CSV (tcp/ e rudp/)
├── pcaps/                      # Capturas de pacotes (.pcap)
├── received_files/             # Arquivos recebidos pelo servidor R-UDP
├── received_tcp/               # Arquivos recebidos pelo servidor TCP
└── graficos_resultado/         # Gráficos PNG gerados
```

## 🔧 Comandos Úteis

| Comando | Descrição |
|---------|-----------|
| `docker compose up -d` | Inicia containers em background |
| `docker compose down` | Para e remove containers |
| `docker compose logs redes_client` | Exibe logs do cliente |
| `docker compose exec redes_client bash` | Shell interativo no cliente |
| `bash limpar_ambiente.sh` | Limpa logs, pcaps, reinicia servidor |


## 👤 Autor
<table>
  <tr>
    <td align="center">
      <a href="https://github.com/MarcioRobt0">
        <img src="https://github.com/MarcioRobt0.png" width="100px;" alt="Foto do seu-usuario"/><br>
        <sub><b>Márcio Roberto de Brito Rodrigues</b></sub>
      </a>
    </td>
  </tr>
</table>
