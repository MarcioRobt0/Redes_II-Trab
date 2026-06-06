# Limpa arquivos e regras do ambiente para rodar os testes do zero

# Cores para o terminal
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}==================================================${NC}"
echo -e "${CYAN}     INICIANDO LIMPEZA DO AMBIENTE        ${NC}"
echo -e "${CYAN}==================================================${NC}"

# 1. Recupera as permissões dos arquivos que o Docker criou como root
echo -e "${YELLOW}[1/3]${NC} Recuperando permissões dos diretórios locais (solicitando sudo)..."
sudo chown -R $USER:$USER logs/ pcaps/ received_tcp/ received_files/ 2>/dev/null || true

# 2. Limpa os arquivos internos mantendo a estrutura de pastas
echo -e "${YELLOW}[2/3]${NC} Apagando arquivos residuais de logs, pcaps e recebidos..."
rm -rf logs/tcp/* logs/rudp/* pcaps/tcp/* pcaps/rudp/* 2>/dev/null || true
rm -rf received_tcp/* received_files/* 2>/dev/null || true

# 3. Limpa as regras do tc na interface caso o script tenha caído travado
echo -e "${YELLOW}[3/4]${NC} Resetando regras do Controle de Tráfego (tc) no container cliente..."
if docker compose ps | grep -q "redes_client"; then
    docker compose exec redes_client tc qdisc del dev eth0 root 2>/dev/null || true
    echo -e "${GREEN}✓ Interface eth0 limpa no container.${NC}"
else
    echo -e "${YELLOW}! Container redes_client não está rodando. Pulando reset do tc.${NC}"
fi

# 4. Reinicia o serviço de servidor para limpar o estado do R-UDP
echo -e "${YELLOW}[4/4]${NC} Reiniciando o serviço redes_server no Docker Compose..."
if docker compose ps | grep -q "redes_server"; then
    docker compose restart redes_server
    echo -e "${GREEN}✓ Serviço redes_server reiniciado.${NC}"
else
    echo -e "${YELLOW}! Container redes_server não está rodando. Pulando restart.${NC}"
fi

echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}       LABORATÓRIO ZERADO E PRONTO PARA USO!      ${NC}"
echo -e "${GREEN}==================================================${NC}"