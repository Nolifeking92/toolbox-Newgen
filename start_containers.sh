#!/bin/bash

# Couleurs pour les messages
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] Démarrage des conteneurs Docker pour l'analyse de malware${NC}"

# Vérification que Docker est installé
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[ERREUR] Docker n'est pas installé${NC}"
    exit 1
fi

# Vérification que docker-compose est installé
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}[ERREUR] docker-compose n'est pas installé${NC}"
    exit 1
fi

# Arrêt des conteneurs existants
echo -e "${BLUE}[*] Arrêt des conteneurs existants...${NC}"
docker-compose down

# Démarrage des conteneurs nécessaires
echo -e "${BLUE}[*] Démarrage des conteneurs binwalk et clamav...${NC}"
docker-compose up -d binwalk clamav

# Vérification que les conteneurs sont démarrés
sleep 3
if docker ps | grep -q "toolboxnewgenbackup-binwalk-1" && docker ps | grep -q "toolboxnewgenbackup-clamav-1"; then
    echo -e "${GREEN}[+] Conteneurs démarrés avec succès !${NC}"
    echo -e "${BLUE}[*] Conteneurs actifs:${NC}"
    docker ps --format "table {{.Names}}\t{{.Status}}"
else
    echo -e "${RED}[ERREUR] Échec du démarrage des conteneurs${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Les conteneurs sont prêts pour l'analyse de malware${NC}" 