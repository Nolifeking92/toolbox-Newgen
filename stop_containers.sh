#!/bin/bash

# Couleurs pour les messages
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] Arrêt des conteneurs Docker${NC}"

# Arrêt des conteneurs
docker-compose down

echo -e "${GREEN}[+] Conteneurs arrêtés avec succès${NC}" 