#!/bin/bash

# Couleurs pour les messages
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] Installation de la Toolbox Newgen${NC}"

# Vérification des prérequis
echo -e "${BLUE}[*] Vérification des prérequis...${NC}"
for cmd in docker docker-compose python3 git; do
    if ! command -v $cmd &> /dev/null; then
        echo -e "${RED}[ERREUR] La commande '$cmd' est requise mais non trouvée.${NC}"
        echo -e "Installez-la avec : sudo apt install $cmd"
        exit 1
    fi
done

# Création des environnements virtuels Python
echo -e "${BLUE}[*] Configuration des environnements Python...${NC}"

# Web
cd web
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
deactivate

# Backend
cd ../backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
deactivate

# Scripts
cd ../scripts
python3 -m venv .venv_pdf
source .venv_pdf/bin/activate
pip install -r requirements.txt
deactivate

cd ..

# Configuration des permissions
echo -e "${BLUE}[*] Configuration des permissions...${NC}"
chmod +x start.sh
chmod +x stop.sh
chmod +x analyze_malware.sh
chmod +x scripts/generate_report.sh
chmod -R u+rwX .

# Construction des images Docker
echo -e "${BLUE}[*] Construction des images Docker...${NC}"
docker-compose build

# Création des dossiers nécessaires
echo -e "${BLUE}[*] Création des dossiers...${NC}"
mkdir -p web/logs
mkdir -p analysis/{samples,rules,reports}
mkdir -p data/clamav

echo -e "${GREEN}[+] Installation terminée !${NC}"
echo -e "${BLUE}[*] Pour démarrer la toolbox :${NC}"
echo -e "   ./start.sh"
echo -e "${BLUE}[*] Interface web :${NC}"
echo -e "   http://localhost:9797" 