#!/bin/bash

# Couleurs pour les messages
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] Démarrage de la Toolbox Newgen${NC}"

# Vérifications récurrentes et automatiques
REQUIRED_DIRS=("web" "backend")
for dir in "${REQUIRED_DIRS[@]}"; do
  if [ ! -d "$dir" ]; then
    echo -e "${RED}[ERREUR] Dossier manquant: $dir. Vérifiez l'extraction ou le dépôt du projet.${NC}"
    exit 1
  fi
done

echo -e "${BLUE}[*] Vérification des dossiers terminée${NC}"

# Nettoyage des dossiers __pycache__ pour éviter les problèmes de permissions
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Vérification des permissions sur toolboxNewgen (en ignorant __pycache__)
find . -type f -not -path "./*/__pycache__/*" -not -path "./*/.git/*" -exec chmod u+rw {} \; 2>/dev/null || true
find . -type d -not -path "./*/__pycache__" -not -path "./*/.git" -exec chmod u+rwx {} \; 2>/dev/null || true

echo -e "${BLUE}[*] Nettoyage et permissions terminés${NC}"

# Vérification des commandes critiques
for cmd in docker python3; do
  if ! command -v $cmd &> /dev/null; then
    echo -e "${RED}[ERREUR] La commande '$cmd' est requise mais non trouvée.${NC}"
    exit 1
  fi
done

echo -e "${BLUE}[*] Vérification des commandes terminée${NC}"

# Vérification de l'environnement virtuel dans web/
echo -e "${BLUE}[*] Vérification de l'environnement virtuel dans web/...${NC}"

# Activation de l'environnement virtuel
echo -e "${BLUE}[*] Activation de l'environnement virtuel...${NC}"
cd web

# Installation des dépendances Python
echo -e "${BLUE}[*] Installation des dépendances Python...${NC}"
source .venv/bin/activate
pip install -r requirements.txt

# Installation des dépendances supplémentaires
echo -e "${BLUE}[*] Installation des dépendances supplémentaires...${NC}"
pip install --upgrade pip setuptools
pip install mysql-connector-python defusedcsv httpx_ntlm requests-toolbelt defusedxml psycopg beautifulsoup4 colorama requests_ntlm

echo -e "${GREEN}[+] Installation des dépendances terminée${NC}"

# Retour au répertoire racine
cd ..

# Démarrage des services Docker
echo -e "${BLUE}[*] Démarrage des services Docker...${NC}"
docker-compose up -d

# Attendre que les services soient prêts
echo -e "${BLUE}[*] Attente du démarrage des services...${NC}"
sleep 5

# Vérification du statut des services
echo -e "${BLUE}[*] Vérification du statut des services...${NC}"
docker-compose ps

echo -e "${GREEN}[+] Services Docker démarrés avec succès${NC}"

# Démarrage du serveur Flask
echo -e "${GREEN}[+] Démarrage du serveur Flask...${NC}"
cd web
python app.py &

# Attendre que le serveur démarre
sleep 3

echo -e "${GREEN}[+] Tous les services sont démarrés !${NC}"
echo -e "${BLUE}[*] Interface web principale: https://127.0.0.1:9797${NC}"

# Affichage des conteneurs actifs
echo -e "${BLUE}[*] Conteneurs Docker actifs:${NC}"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo -e "${RED}[!] Pour arrêter tous les services, utilisez: ./stop.sh${NC}"
echo -e "${BLUE}[*] Script en cours d'exécution. Appuyez sur Ctrl+C pour arrêter.${NC}"

# Attendre l'interruption
wait 