#!/bin/bash

echo "[*] Arrêt de la Toolbox Newgen..."

# Arrêt du serveur Flask (plusieurs méthodes pour être sûr)
echo "[*] Arrêt du serveur Flask..."
pkill -f "python.*app.py" 2>/dev/null || true
pkill -f "flask" 2>/dev/null || true
pkill -f "werkzeug" 2>/dev/null || true

# Attendre un peu pour que les processus se terminent
sleep 2

# Vérifier s'il reste des processus Flask
if pgrep -f "python.*app.py" > /dev/null; then
    echo "[!] Force l'arrêt des processus Flask restants..."
    pkill -9 -f "python.*app.py" 2>/dev/null || true
fi

# Arrêt des services Docker
echo "[*] Arrêt des services Docker..."
docker-compose down

# Nettoyage des conteneurs orphelins
echo "[*] Nettoyage des conteneurs..."
docker container prune -f

# Nettoyage des réseaux Docker non utilisés
echo "[*] Nettoyage des réseaux Docker..."
docker network prune -f

echo "[+] Tous les services ont été arrêtés."
echo "[*] Toolbox Newgen arrêtée avec succès."
