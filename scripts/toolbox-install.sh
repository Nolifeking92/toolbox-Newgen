#!/bin/bash
set -e
echo "Construction des conteneurs..."
docker-compose build
echo "Démarrage des outils de cybersécurité..."
docker-compose up -d
echo "Tous les outils sont installés et démarrés." 