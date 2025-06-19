#!/bin/bash

# Dossier de destination des sauvegardes
BACKUP_DIR="backup"
DATE=$(date +"%Y%m%d_%H%M%S")
ARCHIVE_NAME="toolbox_backup_$DATE.tar.gz"

# Créer le dossier de backup s'il n'existe pas
mkdir -p "$BACKUP_DIR"

# Fichiers et dossiers à sauvegarder
INCLUDES=(
    "web/users.db"
    "reports/"
    "web/requirements.txt"
    "docker-compose.yml"
    "web/app.py"
    "web/ssl/"
)

# Création de l'archive

tar -czvf "$BACKUP_DIR/$ARCHIVE_NAME" ${INCLUDES[@]}

if [ $? -eq 0 ]; then
    echo "[OK] Sauvegarde créée : $BACKUP_DIR/$ARCHIVE_NAME"
else
    echo "[ERREUR] La sauvegarde a échoué."
    exit 1
fi 