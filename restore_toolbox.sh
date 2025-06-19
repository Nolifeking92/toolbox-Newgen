#!/bin/bash

# Script de restauration pour la toolbox

BACKUP_DIR="backup"

if [ $# -lt 1 ]; then
    echo "Usage : $0 <archive_backup.tar.gz>"
    echo "Exemple : $0 $BACKUP_DIR/toolbox_backup_20240618_235959.tar.gz"
    exit 1
fi

ARCHIVE="$1"

if [ ! -f "$ARCHIVE" ]; then
    echo "[ERREUR] Archive $ARCHIVE introuvable."
    exit 1
fi

tar -xzvf "$ARCHIVE" -C ./

if [ $? -eq 0 ]; then
    echo "[OK] Restauration terminée."
else
    echo "[ERREUR] La restauration a échoué."
    exit 1
fi 