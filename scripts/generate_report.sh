#!/bin/bash
# Usage: ./generate_report.sh <outil> <commande>
# Exemple: ./generate_report.sh nmap "nmap -T4 scanme.nmap.org"

set -e

if [ $# -lt 2 ]; then
  echo "Usage: $0 <outil> <commande>"
  exit 1
fi

OUTIL="$1"
shift
CMD="$@"
DATE=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="../reports"
REPORT_FILE="$REPORT_DIR/${OUTIL}_$DATE.txt"

mkdir -p "$REPORT_DIR"
echo "[+] Génération du rapport pour $OUTIL..."

if [ "$OUTIL" = "nikto" ]; then
  docker run --rm frapsoft/nikto $CMD | tee "$REPORT_FILE"
else
  docker compose run --rm $OUTIL $CMD | tee "$REPORT_FILE"
fi

echo "[+] Rapport sauvegardé dans $REPORT_FILE" 