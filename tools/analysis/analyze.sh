#!/bin/bash

SAMPLE_PATH="$1"
SAMPLE_NAME=$(basename "$SAMPLE_PATH")
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="/data/reports/${TIMESTAMP}_${SAMPLE_NAME}"

# Création du dossier de rapport
mkdir -p "$REPORT_DIR"

echo "[+] Démarrage de l'analyse pour: $SAMPLE_NAME"
echo "[+] Les rapports seront sauvegardés dans: $REPORT_DIR"

# 1. Analyse YARA
echo "[+] Lancement de l'analyse YARA..."
yara -r /data/rules/* "/data/samples/$SAMPLE_NAME" > "$REPORT_DIR/yara_results.txt" 2>&1
echo "[+] Analyse YARA terminée"

# 2. Analyse Binwalk
echo "[+] Lancement de l'analyse Binwalk..."
binwalk -B -e "/data/samples/$SAMPLE_NAME" > "$REPORT_DIR/binwalk_results.txt" 2>&1
strings "/data/samples/$SAMPLE_NAME" > "$REPORT_DIR/strings_results.txt"
echo "[+] Analyse Binwalk terminée"

# 3. Analyse Volatility (si c'est un dump mémoire)
if file "/data/samples/$SAMPLE_NAME" | grep -i "memory"; then
    echo "[+] Fichier identifié comme dump mémoire, lancement de Volatility3..."
    vol.py -f "/data/samples/$SAMPLE_NAME" windows.pslist > "$REPORT_DIR/volatility_processes.txt" 2>&1
    vol.py -f "/data/samples/$SAMPLE_NAME" windows.netscan > "$REPORT_DIR/volatility_network.txt" 2>&1
    vol.py -f "/data/samples/$SAMPLE_NAME" windows.malfind > "$REPORT_DIR/volatility_malfind.txt" 2>&1
    echo "[+] Analyse Volatility terminée"
fi

# Génération du rapport final
echo "[+] Génération du rapport final..."
{
    echo "=== Rapport d'analyse malware ==="
    echo "Fichier: $SAMPLE_NAME"
    echo "Date: $(date)"
    echo
    echo "1. Résultats YARA:"
    cat "$REPORT_DIR/yara_results.txt"
    echo
    echo "2. Résultats Binwalk:"
    cat "$REPORT_DIR/binwalk_results.txt"
    echo
    echo "3. Chaînes extraites (top 20 plus pertinentes):"
    grep -i -E "http|cmd|exe|dll|registry|key|password" "$REPORT_DIR/strings_results.txt" | head -20
} > "$REPORT_DIR/summary.txt"

if [ -f "$REPORT_DIR/volatility_processes.txt" ]; then
    {
        echo
        echo "4. Analyse mémoire (Volatility3):"
        echo "- Processus suspects:"
        cat "$REPORT_DIR/volatility_processes.txt"
        echo
        echo "- Connexions réseau:"
        cat "$REPORT_DIR/volatility_network.txt"
        echo
        echo "- Code injecté potentiel:"
        cat "$REPORT_DIR/volatility_malfind.txt"
    } >> "$REPORT_DIR/summary.txt"
fi

echo "[+] Analyse terminée! Rapport complet disponible dans: $REPORT_DIR/summary.txt" 