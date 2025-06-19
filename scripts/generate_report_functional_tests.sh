#!/bin/bash
# Script pour tester la génération de rapports fonctionnels pour chaque outil
# Usage: ./generate_report_functional_tests.sh

set -e
cd "$(dirname "$0")"

# Préparation des fichiers de test
TEST_DIR="../reports/test_data"
mkdir -p "$TEST_DIR"

# 1. john : hash md5 de "password"
echo -n "password" | md5sum | awk '{print $1}' > "$TEST_DIR/hash.txt"

# 2. hashcat : même hash et wordlist
cp "$TEST_DIR/hash.txt" "$TEST_DIR/hashcat_hash.txt"
echo "password" > "$TEST_DIR/wordlist.txt"

# 3. yara : règle et fichier cible
echo 'rule always_true { condition: true }' > "$TEST_DIR/test_rule.yar"
echo "test" > "$TEST_DIR/test_file.txt"

# 4. binwalk : utiliser /bin/ls si dispo, sinon un fichier vide
BINWALK_FILE="/bin/ls"
[ -f "$BINWALK_FILE" ] || BINWALK_FILE="$TEST_DIR/test_file.txt"

# 5. clamav : fichier texte
cp "$TEST_DIR/test_file.txt" "$TEST_DIR/clamav_test.txt"

# 6. fping : cible locale
FPING_TARGET="127.0.0.1"

# 7. masscan : cible locale
MASSCAN_TARGET="127.0.0.1"

# 8. nmap : cible locale
NMAP_TARGET="127.0.0.1"

# 9. dirsearch : cible locale (nécessite un serveur web sur 127.0.0.1)
DIRSEARCH_URL="http://127.0.0.1"

# 10. sublist3r : domaine public
SUBLIST3R_DOMAIN="example.com"

# 11. medusa/hydra : test factice, nécessite un service actif pour un vrai test

# Lancement des tests
./generate_report.sh john "--format=raw-md5 $TEST_DIR/hash.txt --wordlist=$TEST_DIR/wordlist.txt"
./generate_report.sh hashcat "-m 0 $TEST_DIR/hashcat_hash.txt $TEST_DIR/wordlist.txt --quiet"
./generate_report.sh yara "$TEST_DIR/test_rule.yar $TEST_DIR/test_file.txt"
./generate_report.sh binwalk "$BINWALK_FILE"
./generate_report.sh clamav "$TEST_DIR/clamav_test.txt"
./generate_report.sh fping "-c1 $FPING_TARGET"
./generate_report.sh masscan "$MASSCAN_TARGET -p22 --rate=1000"
./generate_report.sh nmap "-p 22,80 $NMAP_TARGET"
./generate_report.sh dirsearch "-u $DIRSEARCH_URL -e html"
./generate_report.sh sublist3r "-d $SUBLIST3R_DOMAIN"
# Tests factices pour hydra et medusa (remplacer par un vrai service si besoin)
./generate_report.sh hydra "-L $TEST_DIR/wordlist.txt -P $TEST_DIR/wordlist.txt $FPING_TARGET ssh || true"
./generate_report.sh medusa "-h || true"
# Ajout d'autres outils si besoin... 