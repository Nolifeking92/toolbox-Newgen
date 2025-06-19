#!/bin/bash
# Script pour tester la génération de rapports pour tous les outils (test minimal avec --help)
# Usage: ./generate_report_minimal_tests.sh

TOOLS=(
  "sqlmap"
  "medusa"
  "fping"
  "netdiscover"
  "xsstrike"
  "wfuzz"
  "volatility3"
  "kismet"
  "clamav"
  "sublist3r"
  "hydra"
  "commix"
  "yara"
  "metasploit"
  "hashcat"
  "binwalk"
  "dirsearch"
  "aircrack-ng"
  "masscan"
  "john"
  "openvas"
  "zap"
  "nmap"
)

for TOOL in "${TOOLS[@]}"; do
  echo "\n===== Test $TOOL ====="
  ./generate_report.sh "$TOOL" "--help"
done 