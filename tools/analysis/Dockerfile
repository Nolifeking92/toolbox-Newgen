FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Installation des outils nécessaires
RUN apt-get update && apt-get install -y \
    yara \
    binwalk \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Installation de Volatility3
RUN pip3 install volatility3

# Création des dossiers de travail
RUN mkdir -p /data/samples /data/rules /data/reports

WORKDIR /data

# Script d'analyse
COPY analyze.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/analyze.sh

ENTRYPOINT ["/usr/local/bin/analyze.sh"] 