FROM openjdk:11-jre-slim

# Installation des dépendances
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Télécharger et installer ZAP (version plus récente)
RUN wget https://github.com/zaproxy/zaproxy/releases/download/v2.15.0/ZAP_2.15.0_Linux.tar.gz \
    && tar -xzf ZAP_2.15.0_Linux.tar.gz \
    && mv ZAP_2.15.0 /zap \
    && rm ZAP_2.15.0_Linux.tar.gz

# Créer les répertoires de travail
RUN mkdir -p /zap/wrk /reports

# Définir le répertoire de travail
WORKDIR /zap/wrk

# Commande par défaut
CMD ["/zap/zap.sh", "--help"] 