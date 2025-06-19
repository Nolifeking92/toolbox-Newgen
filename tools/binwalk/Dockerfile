FROM python:3.9-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    binwalk \
    file \
    && rm -rf /var/lib/apt/lists/*

# Création du répertoire de travail
WORKDIR /samples

# Point d'entrée par défaut
CMD ["bash"] 