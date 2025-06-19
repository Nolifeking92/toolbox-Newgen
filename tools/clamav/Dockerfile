FROM debian:bullseye-slim

# Installation de ClamAV et ses dépendances
RUN apt-get update && apt-get install -y \
    clamav \
    clamav-daemon \
    && rm -rf /var/lib/apt/lists/*

# Mise à jour des signatures
RUN freshclam

# Création du répertoire de travail
WORKDIR /scan

# Point d'entrée par défaut
CMD ["bash"] 