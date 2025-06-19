FROM python:3.8-slim

# Installation des dépendances système
RUN apt-get update && apt-get install -y \
    git \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Installation de Volatility3 et ses dépendances
RUN pip install --no-cache-dir \
    volatility3 \
    distorm3 \
    yara-python \
    capstone \
    pefile \
    pycryptodome

WORKDIR /data

CMD ["bash"] 