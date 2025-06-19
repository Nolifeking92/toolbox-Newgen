# Guide d'Installation - Toolbox Newgen

## Prérequis

- Linux (testé sur Kali Linux)
- Docker et Docker Compose
- Python 3.8+
- Git

## Installation rapide

```bash
# 1. Cloner le dépôt
git clone https://github.com/VOTRE_USERNAME/toolboxNewgen.git
cd toolboxNewgen

# 2. Lancer l'installation
chmod +x toolbox-install.sh
./toolbox-install.sh
```

## Installation manuelle détaillée

### 1. Configuration de l'environnement

```bash
# Créer les environnements virtuels Python
cd web
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
deactivate

cd ../backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
deactivate

cd ../scripts
python3 -m venv .venv_pdf
source .venv_pdf/bin/activate
pip install -r requirements.txt
deactivate
```

### 2. Configuration Docker

```bash
# Construire les images Docker
docker-compose build

# Vérifier que les images sont bien construites
docker images | grep toolboxnewgen
```

### 3. Configuration des permissions

```bash
# Donner les droits d'exécution aux scripts
chmod +x start.sh
chmod +x stop.sh
chmod +x analyze_malware.sh
chmod +x scripts/generate_report.sh
```

### 4. Premier démarrage

```bash
# Lancer la toolbox
./start.sh

# Vérifier que tout fonctionne
curl http://localhost:9797
```

## Structure des dossiers

```
toolboxNewgen/
├── web/                # Application web Flask
├── backend/            # API FastAPI
├── scripts/            # Scripts utilitaires
├── analysis/           # Dossier d'analyse
├── data/              # Données persistantes
└── docker-compose.yml # Configuration Docker
```

## Ports utilisés

- 9797 : Interface web principale
- 8000 : API Backend
- 3000 : Interface malware

## Configuration des outils

### ClamAV
- Base de données : `/data/clamav`
- Configuration : `docker-compose.yml`

### Binwalk
- Dossier d'analyse : `/analysis/samples`

### Hydra
- Wordlists : `/wordlists`

## Dépannage

### 1. Problèmes courants

- **Erreur de port** : Vérifier qu'aucun service n'utilise les ports 9797, 8000 et 3000
  ```bash
  sudo lsof -i :9797
  sudo lsof -i :8000
  sudo lsof -i :3000
  ```

- **Erreur Docker** : Vérifier que Docker est bien démarré
  ```bash
  sudo systemctl status docker
  ```

- **Erreur de permissions** : Vérifier les droits sur les dossiers
  ```bash
  sudo chown -R $USER:$USER .
  chmod -R u+rwX .
  ```

### 2. Logs

- Logs Flask : `web/logs/`
- Logs Docker : `docker-compose logs`
- Logs système : `journalctl -u docker`

## Mise à jour

```bash
# 1. Arrêter la toolbox
./stop.sh

# 2. Mettre à jour depuis Git
git pull

# 3. Reconstruire les images Docker
docker-compose build

# 4. Redémarrer
./start.sh
```

## Désinstallation

```bash
# 1. Arrêter et supprimer les conteneurs
./stop.sh
docker-compose down -v

# 2. Supprimer les images Docker
docker rmi $(docker images | grep toolboxnewgen | awk '{print $3}')

# 3. Supprimer le dossier
cd ..
rm -rf toolboxNewgen
```

## Support

Pour toute question ou problème :
1. Consulter les issues GitHub
2. Créer une nouvelle issue si le problème n'est pas répertorié
3. Fournir les logs et la sortie de `docker-compose ps` 