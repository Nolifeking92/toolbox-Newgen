# Guide d'utilisation des conteneurs Docker pour l'analyse de malware

## Problème résolu

L'erreur `Error response from daemon: No such container: toolboxnewgenbackup-binwalk-1` était causée par des conteneurs Docker qui n'étaient pas démarrés.

## Solution

### 1. Scripts de démarrage et d'arrêt

Nous avons créé deux scripts pour gérer facilement les conteneurs :

#### Démarrage des conteneurs
```bash
./start_containers.sh
```

#### Arrêt des conteneurs
```bash
./stop_containers.sh
```

### 2. Script principal corrigé

Le script `start.sh` a été corrigé pour :
- Démarrer automatiquement les conteneurs `binwalk` et `clamav`
- Vérifier que les conteneurs sont bien démarrés
- Afficher le statut des conteneurs
- Surveiller et redémarrer automatiquement les conteneurs si nécessaire

### 3. Conteneurs disponibles

- **binwalk** : Analyse de fichiers binaires et extraction de signatures
- **clamav** : Scanner antivirus pour détection de malware

### 4. Utilisation

1. **Démarrer les conteneurs** :
   ```bash
   ./start_containers.sh
   ```

2. **Démarrer l'application web** :
   ```bash
   cd web && .venv/bin/python app.py
   ```

3. **Accéder à l'interface** :
   - URL : https://127.0.0.1:9797
   - Identifiants : admin/admin

4. **Analyser un fichier** :
   - Aller dans la section "Malware Analysis"
   - Uploader un fichier
   - Les analyses binwalk et clamav seront exécutées automatiquement

### 5. Vérification du fonctionnement

Pour vérifier que les conteneurs fonctionnent :

```bash
# Voir les conteneurs actifs
docker ps

# Tester binwalk
docker exec toolboxnewgenbackup-binwalk-1 binwalk --help

# Tester clamav
docker exec toolboxnewgenbackup-clamav-1 clamscan --help
```

### 6. Dépannage

Si les conteneurs ne démarrent pas :

1. Vérifier que Docker est installé :
   ```bash
   docker --version
   docker-compose --version
   ```

2. Redémarrer les conteneurs :
   ```bash
   ./stop_containers.sh
   ./start_containers.sh
   ```

3. Vérifier les logs :
   ```bash
   docker-compose logs binwalk
   docker-compose logs clamav
   ```

## Structure des dossiers

```
analysis/
├── samples/     # Fichiers à analyser
├── reports/     # Rapports d'analyse
└── rules/       # Règles YARA (optionnel)
```

Les conteneurs ont accès à ces dossiers via des volumes Docker. 