# 🛡️ Toolbox Newgen - Suite de Cybersécurité

Une toolbox complète de cybersécurité avec interface web moderne pour l'analyse de vulnérabilités, le test d'intrusion et la gestion de projets de sécurité.

## 🚀 Fonctionnalités

### 🔍 **Outils de Scan et Analyse**
- **Nmap** - Scanner de ports et services
- **Dirsearch** - Scanner de répertoires web
- **ClamAV** - Antivirus et détection de malware
- **Hydra** - Test de force brute
- **SQLMap** - Détection d'injections SQL
- **OWASP ZAP** - Scanner de vulnérabilités web
- **John the Ripper** - Crack de mots de passe
- **Binwalk** - Analyse de fichiers binaires
- **Volatility3** - Analyse de mémoire
- **TShark** - Analyse de trafic réseau

### 📊 **Interface Web**
- Dashboard avec statistiques en temps réel
- Gestion de projets de sécurité
- Génération de rapports (PDF, JSON, CSV)
- Planification de scans
- Système d'utilisateurs et permissions
- Interface responsive et moderne

### 🛠️ **Gestion de Projets**
- Création et gestion de projets
- Attribution de rapports aux projets
- Suivi des tâches et progression
- Collaboration en équipe

## 🐳 Installation avec Docker

### Prérequis
- Docker et Docker Compose
- Python 3.8+
- Git

### Installation rapide

```bash
# Cloner le repository
git clone https://github.com/votre-username/toolbox-newgen.git
cd toolbox-newgen

# Donner les permissions d'exécution
chmod +x start.sh stop.sh

# Démarrer la toolbox
./start.sh
```

### Accès à l'interface
- **URL** : https://127.0.0.1:9797
- **Utilisateur par défaut** : admin
- **Mot de passe par défaut** : admin

## 📁 Structure du Projet

```
toolbox-newgen/
├── web/                    # Application Flask
│   ├── app.py             # Application principale
│   ├── templates/         # Templates HTML
│   ├── static/           # CSS, JS, images
│   └── requirements.txt  # Dépendances Python
├── tools/                # Outils de sécurité
│   ├── binwalk/         # Dockerfile pour Binwalk
│   ├── clamav/          # Dockerfile pour ClamAV
│   └── volatility3/     # Dockerfile pour Volatility3
├── analysis/            # Dossiers d'analyse
│   ├── samples/         # Échantillons à analyser
│   └── reports/         # Rapports générés
├── docker-compose.yml   # Configuration Docker
├── start.sh            # Script de démarrage
├── stop.sh             # Script d'arrêt
└── README.md           # Documentation
```

## 🔧 Configuration

### Variables d'environnement
Créez un fichier `.env` à la racine du projet :

```env
FLASK_SECRET_KEY=votre-clé-secrète
FLASK_ENV=production
DATABASE_URL=sqlite:///users.db
```

### Ports utilisés
- **9797** : Interface web principale
- **Docker** : Ports internes pour les conteneurs

## 🚀 Utilisation

### 1. Démarrage
```bash
./start.sh
```

### 2. Arrêt
```bash
./stop.sh
```

### 3. Redémarrage
```bash
./stop.sh && ./start.sh
```

## 📊 Fonctionnalités Avancées

### 🔐 Sécurité
- Authentification utilisateur
- Gestion des rôles (admin/user)
- Protection contre les attaques
- Logs de sécurité

### 📈 Monitoring
- Statistiques système en temps réel
- Monitoring des scans
- Alertes automatiques
- Historique des analyses

### 🔄 Automatisation
- Planification de scans
- Rapports automatiques
- Notifications par email
- Intégration continue

## 🛡️ Sécurité et Bonnes Pratiques

### ⚠️ Avertissements
- **Utilisez uniquement sur des systèmes autorisés**
- **Respectez les lois locales sur la cybersécurité**
- **Ne testez jamais sans autorisation explicite**

### 🔒 Recommandations
- Changez les mots de passe par défaut
- Utilisez HTTPS en production
- Configurez un pare-feu approprié
- Faites des sauvegardes régulières

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour contribuer :

1. Fork le projet
2. Créez une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📝 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 🆘 Support

- **Issues** : [GitHub Issues](https://github.com/votre-username/toolbox-newgen/issues)
- **Documentation** : [Wiki](https://github.com/votre-username/toolbox-newgen/wiki)
- **Email** : support@toolbox-newgen.com

## 🙏 Remerciements

- OWASP pour ZAP
- Nmap Security Scanner
- ClamAV Team
- Tous les contributeurs open source

---

**⚠️ Disclaimer** : Cet outil est destiné uniquement à des fins éducatives et de test sur des systèmes autorisés. Les auteurs ne sont pas responsables de son utilisation abusive. 