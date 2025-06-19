# Guide d'utilisation : Rapports dans les projets

## 🎯 **Fonctionnalité ajoutée**

Les rapports de scans sont maintenant visibles directement dans la page de détail de chaque projet. Cette fonctionnalité permet d'associer des rapports à des projets et de les consulter facilement.

## 📋 **Comment ça fonctionne**

### 1. **Association d'un rapport à un projet**

1. Allez dans la page **Rapports** (`/rapport`)
2. Trouvez le rapport que vous voulez associer
3. Cliquez sur le bouton **"Associer à un projet"**
4. Sélectionnez le projet dans la liste déroulante
5. Cliquez sur **"Associer"**

### 2. **Visualisation des rapports dans un projet**

1. Allez dans la page **Projets** (`/projects`)
2. Cliquez sur **"Voir"** pour le projet souhaité
3. Dans la page de détail du projet, vous verrez une section **"Rapports associés"**
4. Les rapports sont affichés avec :
   - **Type** : Nmap, Hydra, Dirsearch, Malware, etc.
   - **Date** : Date et heure du scan
   - **Fichier** : Nom du fichier de rapport
   - **Actions** : Télécharger (TXT/PDF) ou Retirer du projet

## 🔧 **Fonctionnalités disponibles**

### ✅ **Actions sur les rapports :**

- **📄 TXT** : Télécharger le rapport au format texte
- **📋 PDF** : Télécharger le rapport au format PDF
- **🗑️ Retirer** : Retirer le rapport du projet (ne supprime pas le fichier)

### 📊 **Types de rapports supportés :**

- **Nmap** : Scans de ports et services
- **Hydra** : Tests de force brute
- **Dirsearch** : Énumération de répertoires
- **Malware** : Analyses de malware (ClamAV, Binwalk)
- **SQLMap** : Tests d'injection SQL
- **ZAP** : Scans de vulnérabilités web
- **John** : Crack de mots de passe

## 🎨 **Interface utilisateur**

### **Section "Rapports associés" :**

```
┌─────────────────────────────────────────────────────────────┐
│ Rapports associés :                                         │
├─────────────┬─────────────┬─────────────────┬───────────────┤
│ Type        │ Date        │ Fichier         │ Actions       │
├─────────────┼─────────────┼─────────────────┼───────────────┤
│ NMAP        │ 19/06/2025  │ nmap_20250619_  │ 📄 TXT 📋 PDF │
│             │ 14:30       │ 143022.txt      │ 🗑️ Retirer    │
├─────────────┼─────────────┼─────────────────┼───────────────┤
│ HYDRA       │ 19/06/2025  │ hydra_20250619_ │ 📄 TXT 📋 PDF │
│             │ 22:46       │ 224636.txt      │ 🗑️ Retirer    │
└─────────────┴─────────────┴─────────────────┴───────────────┘
```

### **Message si aucun rapport :**

```
Aucun rapport associé à ce projet. 
Voir tous les rapports
```

## 🚀 **Avantages**

1. **Organisation** : Regrouper les rapports par projet
2. **Accessibilité** : Accès rapide aux rapports depuis le projet
3. **Flexibilité** : Associer/désassocier facilement
4. **Visibilité** : Voir tous les scans d'un projet en un coup d'œil
5. **Export** : Télécharger les rapports dans différents formats

## 🔄 **Workflow recommandé**

1. **Créer un projet** pour votre audit
2. **Lancer des scans** avec différents outils
3. **Associer les rapports** au projet depuis la page Rapports
4. **Consulter les résultats** directement dans le projet
5. **Télécharger les rapports** selon vos besoins
6. **Retirer les rapports** obsolètes si nécessaire

## 🛠️ **Technique**

- **Stockage** : Les associations sont stockées dans des fichiers `.project`
- **Base de données** : Aucune modification de la base de données requise
- **Compatibilité** : Fonctionne avec le système existant
- **Performance** : Lecture directe des fichiers pour les associations

## ✅ **Test de la fonctionnalité**

Un script de test est disponible : `test_project_reports.py`

```bash
cd web && .venv/bin/python ../test_project_reports.py
```

---

**🎉 La fonctionnalité est maintenant opérationnelle !** 