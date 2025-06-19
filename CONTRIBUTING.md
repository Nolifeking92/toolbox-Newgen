# 🤝 Guide de Contribution

Merci de votre intérêt pour contribuer à **Toolbox Newgen** ! Ce document vous guidera dans le processus de contribution.

## 📋 Table des Matières

- [Code de Conduite](#code-de-conduite)
- [Comment Contribuer](#comment-contribuer)
- [Guide de Développement](#guide-de-développement)
- [Tests](#tests)
- [Pull Request](#pull-request)
- [Rapport de Bugs](#rapport-de-bugs)
- [Suggestions de Fonctionnalités](#suggestions-de-fonctionnalités)

## 📜 Code de Conduite

### Notre Engagement

Nous nous engageons à maintenir un environnement ouvert et accueillant pour tous, peu importe l'âge, la taille, le handicap, l'ethnicité, l'identité et l'expression de genre, le niveau d'expérience, la nationalité, l'apparence personnelle, la race, la religion ou l'identité et l'orientation sexuelles.

### Nos Standards

Exemples de comportements qui contribuent à créer un environnement positif :

- Utiliser un langage accueillant et inclusif
- Respecter les différents points de vue et expériences
- Accepter gracieusement les critiques constructives
- Se concentrer sur ce qui est le mieux pour la communauté
- Faire preuve d'empathie envers les autres membres de la communauté

## 🚀 Comment Contribuer

### 1. Fork et Clone

```bash
# Fork le repository sur GitHub
# Puis clonez votre fork
git clone https://github.com/votre-username/toolbox-newgen.git
cd toolbox-newgen

# Ajoutez le repository original comme upstream
git remote add upstream https://github.com/original-username/toolbox-newgen.git
```

### 2. Créez une Branche

```bash
# Créez une branche pour votre fonctionnalité
git checkout -b feature/nouvelle-fonctionnalite

# Ou pour un bug fix
git checkout -b fix/correction-bug
```

### 3. Développez

- Suivez les conventions de code existantes
- Ajoutez des tests pour les nouvelles fonctionnalités
- Assurez-vous que tous les tests passent
- Mettez à jour la documentation si nécessaire

### 4. Testez

```bash
# Lancez les tests
./test_malware_analysis.sh
python -m pytest web/tests/

# Vérifiez que l'interface fonctionne
./start.sh
# Accédez à https://127.0.0.1:9797
```

### 5. Commit et Push

```bash
# Ajoutez vos changements
git add .

# Créez un commit descriptif
git commit -m "feat: ajoute nouvelle fonctionnalité X"

# Poussez vers votre fork
git push origin feature/nouvelle-fonctionnalite
```

## 🛠️ Guide de Développement

### Structure du Code

```
toolbox-newgen/
├── web/                    # Application Flask
│   ├── app.py             # Application principale
│   ├── templates/         # Templates HTML
│   ├── static/           # CSS, JS, images
│   └── tests/            # Tests unitaires
├── tools/                # Outils Docker
├── analysis/             # Dossiers d'analyse
└── docs/                 # Documentation
```

### Conventions de Code

#### Python
- **PEP 8** : Suivez les conventions PEP 8
- **Docstrings** : Documentez toutes les fonctions
- **Type Hints** : Utilisez les annotations de type
- **Noms** : Utilisez des noms descriptifs

```python
def analyze_target(target: str, options: dict = None) -> dict:
    """
    Analyse une cible avec les outils configurés.
    
    Args:
        target: La cible à analyser
        options: Options d'analyse
        
    Returns:
        dict: Résultats de l'analyse
    """
    pass
```

#### JavaScript
- **ES6+** : Utilisez les fonctionnalités ES6+
- **JSDoc** : Documentez les fonctions
- **Camel Case** : Pour les variables et fonctions

```javascript
/**
 * Lance une analyse d'outil
 * @param {string} tool - Nom de l'outil
 * @param {string} target - Cible à analyser
 * @returns {Promise<Object>} Résultats
 */
async function runToolAnalysis(tool, target) {
    // Code ici
}
```

#### HTML/CSS
- **Sémantique** : Utilisez des balises sémantiques
- **Accessibilité** : Respectez les standards WCAG
- **Responsive** : Design mobile-first

### Tests

#### Tests Unitaires
```bash
# Lancer tous les tests
python -m pytest

# Tests avec couverture
python -m pytest --cov=web

# Tests spécifiques
python -m pytest web/tests/test_security.py
```

#### Tests d'Intégration
```bash
# Test de l'interface web
./test_manual.py

# Test des outils Docker
./test_malware_analysis.sh
```

## 🔄 Pull Request

### Avant de Soumettre

1. **Tests** : Assurez-vous que tous les tests passent
2. **Documentation** : Mettez à jour la documentation
3. **Code Review** : Demandez une review à un autre développeur
4. **Convention** : Suivez les conventions de commit

### Template de Pull Request

```markdown
## Description
Brève description des changements

## Type de Changement
- [ ] Bug fix
- [ ] Nouvelle fonctionnalité
- [ ] Amélioration
- [ ] Documentation
- [ ] Refactoring

## Tests
- [ ] Tests unitaires passent
- [ ] Tests d'intégration passent
- [ ] Interface web fonctionne

## Checklist
- [ ] Code suit les conventions
- [ ] Documentation mise à jour
- [ ] Tests ajoutés
- [ ] Pas de régression

## Screenshots (si applicable)
```

## 🐛 Rapport de Bugs

### Template de Bug Report

```markdown
## Description du Bug
Description claire et concise du bug

## Étapes pour Reproduire
1. Aller à '...'
2. Cliquer sur '...'
3. Voir l'erreur

## Comportement Attendu
Description de ce qui devrait se passer

## Comportement Actuel
Description de ce qui se passe actuellement

## Environnement
- OS: [ex: Ubuntu 20.04]
- Navigateur: [ex: Chrome 90]
- Version: [ex: 1.0.0]

## Logs
```
Logs d'erreur si disponibles
```

## Screenshots
Screenshots si applicable
```

## 💡 Suggestions de Fonctionnalités

### Template de Feature Request

```markdown
## Problème
Description du problème que cette fonctionnalité résoudrait

## Solution Proposée
Description de la solution souhaitée

## Alternatives Considérées
Autres solutions considérées

## Contexte Additionnel
Contexte supplémentaire, screenshots, etc.
```

## 📞 Contact

- **Issues** : [GitHub Issues](https://github.com/votre-username/toolbox-newgen/issues)
- **Discussions** : [GitHub Discussions](https://github.com/votre-username/toolbox-newgen/discussions)
- **Email** : contribute@toolbox-newgen.com

## 🙏 Remerciements

Merci à tous les contributeurs qui rendent ce projet possible !

---

**Note** : Ce guide est inspiré des meilleures pratiques open source. N'hésitez pas à suggérer des améliorations ! 