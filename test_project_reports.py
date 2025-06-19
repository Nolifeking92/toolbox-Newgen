#!/usr/bin/env python3
"""
Script de test pour vérifier que les rapports apparaissent dans la page projet
"""

import os
import sys
import requests
import urllib3
from datetime import datetime

# Désactiver les avertissements SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_project_reports():
    """Test que les rapports apparaissent dans la page projet"""
    
    base_url = "https://127.0.0.1:9797"
    session = requests.Session()
    session.verify = False
    
    print("🔍 Test de l'affichage des rapports dans la page projet")
    print("=" * 60)
    
    # 1. Connexion
    print("\n1. Connexion...")
    login_data = {
        'username': 'admin',
        'password': 'admin'
    }
    
    try:
        response = session.post(f"{base_url}/login", data=login_data, allow_redirects=False)
        if response.status_code == 302:
            print("✅ Connexion réussie")
        else:
            print(f"❌ Échec de la connexion: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur de connexion: {e}")
        return False
    
    # 2. Vérifier qu'il y a des projets
    print("\n2. Vérification des projets...")
    try:
        response = session.get(f"{base_url}/projects")
        if response.status_code == 200:
            print("✅ Page projets accessible")
            if "Projet" in response.text:
                print("✅ Projets trouvés")
            else:
                print("⚠️  Aucun projet trouvé")
        else:
            print(f"❌ Erreur accès projets: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur accès projets: {e}")
        return False
    
    # 3. Vérifier qu'il y a des rapports
    print("\n3. Vérification des rapports...")
    try:
        response = session.get(f"{base_url}/rapport")
        if response.status_code == 200:
            print("✅ Page rapports accessible")
            if "nmap" in response.text or "hydra" in response.text or "dirsearch" in response.text:
                print("✅ Rapports trouvés")
            else:
                print("⚠️  Aucun rapport trouvé")
        else:
            print(f"❌ Erreur accès rapports: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur accès rapports: {e}")
        return False
    
    # 4. Tester la page détail d'un projet
    print("\n4. Test de la page détail projet...")
    try:
        # Essayer le projet 1
        response = session.get(f"{base_url}/projects/1")
        if response.status_code == 200:
            print("✅ Page détail projet accessible")
            
            # Vérifier si la section rapports est présente
            if "Rapports associés" in response.text:
                print("✅ Section 'Rapports associés' trouvée")
                
                # Vérifier s'il y a des rapports listés
                if "Aucun rapport associé" in response.text:
                    print("ℹ️  Aucun rapport associé à ce projet")
                else:
                    print("✅ Rapports associés trouvés dans la page")
                    
                    # Vérifier les liens de téléchargement
                    if "download_report_api" in response.text:
                        print("✅ Liens de téléchargement corrects")
                    else:
                        print("⚠️  Liens de téléchargement manquants")
            else:
                print("❌ Section 'Rapports associés' manquante")
                return False
        else:
            print(f"❌ Erreur accès détail projet: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Erreur accès détail projet: {e}")
        return False
    
    # 5. Tester l'assignation d'un rapport
    print("\n5. Test d'assignation de rapport...")
    try:
        # Vérifier s'il y a des rapports disponibles
        response = session.get(f"{base_url}/rapport")
        if "nmap_" in response.text:
            # Extraire un nom de rapport nmap
            import re
            nmap_reports = re.findall(r'nmap_\d+_\d+\.txt', response.text)
            if nmap_reports:
                report_filename = nmap_reports[0]
                print(f"📋 Test avec le rapport: {report_filename}")
                
                # Tester la page d'assignation
                response = session.get(f"{base_url}/rapport/assign/{report_filename}")
                if response.status_code == 200:
                    print("✅ Page d'assignation accessible")
                    
                    # Assigner au projet 1
                    assign_data = {
                        'project_id': '1'
                    }
                    response = session.post(f"{base_url}/rapport/assign/{report_filename}", data=assign_data, allow_redirects=False)
                    if response.status_code == 302:
                        print("✅ Rapport assigné avec succès")
                        
                        # Vérifier que le rapport apparaît maintenant dans le projet
                        response = session.get(f"{base_url}/projects/1")
                        if report_filename in response.text:
                            print("✅ Rapport visible dans la page projet")
                        else:
                            print("❌ Rapport non visible dans la page projet")
                            return False
                    else:
                        print(f"❌ Échec de l'assignation: {response.status_code}")
                        return False
                else:
                    print(f"❌ Erreur page assignation: {response.status_code}")
                    return False
            else:
                print("⚠️  Aucun rapport nmap trouvé pour le test")
        else:
            print("⚠️  Aucun rapport disponible pour le test")
    except Exception as e:
        print(f"❌ Erreur test assignation: {e}")
        return False
    
    print("\n" + "=" * 60)
    print("🎉 Test terminé avec succès !")
    print("\n📋 Instructions pour tester manuellement:")
    print("1. Allez sur https://127.0.0.1:9797")
    print("2. Connectez-vous avec admin/admin")
    print("3. Allez dans 'Rapports' et assignez un rapport à un projet")
    print("4. Allez dans 'Projets' et cliquez sur un projet")
    print("5. Vérifiez que les rapports associés apparaissent dans la section 'Rapports associés'")
    print("6. Testez les liens de téléchargement TXT et PDF")
    
    return True

if __name__ == "__main__":
    success = test_project_reports()
    sys.exit(0 if success else 1) 