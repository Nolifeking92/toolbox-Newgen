#!/usr/bin/env python3
"""
Script pour tester manuellement l'affichage des rapports dans la page projet
"""

import requests
import urllib3
from bs4 import BeautifulSoup

# Désactiver les avertissements SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_manual():
    """Test manuel de l'affichage des rapports"""
    
    base_url = "https://127.0.0.1:9797"
    session = requests.Session()
    session.verify = False
    
    print("🔍 Test manuel de l'affichage des rapports dans la page projet")
    print("=" * 60)
    
    # 1. Connexion
    print("\n1. Connexion...")
    login_data = {
        'username': 'admin',
        'password': 'admin'
    }
    
    response = session.post(f"{base_url}/login", data=login_data, allow_redirects=False)
    if response.status_code == 302:
        print("✅ Connexion réussie")
    else:
        print(f"❌ Échec de la connexion: {response.status_code}")
        return
    
    # 2. Accéder à la page projet 1
    print("\n2. Accès à la page projet 1...")
    response = session.get(f"{base_url}/projects/1")
    if response.status_code == 200:
        print("✅ Page projet accessible")
        
        # Analyser le HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Chercher la section "Rapports associés"
        reports_section = soup.find(string=lambda text: text and "Rapports associés" in text)
        if reports_section:
            print("✅ Section 'Rapports associés' trouvée")
            
            # Chercher les liens de téléchargement
            download_links = soup.find_all('a', href=lambda href: href and 'download_report_api' in href)
            if download_links:
                print(f"✅ {len(download_links)} liens de téléchargement trouvés")
                for link in download_links:
                    print(f"   - {link.get('href')}")
            else:
                print("⚠️  Aucun lien de téléchargement trouvé")
                
            # Chercher les rapports listés
            if "Aucun rapport associé" in response.text:
                print("ℹ️  Aucun rapport associé à ce projet")
            else:
                print("✅ Rapports associés trouvés")
                
                # Extraire les informations des rapports
                table = soup.find('table', class_='tasks-table')
                if table:
                    rows = table.find_all('tr')[1:]  # Ignorer l'en-tête
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) >= 4:
                            report_type = cells[0].get_text(strip=True)
                            report_date = cells[1].get_text(strip=True)
                            report_filename = cells[2].get_text(strip=True)
                            print(f"   📋 {report_type} - {report_date} - {report_filename}")
        else:
            print("❌ Section 'Rapports associés' manquante")
    else:
        print(f"❌ Erreur accès projet: {response.status_code}")
    
    print("\n" + "=" * 60)
    print("🎉 Test manuel terminé !")

if __name__ == "__main__":
    test_manual() 