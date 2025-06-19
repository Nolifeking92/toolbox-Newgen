#!/usr/bin/env python3
"""
Script pour tester directement la fonction project_detail
"""

import os
import sys

# Ajouter le dossier web au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web'))

from app import app, db, Project, ProjectReport
from datetime import datetime

def test_direct():
    """Test direct de la fonction project_detail"""
    
    with app.app_context():
        print("🔍 Test direct de la fonction project_detail")
        print("=" * 60)
        
        # Récupérer le projet 1
        project = Project.query.get(1)
        if project:
            print(f"✅ Projet trouvé: {project.name} (ID: {project.id})")
            
            # Récupérer les rapports associés
            project_report_entries = ProjectReport.query.filter_by(project_id=project.id).all()
            print(f"📋 {len(project_report_entries)} rapports trouvés dans la DB")
            
            project_reports = []
            for report_entry in project_report_entries:
                print(f"   - {report_entry.report_filename} ({report_entry.report_type})")
                
                # Vérifier si le fichier existe
                report_path = os.path.join(os.path.dirname(__file__), '..', 'reports', report_entry.report_filename)
                print(f"     🔍 Vérification du chemin: {report_path}")
                if os.path.exists(report_path):
                    print(f"     ✅ Fichier existe")
                    
                    # Extraire la date
                    date_str = 'Date inconnue'
                    try:
                        filename = report_entry.report_filename
                        parts = filename.replace('.txt', '').split('_')
                        if len(parts) >= 3:
                            date_part = parts[-2] + '_' + parts[-1]
                            if len(date_part) == 15:
                                date_obj = datetime.strptime(date_part, '%Y%m%d_%H%M%S')
                                date_str = date_obj.strftime('%d/%m/%Y %H:%M')
                    except:
                        pass
                    
                    project_reports.append({
                        'filename': report_entry.report_filename,
                        'type': report_entry.report_type,
                        'date': date_str
                    })
                    print(f"     📅 Date: {date_str}")
                    print(f"     📋 Ajouté à la liste: {report_entry.report_filename}")
                else:
                    print(f"     ❌ Fichier manquant: {report_path}")
            
            print(f"\n📋 Total rapports pour template: {len(project_reports)}")
            for report in project_reports:
                print(f"   - {report['filename']} ({report['type']}) - {report['date']}")
        else:
            print("❌ Projet 1 non trouvé")
        
        print("\n" + "=" * 60)
        print("🎉 Test direct terminé !")

if __name__ == "__main__":
    test_direct() 