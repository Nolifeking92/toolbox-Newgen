#!/usr/bin/env python3
"""
Script pour vérifier les associations de rapports dans la base de données
"""

import os
import sys

# Ajouter le dossier web au path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'web'))

from app import app, db, Project, ProjectReport

def check_database():
    """Vérifier les associations dans la base de données"""
    
    with app.app_context():
        print("🔍 Vérification des associations de rapports dans la base de données")
        print("=" * 60)
        
        # Vérifier les projets
        projects = Project.query.all()
        print(f"\n📋 Projets trouvés: {len(projects)}")
        for project in projects:
            print(f"   - Projet {project.id}: {project.name}")
        
        # Vérifier les associations de rapports
        project_reports = ProjectReport.query.all()
        print(f"\n📋 Associations de rapports trouvées: {len(project_reports)}")
        for pr in project_reports:
            print(f"   - Projet {pr.project_id} -> {pr.report_filename} ({pr.report_type})")
        
        # Vérifier les rapports pour le projet 1
        print(f"\n📋 Rapports associés au projet 1:")
        project1_reports = ProjectReport.query.filter_by(project_id=1).all()
        for pr in project1_reports:
            print(f"   - {pr.report_filename} ({pr.report_type})")
            
            # Vérifier si le fichier existe
            report_path = os.path.join(os.path.dirname(__file__), 'reports', pr.report_filename)
            if os.path.exists(report_path):
                print(f"     ✅ Fichier existe: {report_path}")
            else:
                print(f"     ❌ Fichier manquant: {report_path}")
        
        print("\n" + "=" * 60)
        print("🎉 Vérification terminée !")

if __name__ == "__main__":
    check_database() 