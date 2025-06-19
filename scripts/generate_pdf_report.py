import os
import sys
import glob
import re
from datetime import datetime

REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports'))
PDF_PATH = os.path.join(os.path.dirname(__file__), 'rapport_scans.pdf')
TOOLBOX_NAME = "Toolbox Newgen"

def parse_nmap_report(filepath):
    data = {
        'target': None,
        'date': None,
        'os': None,
        'ports': []
    }
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    for line in lines:
        if not data['date']:
            m = re.search(r'Starting Nmap.*at (.*)', line)
            if m:
                data['date'] = m.group(1).strip()
        if not data['target']:
            m = re.search(r'Nmap scan report for (.+?)( \(|$)', line)
            if m:
                data['target'] = m.group(1).strip()
        if 'OS details:' in line or 'OS guess:' in line:
            data['os'] = line.split(':', 1)[-1].strip()
        m = re.match(r'(\d+/tcp)\s+(open|closed|filtered)\s+(\S+)(.*)', line)
        if m:
            port, state, service, extra = m.groups()
            data['ports'].append({
                'port': port,
                'state': state,
                'service': service,
                'extra': extra.strip()
            })
    return data

def parse_openvas_report(filepath):
    vulns = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            if re.match(r'\s*- CVE-|SSL|privilege|Remote Code|expir', line, re.I):
                vulns.append(line.strip())
    return vulns

def parse_dirsearch_report(filepath):
    resources = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = re.match(r'\s*- (/.+?) \(Status: (\d+)\)', line)
            if m:
                resources.append({'path': m.group(1), 'status': m.group(2)})
    return resources

def parse_clamav_report(filepath):
    infected = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = re.match(r'\s*- (.+?): (.+) FOUND', line)
            if m:
                infected.append({'file': m.group(1), 'malware': m.group(2)})
    return infected

def parse_hydra_report(filepath):
    creds = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            m = re.match(r'\s*- login: (.+?), password: (.+)', line)
            if m:
                creds.append({'login': m.group(1), 'password': m.group(2)})
    return creds

def parse_zap_report(filepath):
    vulns = []
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
        # Extraire les vulnérabilités FAIL et WARN
        for line in content.split('\n'):
            if 'FAIL-NEW:' in line or 'WARN-NEW:' in line:
                vulns.append(line.strip())
            elif line.startswith('FAIL-NEW:') or line.startswith('WARN-NEW:'):
                vulns.append(line.strip())
    return vulns

def collect_reports():
    print(f"[DEBUG] Début de collect_reports()")
    reports = {}
    nmap_files = glob.glob(os.path.join(REPORTS_DIR, 'nmap_*.txt'))
    print(f"[DEBUG] Fichiers Nmap trouvés : {nmap_files}")
    for f in nmap_files:
        print(f"[DEBUG] Lecture Nmap : {f}")
        nmap = parse_nmap_report(f)
        if nmap['target']:
            reports[nmap['target']] = {
                'nmap': nmap,
                'openvas': [],
                'dirsearch': [],
                'clamav': [],
                'hydra': [],
                'zap': []
            }
    for tool, parser in [
        ('openvas', parse_openvas_report),
        ('dirsearch', parse_dirsearch_report),
        ('clamav', parse_clamav_report),
        ('hydra', parse_hydra_report),
        ('zap', parse_zap_report)
    ]:
        tool_files = glob.glob(os.path.join(REPORTS_DIR, f'{tool}_*.txt'))
        print(f"[DEBUG] Fichiers {tool} trouvés : {tool_files}")
        for f in tool_files:
            print(f"[DEBUG] Lecture {tool} : {f}")
            base = os.path.basename(f)
            date = base.split('_')[-1].replace('.txt','')
            for tgt in reports:
                reports[tgt][tool].extend(parser(f))
                break
    print(f"[DEBUG] Rapports collectés : {list(reports.keys())}")
    return reports

def generate_pentest_pdf():
    print("[DEBUG] Début de generate_pentest_pdf()")
    from fpdf import FPDF
    
    class PDF(FPDF):
        def header(self):
            # Logo
            self.set_font('Arial', 'B', 24)
            self.set_text_color(0, 255, 200)  # Cyan néon
            self.cell(0, 20, f'{TOOLBOX_NAME}', 0, 1, 'C')
            self.set_font('Arial', 'B', 16)
            self.set_text_color(255, 255, 255)  # Blanc
            self.cell(0, 10, 'Rapport de Test de Pénétration', 0, 1, 'C')
            self.ln(10)

        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.set_text_color(128, 128, 128)  # Gris
            self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.alias_nb_pages()
    
    # Ajout de la police DejaVu si disponible
    font_path = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
    if os.path.exists(font_path):
        pdf.add_font('DejaVu', '', font_path, uni=True)
        pdf.add_font('DejaVu', 'B', font_path, uni=True)
        base_font = 'DejaVu'
    else:
        base_font = 'Arial'

    reports = collect_reports()
    print(f"[DEBUG] Nombre de cibles trouvées : {len(reports)}")

    for tgt, data in reports.items():
        print(f"[DEBUG] Génération page PDF pour : {tgt}")
        pdf.add_page()
        
        # Information sur la cible
        pdf.set_fill_color(40, 44, 52)  # Fond sombre
        pdf.set_text_color(255, 255, 255)  # Texte blanc
        pdf.set_font(base_font, 'B', 14)
        pdf.cell(0, 10, f'Cible : {tgt}', 1, 1, 'L', True)
        
        # Date du scan
        date = data['nmap'].get('date') or datetime.now().strftime('%Y-%m-%d %H:%M')
        pdf.set_font(base_font, '', 10)
        pdf.set_fill_color(50, 54, 62)  # Fond légèrement plus clair
        pdf.cell(0, 8, f'Date du scan : {date}', 1, 1, 'L', True)
        pdf.ln(5)

        # Résumé des outils utilisés avec icônes
        outils_utilises = []
        if data.get('nmap') and data['nmap'].get('ports'): outils_utilises.append('🔍 Nmap')
        if data.get('openvas'): outils_utilises.append('🛡️ OpenVAS')
        if data.get('dirsearch'): outils_utilises.append('🔎 Dirsearch')
        if data.get('clamav'): outils_utilises.append('🦠 ClamAV')
        if data.get('hydra'): outils_utilises.append('🔑 Hydra')
        if data.get('zap'): outils_utilises.append('🕷️ ZAP')

        pdf.set_font(base_font, 'B', 12)
        pdf.set_fill_color(60, 64, 72)
        pdf.cell(0, 10, f"Outils utilisés : {', '.join(outils_utilises) if outils_utilises else 'Aucun'}", 1, 1, 'L', True)
        pdf.ln(5)

        # Section Nmap avec style amélioré
        if data.get('nmap') and data['nmap'].get('ports'):
            # Titre de section avec barre de couleur
            pdf.set_fill_color(0, 255, 200)  # Cyan néon
            pdf.cell(2, 10, '', 0, 0, 'L', True)
            pdf.set_fill_color(40, 44, 52)
            pdf.cell(0, 10, ' Résultats Nmap', 1, 1, 'L', True)
            
            # OS détecté
            if data['nmap'].get('os'):
                pdf.set_font(base_font, '', 11)
                pdf.set_fill_color(50, 54, 62)
                pdf.cell(0, 8, f"OS détecté : {data['nmap']['os']}", 1, 1, 'L', True)
                pdf.ln(2)

            # Tableau des ports avec couleurs selon l'état
            if data['nmap']['ports']:
                # En-tête du tableau
                pdf.set_fill_color(0, 255, 200)  # Cyan néon
                pdf.set_text_color(0, 0, 0)  # Texte noir
                pdf.set_font(base_font, 'B', 10)
                pdf.cell(30, 8, 'Port', 1, 0, 'C', True)
                pdf.cell(40, 8, 'Service', 1, 0, 'C', True)
                pdf.cell(30, 8, 'État', 1, 0, 'C', True)
                pdf.cell(0, 8, 'Info', 1, 1, 'C', True)

                # Contenu du tableau
                pdf.set_font(base_font, '', 10)
                for p in data['nmap']['ports']:
                    # Couleurs selon l'état
                    if p['state'] == 'open':
                        pdf.set_fill_color(255, 51, 51, 0.5)  # Rouge pour open
                    elif p['state'] == 'filtered':
                        pdf.set_fill_color(255, 153, 51, 0.5)  # Orange pour filtered
                    else:
                        pdf.set_fill_color(40, 44, 52)  # Gris foncé pour closed

                    pdf.set_text_color(255, 255, 255)  # Texte blanc
                    pdf.cell(30, 8, p['port'], 1, 0, 'C', True)
                    pdf.cell(40, 8, p['service'], 1, 0, 'C', True)
                    pdf.cell(30, 8, p['state'], 1, 0, 'C', True)
                    pdf.cell(0, 8, p['extra'], 1, 1, 'L', True)
                pdf.ln(5)

        # Section Vulnérabilités
        if data.get('openvas'):
            pdf.set_fill_color(0, 255, 200)
            pdf.cell(2, 10, '', 0, 0, 'L', True)
            pdf.set_fill_color(40, 44, 52)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font(base_font, 'B', 12)
            pdf.cell(0, 10, ' Vulnérabilités détectées', 1, 1, 'L', True)
            
            pdf.set_font(base_font, '', 10)
            for v in data['openvas']:
                pdf.set_fill_color(50, 54, 62)
                pdf.cell(0, 8, v, 1, 1, 'L', True)
            pdf.ln(5)

        # Section Ressources Web
        if data.get('dirsearch'):
            pdf.set_fill_color(0, 255, 200)
            pdf.cell(2, 10, '', 0, 0, 'L', True)
            pdf.set_fill_color(40, 44, 52)
            pdf.cell(0, 10, ' Ressources Web découvertes', 1, 1, 'L', True)
            
            pdf.set_fill_color(0, 255, 200)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(80, 8, 'Chemin', 1, 0, 'C', True)
            pdf.cell(0, 8, 'Status', 1, 1, 'C', True)
            
            pdf.set_text_color(255, 255, 255)
            for r in data['dirsearch']:
                pdf.set_fill_color(50, 54, 62)
                pdf.cell(80, 8, r['path'], 1, 0, 'L', True)
                pdf.cell(0, 8, r['status'], 1, 1, 'C', True)
            pdf.ln(5)

        # Section Malwares
        if data.get('clamav'):
            pdf.set_fill_color(0, 255, 200)
            pdf.cell(2, 10, '', 0, 0, 'L', True)
            pdf.set_fill_color(40, 44, 52)
            pdf.cell(0, 10, ' Fichiers infectés détectés', 1, 1, 'L', True)
            
            pdf.set_fill_color(50, 54, 62)
            for i in data['clamav']:
                pdf.cell(0, 8, f"{i['file']} - {i['malware']}", 1, 1, 'L', True)
            pdf.ln(5)

        # Section Brute Force
        if data.get('hydra'):
            pdf.set_fill_color(0, 255, 200)
            pdf.cell(2, 10, '', 0, 0, 'L', True)
            pdf.set_fill_color(40, 44, 52)
            pdf.cell(0, 10, ' Identifiants trouvés (Brute Force)', 1, 1, 'L', True)
            
            pdf.set_fill_color(0, 255, 200)
            pdf.set_text_color(0, 0, 0)
            pdf.cell(40, 8, 'Login', 1, 0, 'C', True)
            pdf.cell(0, 8, 'Mot de passe', 1, 1, 'C', True)
            
            pdf.set_text_color(255, 255, 255)
            for c in data['hydra']:
                pdf.set_fill_color(50, 54, 62)
                pdf.cell(40, 8, c['login'], 1, 0, 'C', True)
                pdf.cell(0, 8, c['password'], 1, 1, 'C', True)
            pdf.ln(5)

        # Section ZAP
        if data.get('zap'):
            pdf.set_fill_color(0, 255, 200)
            pdf.cell(2, 10, '', 0, 0, 'L', True)
            pdf.set_fill_color(40, 44, 52)
            pdf.cell(0, 10, ' Vulnérabilités détectées par ZAP', 1, 1, 'L', True)
            
            pdf.set_fill_color(50, 54, 62)
            for v in data['zap']:
                pdf.cell(0, 8, v, 1, 1, 'L', True)
            pdf.ln(5)

    pdf.output(PDF_PATH)
    print(f"[DEBUG] PDF généré à : {PDF_PATH}")

if __name__ == '__main__':
    generate_pentest_pdf() 