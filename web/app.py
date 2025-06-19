import os
import subprocess
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, send_from_directory, session, abort
from datetime import datetime, timedelta
import json
import psutil
import threading
import queue
import re
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from functools import wraps
import glob
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import requests
import shutil
from werkzeug.utils import secure_filename
import uuid
import time
from fpdf import FPDF
import csv
import io
from io import BytesIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 Mo

# Rate limiting for login attempts
login_attempts = {}
MAX_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes

def is_rate_limited(ip):
    if ip not in login_attempts:
        return False
    attempts = login_attempts[ip]
    if len(attempts) >= MAX_ATTEMPTS:
        last_attempt = attempts[-1]
        if (datetime.now() - last_attempt).total_seconds() < LOCKOUT_TIME:
            return True
        login_attempts[ip] = []  # Reset after lockout period
    return False

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Force HTTPS redirect
@app.before_request
def force_https():
    if app.config.get('TESTING', False):
        return
    if not request.is_secure and app.config.get('ENV', 'production') != "development":
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

TRANSLATIONS = {
    'fr': {
        'login': 'Connexion',
        'username': "Nom d'utilisateur",
        'password': 'Mot de passe',
        'submit': 'Se connecter',
        'logout': 'Déconnexion',
        'dashboard': 'Tableau de bord',
        'recent_scans': 'Scans récents',
        'vulns': 'Vulnérabilités détectées',
        'system_activity': 'Activité système',
        'cpu': 'CPU',
        'memory': 'Mémoire',
        'disk': 'Disque',
        'total_scans': 'Total des scans',
        'last_24h': 'Dernières 24h',
        'critical': 'Critiques',
        'high': 'Élevées',
        'medium': 'Moyennes',
        'feedback': 'Feedback',
        'users': 'Utilisateurs',
        'planification': 'Planification',
        'admin_feedbacks': 'Feedbacks (admin)',
    },
    'en': {
        'login': 'Login',
        'username': 'Username',
        'password': 'Password',
        'submit': 'Sign in',
        'logout': 'Logout',
        'dashboard': 'Dashboard',
        'recent_scans': 'Recent scans',
        'vulns': 'Detected vulnerabilities',
        'system_activity': 'System activity',
        'cpu': 'CPU',
        'memory': 'Memory',
        'disk': 'Disk',
        'total_scans': 'Total scans',
        'last_24h': 'Last 24h',
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'feedback': 'Feedback',
        'users': 'Users',
        'planification': 'Scheduling',
        'admin_feedbacks': 'Feedbacks (admin)',
    }
}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='user')

class ScanPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    outil = db.Column(db.String(50), nullable=False)
    cible = db.Column(db.String(255), nullable=False)
    type_plan = db.Column(db.String(20), nullable=False)  # 'jour' ou 'unique'
    date_heure = db.Column(db.String(30), nullable=False) # ISO string
    recurrence = db.Column(db.String(20), nullable=True)  # 'daily', 'weekly', 'none'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    username = db.Column(db.String(150), nullable=False)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    client = db.Column(db.String(150), nullable=True)
    start_date = db.Column(db.String(30), nullable=True)
    end_date = db.Column(db.String(30), nullable=True)
    status = db.Column(db.String(30), nullable=False, default='En cours')
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    owner = db.relationship('User', backref='projects')
    progress = db.Column(db.Integer, default=0)

class ProjectMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    role = db.Column(db.String(50), default='contributeur')
    project = db.relationship('Project', backref='memberships')
    user = db.relationship('User', backref='project_memberships')

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    name = db.Column(db.String(150), nullable=False)
    due_date = db.Column(db.String(30), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    progress = db.Column(db.Integer, default=0)  # 0 à 100
    project = db.relationship('Project', backref='tasks')

class ProjectReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    report_filename = db.Column(db.String(255), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)  # nmap, hydra, etc.
    added_date = db.Column(db.DateTime, default=datetime.utcnow)
    project = db.relationship('Project', backref='reports')

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    lang = session.get('lang', 'fr')
    if request.method == 'POST':
        ip = request.remote_addr
        if is_rate_limited(ip):
            remaining_time = LOCKOUT_TIME - (datetime.now() - login_attempts[ip][-1]).total_seconds()
            flash(f'Trop de tentatives. Réessayez dans {int(remaining_time)} secondes.', 'danger')
            return render_template('login.html', hide_sidebar=True, lang=lang, t=TRANSLATIONS[lang])

        lang = request.form.get('lang', 'fr')
        session['lang'] = lang
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            if ip in login_attempts:
                del login_attempts[ip]  # Reset attempts on successful login
            logging.info(f"Connexion réussie pour l'utilisateur {username}")
            return redirect(url_for('dashboard'))
        else:
            if ip not in login_attempts:
                login_attempts[ip] = []
            login_attempts[ip].append(datetime.now())
            logging.warning(f"Échec de connexion pour l'utilisateur {username}")
            flash('Identifiants invalides', 'danger')
    return render_template('login.html', hide_sidebar=True, lang=lang, t=TRANSLATIONS[lang])

@app.route('/logout')
@login_required
def logout():
    logging.info(f"Déconnexion de l'utilisateur {current_user.username}")
    logout_user()
    return redirect(url_for('login'))

@app.route('/users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Accès réservé à l\'admin', 'danger')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        if 'add' in request.form:
            username = request.form['username']
            password = request.form['password']
            role = request.form['role']
            if User.query.filter_by(username=username).first():
                flash('Utilisateur déjà existant', 'warning')
            else:
                hashed_password = generate_password_hash(password)
                new_user = User(username=username, password=hashed_password, role=role)
                db.session.add(new_user)
                db.session.commit()
                logging.info(f"Ajout de l'utilisateur {username} par {current_user.username}")
                flash('Utilisateur ajouté', 'success')
        elif 'delete' in request.form:
            user_id = request.form['user_id']
            user = db.session.get(User, user_id)
            if user and user.username != 'admin':
                db.session.delete(user)
                db.session.commit()
                logging.warning(f"Suppression de l'utilisateur {user.username} par {current_user.username}")
                flash('Utilisateur supprimé', 'success')
            else:
                flash('Impossible de supprimer cet utilisateur', 'danger')
    users = User.query.all()
    return render_template('users.html', users=users)

# Protéger toutes les routes existantes (dashboard, scans, etc.)
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Accès réservé à l\'admin', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def require_login():
    allowed_routes = ['login', 'static']
    if request.endpoint is not None and not request.endpoint.startswith('static') and request.endpoint not in allowed_routes and not current_user.is_authenticated:
        return redirect(url_for('login'))

REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports'))
PDF_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts/rapport_scans.pdf'))

TOOLS_CONFIG = {
    'nmap': {
        'cmd': 'docker run --rm -v /home/kali/toolboxNewgenBAckup/analysis/samples:/targets -v /home/kali/toolboxNewgenBAckup/analysis/reports:/reports uzyexe/nmap:latest nmap -A -p 1-1024 -vv {target}',
        'description': 'Scanner de ports et de services',
        'icon': '🔍'
    },
    'dirsearch': {
        'cmd': 'docker run --rm -v /home/kali/toolboxNewgenBAckup/analysis/samples:/targets -v /home/kali/toolboxNewgenBAckup/analysis/reports:/reports toolboxnewgenbackup-dirsearch python /dirsearch/dirsearch.py -u {target}',
        'description': 'Scanner de répertoires web',
        'icon': '📁'
    },
    'clamav': {
        'cmd': 'docker run --rm -v /home/kali/toolboxNewgenBAckup/analysis/samples:/scan -v /home/kali/toolboxNewgenBAckup/analysis/reports:/reports toolboxnewgenbackup-clamav clamscan {target}',
        'description': 'Antivirus',
        'icon': '🛡️'
    },
    'hydra': {
        'cmd': 'docker run --rm -v /home/kali/toolboxNewgenBAckup/analysis/samples:/targets -v /home/kali/toolboxNewgenBAckup/analysis/reports:/reports toolboxnewgenbackup-hydra hydra -l Mahamadou -P pass.txt {target} http-post-form',
        'description': 'Outil de bruteforce',
        'icon': '💧'
    },
    'sqlmap': {
        'cmd': 'docker run --rm -v /home/kali/toolboxNewgenBAckup/analysis/samples:/targets -v /home/kali/toolboxNewgenBAckup/analysis/reports:/reports toolboxnewgenbackup-sqlmap python /sqlmap/sqlmap.py -u {target}',
        'description': "Détection et exploitation d'injections SQL",
        'icon': '🩸'
    },
    'zap': {
        'cmd': 'docker run --rm -v /home/kali/toolboxNewgenBAckup/analysis/samples:/zap/wrk -v /home/kali/toolboxNewgenBAckup/analysis/reports:/reports toolboxnewgenbackup-zap /zap/zap-baseline.py -t {url}',
        'description': 'Scanner de vulnérabilités web (OWASP ZAP)',
        'icon': '🕷️'
    },
    'malware': {
        'cmd': '',
        'description': 'Analyse de fichiers malveillants',
        'icon': '🦠'
    },
    'john': {
        'cmd': 'docker run --rm -v /home/kali/toolboxNewgenBAckup/analysis/samples:/targets -v /home/kali/toolboxNewgenBAckup/analysis/reports:/reports toolboxnewgenbackup-john john {hashfile}',
        'description': 'Crack de mots de passe (hashes)',
        'icon': '🔑'
    }
}

RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

def get_system_stats():
    """Récupère les statistiques système actuelles."""
    return {
        'cpu_usage': round(psutil.cpu_percent(interval=1), 1),
        'mem_usage': round(psutil.virtual_memory().percent, 1),
        'disk_usage': round(psutil.disk_usage('/').percent, 1)
    }

def parse_nmap_output(content):
    """Parse Nmap output and extract ports, services and vulnerabilities."""
    ports = {'open': 0, 'closed': 0, 'filtered': 0}
    services = {}
    vulns = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    
    lines = content.split('\n')
    for line in lines:
        # Parse ports
        if 'open' in line:
            ports['open'] += 1
            # Extract service
            service_match = re.search(r'(\d+)/tcp\s+open\s+(\w+)', line)
            if service_match:
                service = service_match.group(2)
                services[service] = services.get(service, 0) + 1
        elif 'closed' in line:
            ports['closed'] += 1
        elif 'filtered' in line:
            ports['filtered'] += 1
            
        # Parse vulnerabilities
        if 'VULNERABLE' in line:
            if 'CRITICAL' in line or 'CRITICAL' in line.upper():
                vulns['critical'] += 1
            elif 'HIGH' in line or 'HIGH' in line.upper():
                vulns['high'] += 1
            elif 'MEDIUM' in line or 'MEDIUM' in line.upper():
                vulns['medium'] += 1
            else:
                vulns['low'] += 1
                
    return ports, services, vulns

@app.route('/')
def index():
    # Statistiques par défaut
    default_stats = {
        'total_scans': 0,
        'recent_scans': 0,
        'critical_vulns': 0,
        'high_vulns': 0,
        'medium_vulns': 0,
        'cpu_usage': 0,
        'mem_usage': 0,
        'disk_usage': 0
    }
    
    # Statistiques système
    try:
        system_stats = get_system_stats()
        default_stats.update(system_stats)
    except:
        pass
    
    return render_template('dashboard.html', 
                         active_page='dashboard',
                         stats=default_stats,
                         recent_scans=[])

@app.route('/dashboard')
@login_required
def dashboard():
    lang = session.get('lang', 'fr')
    # Statistiques système
    system_stats = get_system_stats()
    
    # Statistiques des scans
    scan_stats = {
        'total_scans': 0,
        'recent_scans': 0,
        'critical_vulns': 0,
        'high_vulns': 0,
        'medium_vulns': 0,
        'infected_files': 0  # Nouveau compteur pour les fichiers infectés
    }
    
    # Liste des alertes
    alerts = []
    recent_scans = []
    now = datetime.now()
    
    # Parcours des fichiers de résultats
    for filename in os.listdir(REPORTS_DIR):
        if not filename.endswith('.txt'):
            continue
        parts = filename.split('_')
        if len(parts) < 2:
            continue  # Ignore les fichiers qui ne respectent pas le format attendu
        scan_stats['total_scans'] += 1
        # Parse timestamp from filename
        if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
            timestamp_str = parts[1] + parts[2].replace('.txt','')
        else:
            timestamp_str = parts[1].replace('.txt','')
        scan_time = None
        try:
            scan_time = datetime.strptime(timestamp_str, '%Y%m%d%H%M%S')
        except ValueError:
            try:
                scan_time = datetime.strptime(timestamp_str, '%Y%m%d')
            except ValueError:
                scan_time = None
        if scan_time is None:
            continue

        # Vérification si le scan est récent (24h)
        is_recent = now - scan_time < timedelta(hours=24)
        if is_recent:
            scan_stats['recent_scans'] += 1

        tool = parts[0]
        with open(os.path.join(REPORTS_DIR, filename), 'r') as f:
            content = f.read()
            # Gestion des scans récents pour l'affichage
            if len(recent_scans) < 5:
                recent_scans.append({
                    'tool': tool,
                    'tool_icon': TOOLS_CONFIG[tool]['icon'],
                    'target': content.split('\n')[0].split(': ')[1] if ': ' in content.split('\n')[0] else 'N/A',
                    'timestamp': scan_time.strftime('%d/%m/%Y %H:%M')
                })

            # Analyse des vulnérabilités nmap
            if tool == 'nmap':
                _, _, vulns = parse_nmap_output(content)
                scan_stats['critical_vulns'] += vulns['critical']
                scan_stats['high_vulns'] += vulns['high']
                scan_stats['medium_vulns'] += vulns['medium']
                # Alerte si vulnérabilités critiques récentes
                if is_recent and vulns['critical'] > 0:
                    alerts.append(f"⚠️ {vulns['critical']} vulnérabilité(s) critique(s) détectée(s) !")
            # Analyse des résultats ClamAV
            elif tool == 'malware':
                if 'FOUND' in content:  # Fichier infecté
                    scan_stats['infected_files'] += 1
                    if is_recent:
                        alerts.append("🦠 Fichier infecté détecté !")

    # Alerte système si utilisation CPU/RAM élevée
    if system_stats['cpu_usage'] > 90:
        alerts.append("⚡ Utilisation CPU élevée !")
    if system_stats['mem_usage'] > 90:
        alerts.append("💾 Mémoire système critique !")

    return render_template('dashboard.html',
                         active_page='dashboard',
                         stats={**scan_stats, **system_stats},
                         recent_scans=sorted(recent_scans, key=lambda x: x['timestamp'], reverse=True),
                         alerts=alerts,  # Nouvelle variable pour les alertes
                         lang=lang,
                         t=TRANSLATIONS[lang])

@app.route('/scans')
def scans():
    lang = session.get('lang', 'fr')
    return render_template('scans.html', active_page='scans', lang=lang, t=TRANSLATIONS[lang])

@app.route('/rapport')
def rapport():
    reports = []
    # 1. Récupérer les fichiers .txt dans reports/
    report_files = [(REPORTS_DIR, f) for f in os.listdir(REPORTS_DIR) if f.endswith('.txt')]
    # 2. Récupérer les fichiers .txt dans web/results/ (racine)
    results_root = os.path.abspath(os.path.join(os.path.dirname(__file__), 'results'))
    report_files += [(results_root, f) for f in os.listdir(results_root) if f.endswith('.txt')]
    # 3. Récupérer les fichiers .txt dans les sous-dossiers directs de web/results/
    for subdir in ['malware', 'memory', 'network', 'zap']:
        subdir_path = os.path.join(results_root, subdir)
        if os.path.exists(subdir_path):
            report_files += [(subdir_path, f) for f in os.listdir(subdir_path) if f.endswith('.txt')]
    for dir_path, filename in report_files:
        parts = filename.split('_')
        if len(parts) < 2:
            continue  # Ignore les fichiers qui ne respectent pas le format attendu
        tool = parts[0]
        # Correction : gérer les noms avec date + heure (ex: nmap_20250615_172544.txt)
        if len(parts) >= 3 and parts[1].isdigit() and parts[2].isdigit():
            timestamp_str = parts[1] + parts[2].replace('.txt','')
        else:
            timestamp_str = parts[1].replace('.txt','')
        scan_time = None
        try:
            scan_time = datetime.strptime(timestamp_str, '%Y%m%d%H%M%S')
        except ValueError:
            try:
                scan_time = datetime.strptime(timestamp_str, '%Y%m%d')
            except ValueError:
                scan_time = None
        if scan_time is None:
            continue
        with open(os.path.join(dir_path, filename), 'r') as f:
            content = f.read()
            if len(timestamp_str) == 15:  # format YYYYMMDD_HHMMSS
                date_str = scan_time.strftime('%d/%m/%Y %H:%M:%S')
            else:
                date_str = scan_time.strftime('%d/%m/%Y')
            if tool == 'malware':
                title = f'Analyse Malware - {date_str}'
            else:
                title = f'Scan {tool.upper()} - {date_str}'
            report = {
                'id': filename,
                'title': title,
                'date': date_str,
                'tools': [tool],
                'preview': content[:200] + '...' if len(content) > 200 else content,
                'vulns': {'critical': 0, 'high': 0, 'medium': 0}
            }
            if tool == 'nmap':
                _, _, vulns = parse_nmap_output(content)
                report['vulns'] = vulns
            reports.append(report)
    return render_template('rapport.html',
                         active_page='rapport',
                         reports=sorted(reports, key=lambda x: x['date'], reverse=True))

@app.route('/graphique')
def graphique():
    # Données pour les graphiques
    all_ports = {'open': 0, 'closed': 0, 'filtered': 0}
    all_services = {}
    all_vulns = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    activity_data = {}

    # Date limite pour l'historique (14 jours)
    today = datetime.now()
    date_limit = today - timedelta(days=14)

    # On prend les fichiers .txt dans reports/ ET web/results/ (et sous-dossiers)
    report_files = [(REPORTS_DIR, f) for f in os.listdir(REPORTS_DIR) if f.endswith('.txt')]
    results_root = os.path.abspath(os.path.join(os.path.dirname(__file__), 'results'))
    report_files += [(results_root, f) for f in os.listdir(results_root) if f.endswith('.txt')]
    for subdir in ['malware', 'memory', 'network', 'zap']:
        subdir_path = os.path.join(results_root, subdir)
        if os.path.exists(subdir_path):
            report_files += [(subdir_path, f) for f in os.listdir(subdir_path) if f.endswith('.txt')]

    try:
        for dir_path, filename in report_files:
            parts = filename.split('_')
            if len(parts) < 2:
                continue  # Ignore les fichiers qui ne respectent pas le format attendu
            # Extraction de la date du fichier
            if len(parts) >= 2:
                date_str = parts[1]
                if len(date_str) >= 8:  # Au moins YYYYMMDD
                    try:
                        scan_time = datetime.strptime(date_str[:8], '%Y%m%d')
                    except Exception:
                        continue
                    # Ne garder que les 14 derniers jours
                    if scan_time < date_limit:
                        continue
                    scan_date = scan_time.strftime('%d/%m')  # Format JJ/MM
                    activity_data[scan_date] = activity_data.get(scan_date, 0) + 1

                    if filename.startswith('nmap_'):
                        with open(os.path.join(dir_path, filename), 'r') as f:
                            content = f.read()
                            # Analyse du contenu pour les vulnérabilités
                            for line in content.split('\n'):
                                if 'VULNERABLE' in line.upper():
                                    if 'CRITICAL' in line.upper():
                                        all_vulns['critical'] += 1
                                    elif 'HIGH' in line.upper():
                                        all_vulns['high'] += 1
                                    elif 'MEDIUM' in line.upper():
                                        all_vulns['medium'] += 1
                                    else:
                                        all_vulns['low'] += 1
                                # Analyse des ports
                                if '/tcp' in line or '/udp' in line:
                                    if 'open' in line:
                                        all_ports['open'] += 1
                                        # Extraction du service
                                        parts_line = line.split()
                                        if len(parts_line) > 2:
                                            service = parts_line[2]
                                            all_services[service] = all_services.get(service, 0) + 1
                                    elif 'closed' in line:
                                        all_ports['closed'] += 1
                                    elif 'filtered' in line:
                                        all_ports['filtered'] += 1
        # Trier les dates et remplir les jours manquants
        dates = []
        counts = []
        current_date = date_limit
        while current_date <= today:
            date_str = current_date.strftime('%d/%m')  # Format JJ/MM
            dates.append(date_str)
            counts.append(activity_data.get(date_str, 0))
            current_date += timedelta(days=1)

        return render_template('graphique.html',
                            active_page='graphique',
                            stats={'vulns': all_vulns},
                            activity_dates=json.dumps(dates),
                            activity_counts=json.dumps(counts),
                            ports_labels=json.dumps(list(all_ports.keys())),
                            ports_data=json.dumps(list(all_ports.values())),
                            services_labels=json.dumps(list(all_services.keys())),
                            services_data=json.dumps(list(all_services.values())))
    except Exception as e:
        print(f"[ERROR] Erreur lors de la génération des graphiques: {str(e)}")
        import traceback
        traceback.print_exc()
        return render_template('graphique.html',
                            active_page='graphique',
                            stats={'vulns': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}},
                            activity_dates=json.dumps([]),
                            activity_counts=json.dumps([]),
                            ports_labels=json.dumps([]),
                            ports_data=json.dumps([]),
                            services_labels=json.dumps([]),
                            services_data=json.dumps([]))

ALLOWED_EXTENSIONS = {'txt', 'list', 'dic'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/run_tools', methods=['POST'])
def run_tools():
    import json  # Import local pour éviter l'UnboundLocalError
    if request.content_type and request.content_type.startswith('multipart/form-data'):
        data = request.form
        files = request.files
        tools = json.loads(data.get('tools', '[]'))
        target = data.get('target')
        hydra_params = json.loads(data.get('hydra', '{}'))
        dirsearch_params = json.loads(data.get('dirsearch', '{}'))
        clamav_params = json.loads(data.get('clamav', '{}'))
        sqlmap_params = json.loads(data.get('sqlmap', '{}'))
        zap_params = json.loads(data.get('zap', '{}'))
        # Gestion du fichier uploadé pour Hydra
        hydra_passfile = files.get('hydra_passfile')
        filepath = None
        if hydra_passfile:
            if not allowed_file(hydra_passfile.filename):
                return jsonify({'error': 'Type de fichier non autorisé. Seuls les fichiers .txt, .list, .dic sont acceptés.'}), 400
            filename = secure_filename(hydra_passfile.filename)
            unique_name = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join('/tmp', unique_name)
            hydra_passfile.save(filepath)
            # Log upload
            with open('/tmp/hydra_uploads.log', 'a') as logf:
                logf.write(f"{datetime.now().isoformat()} | IP: {request.remote_addr} | Nom: {filename} | Unique: {unique_name} | Taille: {hydra_passfile.content_length or 'inconnue'}\n")
            hydra_params['password'] = filepath  # On force l'utilisation du fichier uploadé
        # Suite du code identique
    else:
        data = request.get_json()
        tools = data.get('tools', [])
        target = data.get('target')
        hydra_params = data.get('hydra', {})
        dirsearch_params = data.get('dirsearch', {})
        clamav_params = data.get('clamav', {})
        sqlmap_params = data.get('sqlmap', {})
        zap_params = data.get('zap', {})
        filepath = None
    if not tools or (not target and not (len(tools) == 1 and tools[0] == 'john')):
        return jsonify({'error': 'Paramètres invalides'}), 400
    result_queue = queue.Queue()
    threads = []
    for tool in tools:
        thread = None
        if tool in TOOLS_CONFIG:
            if tool == 'hydra':
                thread = threading.Thread(target=run_tool_async, args=(tool, target, result_queue, hydra_params, None, None, None, None, None, None))
            elif tool == 'dirsearch':
                thread = threading.Thread(target=run_tool_async, args=(tool, target, result_queue, None, dirsearch_params, None, None, None, None, None))
            elif tool == 'clamav':
                thread = threading.Thread(target=run_tool_async, args=(tool, target, result_queue, None, None, clamav_params, None, None, None, None))
            elif tool == 'sqlmap':
                thread = threading.Thread(target=run_tool_async, args=(tool, target, result_queue, None, None, None, sqlmap_params, None, None, None))
            elif tool == 'nmap':
                # Récupère les paramètres AVANT le thread
                scan_profile = data.get('scan_profile', 'rapide') if 'scan_profile' in data else 'rapide'
                custom_nmap_options = data.get('custom_nmap_options', '').strip() if 'custom_nmap_options' in data else ''
                thread = threading.Thread(target=run_tool_async, args=(tool, target, result_queue, None, None, None, None, None, scan_profile, custom_nmap_options))
            elif tool == 'zap':
                print('[DEBUG] ZAP params:', zap_params)
                if zap_params:
                    # ZAP est exécuté directement, pas dans un thread
                    url = zap_params.get('url', '').strip()
                    extra = zap_params.get('extra', '').strip()
                    print(f'[DEBUG] ZAP URL: {url}')
                    print(f'[DEBUG] ZAP extra: {extra}')
                    if not url:
                        result_queue.put({
                            'tool': tool,
                            'status': 'error',
                            'output': "Erreur : l'URL cible est requise pour ZAP."
                        })
                        continue
                    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'results/zap'))
                    os.makedirs(results_dir, exist_ok=True)
                    print(f'[DEBUG] ZAP results_dir: {results_dir}')
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    report_html = os.path.join(results_dir, f'zap_{timestamp}.html')
                    print(f'[DEBUG] ZAP report_html: {report_html}')
                    docker_cmd = [
                        'docker', 'run', '--rm',
                        '-v', f'{results_dir}:/zap/wrk',
                        'ghcr.io/zaproxy/zaproxy',
                        'zap-baseline.py',
                        '-t', url,
                        '-r', f'zap_{timestamp}.html'
                    ]
                    if extra:
                        docker_cmd += extra.split()
                    print(f'[DEBUG] ZAP docker_cmd: {docker_cmd}')
                    try:
                        print('[DEBUG] ZAP: Lancement du conteneur Docker...')
                        # Utiliser subprocess.run au lieu de check_output pour gérer les codes de sortie non-zéro
                        result = subprocess.run(docker_cmd, capture_output=True, text=True, timeout=600)
                        output = result.stdout + result.stderr
                        print(f'[DEBUG] ZAP: Conteneur terminé, exit code: {result.returncode}, output length: {len(output)}')
                        
                        # ZAP peut retourner un code non-zéro même en cas de succès (warnings)
                        if result.returncode != 0 and "FAIL-NEW: 0" not in output:
                            # Vraie erreur seulement si pas de "FAIL-NEW: 0" dans la sortie
                            raise subprocess.CalledProcessError(result.returncode, docker_cmd, output)
                        
                        # Générer aussi TXT/JSON/CSV à partir de la sortie
                        txt_path = os.path.join(results_dir, f'zap_{timestamp}.txt')
                        json_path = os.path.join(results_dir, f'zap_{timestamp}.json')
                        csv_path = os.path.join(results_dir, f'zap_{timestamp}.csv')
                        print(f'[DEBUG] ZAP: Génération des fichiers de rapport...')
                        with open(txt_path, 'w') as f:
                            f.write(output)
                        with open(json_path, 'w') as f:
                            json.dump({'output': output}, f, indent=2)
                        with open(csv_path, 'w') as f:
                            f.write('output\n"' + output.replace('"', '""').replace('\n', ' ') + '"\n')
                        print(f'[DEBUG] ZAP: Fichiers générés - TXT: {os.path.exists(txt_path)}, JSON: {os.path.exists(json_path)}, CSV: {os.path.exists(csv_path)}')
                        
                        # Copier les rapports ZAP vers reports/ pour centralisation
                        reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports'))
                        os.makedirs(reports_dir, exist_ok=True)
                        
                        # Copier les fichiers vers reports/
                        import shutil
                        for ext in ['txt', 'json', 'csv', 'html']:
                            src_file = os.path.join(results_dir, f'zap_{timestamp}.{ext}')
                            dst_file = os.path.join(reports_dir, f'zap_{timestamp}.{ext}')
                            if os.path.exists(src_file):
                                shutil.copy2(src_file, dst_file)
                                print(f'[DEBUG] ZAP: Copié {src_file} vers {dst_file}')
                        
                        result_queue.put({
                            'tool': tool,
                            'status': 'success',
                            'output': output,
                            'filename': f'zap_{timestamp}.txt',
                            'html_report': f'zap_{timestamp}.html'
                        })
                    except subprocess.CalledProcessError as e:
                        error_output = e.output if hasattr(e, 'output') else str(e)
                        print(f'[DEBUG] ZAP: Erreur CalledProcessError: {error_output}')
                        result_queue.put({
                            'tool': tool,
                            'status': 'error',
                            'output': error_output
                        })
                    except Exception as e:
                        print(f'[DEBUG] ZAP: Exception: {e}')
                        result_queue.put({
                            'tool': tool,
                            'status': 'error',
                            'output': str(e)
                        })
                    continue  # <-- Important : on saute thread.start() pour ZAP
            elif tool == 'john':
                import json  # Import local pour éviter les conflits
                hashfile_path = None
                # Chercher le fichier hash uploadé dans /tmp ou results ou analysis/samples
                # On prend le plus récent fichier john_hashfile si plusieurs
                possible_dirs = [os.path.join(os.path.dirname(__file__), '../analysis/samples'), os.path.join(os.path.dirname(__file__), 'results'), '/tmp']
                for d in possible_dirs:
                    if os.path.exists(d):
                        files = [f for f in os.listdir(d) if f.endswith('.txt') or f.endswith('.hash')]
                        if files:
                            files = sorted([os.path.join(d, f) for f in files], key=os.path.getmtime, reverse=True)
                            hashfile_path = files[0]
                            break
                if not hashfile_path:
                    result_queue.put({
                        'tool': tool,
                        'status': 'error',
                        'output': "Aucun fichier de hash trouvé pour John the Ripper."
                    })
                    return
                base_cmd = TOOLS_CONFIG[tool]['cmd'].format(hashfile=hashfile_path)
                cmd = f"{base_cmd}"
                result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                result_file = os.path.join(REPORTS_DIR, f'{tool}_{timestamp}.txt')
                with open(result_file, 'w') as f:
                    f.write(f"Commande: {cmd}\n")
                    f.write(f"Sortie standard:\n{result.stdout}\n")
                    f.write(f"Erreur standard:\n{result.stderr}\n")
                # Générer JSON et CSV
                base_name = f'{tool}_{timestamp}'
                json_file = os.path.join(REPORTS_DIR, f'{base_name}.json')
                csv_file = os.path.join(REPORTS_DIR, f'{base_name}.csv')
                json_obj = {
                    'command': cmd,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'status': 'success' if result.returncode == 0 else 'error'
                }
                with open(json_file, 'w') as f:
                    json.dump(json_obj, f, indent=2)
                with open(csv_file, 'w') as f:
                    writer = csv.writer(f)
                    writer.writerow(['field', 'value'])
                    writer.writerow(['command', cmd])
                    writer.writerow(['stdout', result.stdout.replace('"', '""').replace('\n', ' ')])
                    writer.writerow(['stderr', result.stderr.replace('"', '""').replace('\n', ' ')])
                    writer.writerow(['status', 'success' if result.returncode == 0 else 'error'])
                result_queue.put({
                    'tool': tool,
                    'status': 'success',
                    'output': (result.stdout or '') + ('\n' + result.stderr if result.stderr else ''),
                    'filename': f'{tool}_{timestamp}.txt'
                })
        if thread is not None:
            thread.start()
            threads.append(thread)
    for thread in threads:
        thread.join()
    results = {}
    while not result_queue.empty():
        result = result_queue.get()
        results[result['tool']] = {
            'status': result['status'],
            'output': result['output']
        }
        # Ajout du nom de fichier si présent
        if 'filename' in result:
            results[result['tool']]['filename'] = result['filename']
        # Ajout du rapport HTML si présent (pour ZAP)
        if 'html_report' in result:
            results[result['tool']]['html_report'] = result['html_report']
    
    # Log de débogage pour voir ce qui est envoyé au frontend
    print(f'[DEBUG] Résultats finaux envoyés au frontend: {json.dumps(results, indent=2)}')
    
    # Génération automatique du PDF après chaque scan
    try:
        import sys
        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))
        from generate_pdf_report import generate_pentest_pdf
        generate_pentest_pdf()
    except Exception as e:
        print(f"Erreur lors de la génération du PDF : {e}")
    return jsonify({'results': results})

def run_tool_async(tool, target, result_queue, hydra_params=None, dirsearch_params=None, clamav_params=None, sqlmap_params=None, zap_params=None, scan_profile=None, custom_nmap_options=None):
    print(f"run_tool_async appelé pour tool={tool}")
    print(f"hydra_params = {hydra_params}")
    try:
        if tool == 'hydra' and hydra_params:
            import json  # Import local pour éviter les conflits
            print("Début branche HYDRA")
            username = hydra_params.get('username', '').strip()
            password = hydra_params.get('password', '').strip()
            service = hydra_params.get('service', '').strip()
            
            # Validation des paramètres requis
            if not username:
                result_queue.put({
                    'tool': tool,
                    'status': 'error',
                    'output': "Erreur : le nom d'utilisateur est requis pour Hydra. Utilisez l'option -l, -L ou -C."
                })
                return
            
            if not password:
                result_queue.put({
                    'tool': tool,
                    'status': 'error',
                    'output': "Erreur : le mot de passe ou fichier de mots de passe est requis pour Hydra."
                })
                return
            
            # Construction des arguments
            user_arg = f'-l {username}'
            if password.endswith('.txt') or password.endswith('.list') or password.endswith('.dic'):
                pass_arg = f'-P {password}'
            else:
                pass_arg = f'-p {password}'
            
            # Construction de la commande
            cmd_parts = ['hydra', user_arg, pass_arg]
            
            # Ajout automatique de -t 2 si SSH
            if service:
                if service.startswith('/') or service.isspace():
                    result_queue.put({
                        'tool': tool,
                        'status': 'error',
                        'output': "Erreur : le champ 'service' est mal formé. Utilisez un nom de service (ex: ssh, ftp) ou un schéma complet (ex: http-post-form://...)."
                    })
                    return
                
                if '://' in service:
                    service_url = service
                else:
                    service_url = f"{service}://{target}"
                
                # Ajout automatique de -t 2 si SSH
                if service.lower().startswith('ssh'):
                    cmd_parts.extend(['-t', '2'])
                
                cmd_parts.append(service_url)
            else:
                # Service par défaut SSH
                service_url = f"ssh://{target}"
                cmd_parts.extend(['-t', '2', service_url])
            
            cmd = ' '.join(cmd_parts)
            print(f"Commande Hydra exécutée : {cmd}")
            
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            result_file = os.path.join(REPORTS_DIR, f'{tool}_{timestamp}.txt')
            with open(result_file, 'w') as f:
                f.write(f"Commande: {cmd}\n")
                f.write(f"Sortie standard:\n{result.stdout}\n")
                f.write(f"Erreur standard:\n{result.stderr}\n")
            # Générer JSON et CSV
            base_name = f'{tool}_{timestamp}'
            json_file = os.path.join(REPORTS_DIR, f'{base_name}.json')
            csv_file = os.path.join(REPORTS_DIR, f'{base_name}.csv')
            json_obj = {
                'command': cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'status': 'success' if result.returncode == 0 else 'error'
            }
            with open(json_file, 'w') as f:
                json.dump(json_obj, f, indent=2)
            with open(csv_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['field', 'value'])
                writer.writerow(['command', cmd])
                writer.writerow(['stdout', result.stdout.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['stderr', result.stderr.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['status', 'success' if result.returncode == 0 else 'error'])
            result_queue.put({
                'tool': tool,
                'status': 'success',
                'output': (result.stdout or '') + ('\n' + result.stderr if result.stderr else ''),
                'filename': f'{tool}_{timestamp}.txt'
            })
        elif tool == 'dirsearch' and dirsearch_params:
            import json
            extra = dirsearch_params.get('extra', '').strip()
            base_cmd = TOOLS_CONFIG[tool]['cmd'].format(target=target)
            cmd = f"{base_cmd} {extra}" if extra else base_cmd
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            result_file = os.path.join(REPORTS_DIR, f'{tool}_{timestamp}.txt')
            with open(result_file, 'w') as f:
                f.write(f"Commande: {cmd}\n")
                f.write(f"Sortie standard:\n{result.stdout}\n")
                f.write(f"Erreur standard:\n{result.stderr}\n")
            # Générer JSON et CSV
            base_name = f'{tool}_{timestamp}'
            json_file = os.path.join(REPORTS_DIR, f'{base_name}.json')
            csv_file = os.path.join(REPORTS_DIR, f'{base_name}.csv')
            json_obj = {
                'command': cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'status': 'success' if result.returncode == 0 else 'error'
            }
            with open(json_file, 'w') as f:
                json.dump(json_obj, f, indent=2)
            with open(csv_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['field', 'value'])
                writer.writerow(['command', cmd])
                writer.writerow(['stdout', result.stdout.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['stderr', result.stderr.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['status', 'success' if result.returncode == 0 else 'error'])
            result_queue.put({
                'tool': tool,
                'status': 'success',
                'output': (result.stdout or '') + ('\n' + result.stderr if result.stderr else ''),
                'filename': f'{tool}_{timestamp}.txt'
            })
        elif tool == 'clamav' and clamav_params:
            extra = clamav_params.get('extra', '').strip()
            base_cmd = TOOLS_CONFIG[tool]['cmd'].format(target=target)
            cmd = f"{base_cmd} {extra}" if extra else base_cmd
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            result_file = os.path.join(REPORTS_DIR, f'{tool}_{timestamp}.txt')
            with open(result_file, 'w') as f:
                f.write(f"Commande: {cmd}\n")
                f.write(f"Sortie standard:\n{result.stdout}\n")
                f.write(f"Erreur standard:\n{result.stderr}\n")
            # Générer JSON et CSV
            base_name = f'{tool}_{timestamp}'
            json_file = os.path.join(REPORTS_DIR, f'{base_name}.json')
            csv_file = os.path.join(REPORTS_DIR, f'{base_name}.csv')
            json_obj = {
                'command': cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'status': 'success' if result.returncode == 0 else 'error'
            }
            with open(json_file, 'w') as f:
                json.dump(json_obj, f, indent=2)
            with open(csv_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['field', 'value'])
                writer.writerow(['command', cmd])
                writer.writerow(['stdout', result.stdout.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['stderr', result.stderr.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['status', 'success' if result.returncode == 0 else 'error'])
            result_queue.put({
                'tool': tool,
                'status': 'success',
                'output': (result.stdout or '') + ('\n' + result.stderr if result.stderr else ''),
                'filename': f'{tool}_{timestamp}.txt'
            })
        elif tool == 'sqlmap' and sqlmap_params:
            print(f"[DEBUG] Branche SQLMap atteinte avec params: {sqlmap_params}")
            import json  # Import local pour éviter les conflits
            url = sqlmap_params.get('url', '').strip()
            extra = sqlmap_params.get('extra', '').strip()
            base_cmd = TOOLS_CONFIG[tool]['cmd'].format(target=url)
            cmd = f"{base_cmd} {extra}" if extra else base_cmd
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            result_file = os.path.join(REPORTS_DIR, f'{tool}_{timestamp}.txt')
            with open(result_file, 'w') as f:
                f.write(f"Commande: {cmd}\n")
                f.write(f"Sortie standard:\n{result.stdout}\n")
                f.write(f"Erreur standard:\n{result.stderr}\n")
            # Générer JSON et CSV
            base_name = f'{tool}_{timestamp}'
            json_file = os.path.join(REPORTS_DIR, f'{base_name}.json')
            csv_file = os.path.join(REPORTS_DIR, f'{base_name}.csv')
            json_obj = {
                'command': cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'status': 'success' if result.returncode == 0 else 'error'
            }
            with open(json_file, 'w') as f:
                json.dump(json_obj, f, indent=2)
            with open(csv_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['field', 'value'])
                writer.writerow(['command', cmd])
                writer.writerow(['stdout', result.stdout.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['stderr', result.stderr.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['status', 'success' if result.returncode == 0 else 'error'])
            result_queue.put({
                'tool': tool,
                'status': 'success',
                'output': (result.stdout or '') + ('\n' + result.stderr if result.stderr else ''),
                'filename': f'{tool}_{timestamp}.txt'
            })
        elif tool == 'nmap':
            # --- Défense simulée Nmap pédagogique ---
            import json, time
            nmap_history_file = '/tmp/nmap_scan_history.json'
            now = time.time()
            # Charger l'historique
            if os.path.exists(nmap_history_file):
                with open(nmap_history_file, 'r') as f:
                    nmap_history = json.load(f)
            else:
                nmap_history = {}
            # Nettoyer l'historique (garder que les scans < 10 min)
            history = nmap_history.get(target, [])
            history = [t for t in history if now - t < 600]
            history.append(now)
            nmap_history[target] = history
            with open(nmap_history_file, 'w') as f:
                json.dump(nmap_history, f)
            # Détection -T5
            is_aggressive = '-T5' in TOOLS_CONFIG[tool]['cmd'] or '-T5' in (dirsearch_params.get('extra', '') if dirsearch_params else '')
            # Déclenchement défense
            if len(history) > 3 or is_aggressive:
                if not is_blacklisted(target):
                    add_to_blacklist(target)
                    raison = "fréquence (>3 scans/10min)" if len(history) > 3 else "option -T5 (agressif)"
                    log_defense_event(f"DEFENSE | IP {target} bloquée par défense simulée Nmap ({raison})")
                    result_queue.put({
                        'tool': 'defense',
                        'status': 'alert',
                        'output': f"Défense simulée : IP {target} bloquée ({raison})"
                    })
            extra = dirsearch_params.get('extra', '').strip() if dirsearch_params else ''
            base_cmd = TOOLS_CONFIG[tool]['cmd'].format(target=target)
            cmd = f"{base_cmd} {extra}" if extra else base_cmd
            print(f"[DEBUG NMAP] target={target}, scan_count={len(history)}, is_aggressive={is_aggressive}")
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            result_file = os.path.join(REPORTS_DIR, f'{tool}_{timestamp}.txt')
            with open(result_file, 'w') as f:
                f.write(f"Commande: {cmd}\n")
                f.write(f"Sortie standard:\n{result.stdout}\n")
                f.write(f"Erreur standard:\n{result.stderr}\n")
            # Générer les fichiers JSON et CSV pour tous les outils
            base_name = f'{tool}_{timestamp}'
            json_file = os.path.join(REPORTS_DIR, f'{base_name}.json')
            csv_file = os.path.join(REPORTS_DIR, f'{base_name}.csv')
            # Créer l'objet JSON
            json_obj = {
                'command': cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'status': 'success' if result.returncode == 0 else 'error'
            }
            # Écrire le fichier JSON
            with open(json_file, 'w') as f:
                json.dump(json_obj, f, indent=2)
            # Écrire le fichier CSV
            with open(csv_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['field', 'value'])
                writer.writerow(['command', cmd])
                writer.writerow(['stdout', result.stdout.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['stderr', result.stderr.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['status', 'success' if result.returncode == 0 else 'error'])
            result_queue.put({
                'tool': tool,
                'status': 'success',
                'output': (result.stdout or '') + ('\n' + result.stderr if result.stderr else ''),
                'filename': f'{tool}_{timestamp}.txt'
            })
        elif tool == 'zap' and zap_params:
            url = zap_params.get('url', '').strip()
            extra = zap_params.get('extra', '').strip()
            base_cmd = TOOLS_CONFIG[tool]['cmd'].format(url=url)
            cmd = f"{base_cmd} {extra}" if extra else base_cmd
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            result_file = os.path.join(REPORTS_DIR, f'{tool}_{timestamp}.txt')
            with open(result_file, 'w') as f:
                f.write(f"Commande: {cmd}\n")
                f.write(f"Sortie standard:\n{result.stdout}\n")
                f.write(f"Erreur standard:\n{result.stderr}\n")
            # Générer les fichiers JSON et CSV pour tous les outils
            base_name = f'{tool}_{timestamp}'
            json_file = os.path.join(REPORTS_DIR, f'{base_name}.json')
            csv_file = os.path.join(REPORTS_DIR, f'{base_name}.csv')
            # Créer l'objet JSON
            json_obj = {
                'command': cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'status': 'success' if result.returncode == 0 else 'error'
            }
            # Écrire le fichier JSON
            with open(json_file, 'w') as f:
                json.dump(json_obj, f, indent=2)
            # Écrire le fichier CSV
            with open(csv_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['field', 'value'])
                writer.writerow(['command', cmd])
                writer.writerow(['stdout', result.stdout.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['stderr', result.stderr.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['status', 'success' if result.returncode == 0 else 'error'])
            # Limiter la taille du champ output à 1000 caractères pour test
            output_limited = ((result.stdout or '') + ('\n' + result.stderr if result.stderr else ''))[:1000]
            result_queue.put({
                'tool': tool,
                'status': 'success',
                'output': output_limited,
                'filename': f'{tool}_{timestamp}.txt',
                'html_report': f'{tool}_{timestamp}.html'
            })
        else:
            cmd = TOOLS_CONFIG[tool]['cmd'].format(target=target)
            result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=300)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            result_file = os.path.join(REPORTS_DIR, f'{tool}_{timestamp}.txt')
            with open(result_file, 'w') as f:
                f.write(f"Commande: {cmd}\n")
                f.write(f"Sortie standard:\n{result.stdout}\n")
                f.write(f"Erreur standard:\n{result.stderr}\n")
            # Générer les fichiers JSON et CSV pour tous les outils
            base_name = f'{tool}_{timestamp}'
            json_file = os.path.join(REPORTS_DIR, f'{base_name}.json')
            csv_file = os.path.join(REPORTS_DIR, f'{base_name}.csv')
            # Créer l'objet JSON
            json_obj = {
                'command': cmd,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'status': 'success' if result.returncode == 0 else 'error'
            }
            # Écrire le fichier JSON
            with open(json_file, 'w') as f:
                json.dump(json_obj, f, indent=2)
            # Écrire le fichier CSV
            with open(csv_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(['field', 'value'])
                writer.writerow(['command', cmd])
                writer.writerow(['stdout', result.stdout.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['stderr', result.stderr.replace('"', '""').replace('\n', ' ')])
                writer.writerow(['status', 'success' if result.returncode == 0 else 'error'])
            result_queue.put({
                'tool': tool,
                'status': 'success',
                'output': (result.stdout or '') + ('\n' + result.stderr if result.stderr else ''),
                'filename': f'{tool}_{timestamp}.txt'
            })
    except Exception as e:
        print(f"Exception dans run_tool_async pour tool={tool} : {e}")
        result_queue.put({
            'tool': tool,
            'status': 'error',
            'output': str(e)
        })

@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    import sys
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts')))
    from generate_pdf_report import generate_pentest_pdf
    # Génère le PDF
    generate_pentest_pdf()
    # Chemin du PDF généré
    pdf_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../scripts/rapport_scans.pdf'))
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True, download_name='rapport_securite.pdf', mimetype='application/pdf')
    return jsonify({'error': 'PDF non généré'}), 500

@app.route('/report/<report_id>')
def view_report(report_id):
    report_path = os.path.join(REPORTS_DIR, report_id)
    if os.path.exists(report_path):
        with open(report_path, 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    return jsonify({'error': 'Report not found'}), 404

@app.route('/report/<report_id>/download')
def download_report(report_id):
    report_path = os.path.join(REPORTS_DIR, report_id)
    if os.path.exists(report_path):
        return send_file(report_path, as_attachment=True)
    return jsonify({'error': 'Report not found'}), 404

@app.route('/report/<report_id>', methods=['DELETE'])
def delete_report(report_id):
    report_path = os.path.join(REPORTS_DIR, report_id)
    if os.path.exists(report_path):
        os.remove(report_path)
        return jsonify({'status': 'success'})
    return jsonify({'error': 'Report not found'}), 404

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        note = request.form.get('note')
        avis = request.form.get('avis')
        user = current_user.username if current_user.is_authenticated else 'anonyme'
        feedback_line = f"{datetime.now().isoformat()} | {user} | Note: {note} | Avis: {avis}\n"
        feedback_path = os.path.join(os.path.dirname(__file__), '../feedbacks.txt')
        with open(feedback_path, 'a', encoding='utf-8') as f:
            f.write(feedback_line)
        flash('Merci pour votre retour !')
        return redirect(url_for('feedback'))
    return render_template('feedback.html')

@app.route('/admin/feedbacks')
@login_required
def admin_feedbacks():
    if current_user.role != 'admin':
        flash('Accès réservé à l\'admin', 'danger')
        return redirect(url_for('dashboard'))
    feedback_path = os.path.join(os.path.dirname(__file__), '../feedbacks.txt')
    feedbacks = []
    if os.path.exists(feedback_path):
        with open(feedback_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    date, user, note_part, avis_part = line.strip().split(' | ', 3)
                    note = note_part.replace('Note: ', '').strip()
                    avis = avis_part.replace('Avis: ', '').strip()
                    feedbacks.append({'date': date, 'user': user, 'note': int(note), 'avis': avis})
                except Exception:
                    continue
    # Tri par note décroissante par défaut
    sort_by = request.args.get('sort', 'note')
    order = request.args.get('order', 'desc')
    reverse = order == 'desc'
    if sort_by == 'note':
        feedbacks.sort(key=lambda x: x['note'], reverse=reverse)
    elif sort_by == 'date':
        feedbacks.sort(key=lambda x: x['date'], reverse=reverse)
    note_order = 'asc' if sort_by == 'note' and order == 'desc' else 'desc'
    date_order = 'asc' if sort_by == 'date' and order == 'desc' else 'desc'
    return render_template(
        'admin_feedbacks.html',
        feedbacks=feedbacks,
        sort_by=sort_by,
        order=order,
        note_order=note_order,
        date_order=date_order
    )

@app.route('/admin/feedbacks/download')
@login_required
def download_feedbacks():
    if current_user.role != 'admin':
        flash('Accès réservé à l\'admin', 'danger')
        return redirect(url_for('dashboard'))
    feedback_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../feedbacks.txt'))
    if not os.path.exists(feedback_path):
        flash('Aucun feedback à télécharger.', 'warning')
        return redirect(url_for('admin_feedbacks'))
    return send_from_directory(os.path.dirname(feedback_path), os.path.basename(feedback_path), as_attachment=True)

@app.route('/planification', methods=['GET', 'POST'])
@login_required
def planification():
    if request.method == 'POST':
        outil = request.form.get('outil')
        cible = request.form.get('cible')
        type_plan = request.form.get('type_plan')
        if type_plan == 'jour':
            heure = request.form.get('heure')
            date_heure = heure
        else:
            datetime_str = request.form.get('datetime')
            date_heure = datetime_str
        plan = ScanPlan(
            outil=outil,
            cible=cible,
            type_plan=type_plan,
            date_heure=date_heure,
            recurrence='daily' if type_plan == 'jour' else 'none',
            user_id=current_user.id,
            username=current_user.username
        )
        db.session.add(plan)
        db.session.commit()
        flash(f'Scan {outil} sur {cible} planifié.', 'success')
    # Affiche tous les scans planifiés (admin) ou ceux de l'utilisateur
    if current_user.role == 'admin':
        plans = ScanPlan.query.order_by(ScanPlan.id.desc()).all()
    else:
        plans = ScanPlan.query.filter_by(user_id=current_user.id).order_by(ScanPlan.id.desc()).all()
    return render_template('planification.html', plans=plans)

@app.route('/planification/delete/<int:plan_id>', methods=['POST'])
@login_required
def delete_plan(plan_id):
    plan = ScanPlan.query.get_or_404(plan_id)
    if current_user.role != 'admin' and plan.user_id != current_user.id:
        flash("Accès refusé.", 'danger')
        return redirect(url_for('planification'))
    db.session.delete(plan)
    db.session.commit()
    flash("Scan planifié supprimé.", 'success')
    return redirect(url_for('planification'))

@app.route('/planification/edit/<int:plan_id>', methods=['GET', 'POST'])
@login_required
def edit_plan(plan_id):
    plan = ScanPlan.query.get_or_404(plan_id)
    if current_user.role != 'admin' and plan.user_id != current_user.id:
        flash("Accès refusé.", 'danger')
        return redirect(url_for('planification'))
    if request.method == 'POST':
        plan.outil = request.form.get('outil')
        plan.cible = request.form.get('cible')
        plan.type_plan = request.form.get('type_plan')
        if plan.type_plan == 'jour':
            plan.date_heure = request.form.get('heure')
            plan.recurrence = 'daily'
        else:
            plan.date_heure = request.form.get('datetime')
            plan.recurrence = 'none'
        db.session.commit()
        flash("Scan planifié modifié.", 'success')
        return redirect(url_for('planification'))
    return render_template('planification.html', edit_plan=plan, plans=ScanPlan.query.order_by(ScanPlan.id.desc()).all())

@app.route('/projects')
@login_required
def projects():
    user_projects = Project.query.filter_by(owner_id=current_user.id).all()
    return render_template('projects.html', projects=user_projects)

@app.route('/projects/new', methods=['GET', 'POST'])
@login_required
def new_project():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form.get('description')
        client = request.form.get('client')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        status = request.form.get('status', 'En cours')
        project = Project(name=name, description=description, client=client, start_date=start_date, end_date=end_date, status=status, owner_id=current_user.id)
        db.session.add(project)
        db.session.commit()
        flash('Projet créé avec succès', 'success')
        return redirect(url_for('projects'))
    return render_template('project_form.html', project=None)

@app.route('/projects/edit/<int:project_id>', methods=['GET', 'POST'])
@login_required
def edit_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.owner_id != current_user.id and current_user.role != 'admin':
        flash('Accès refusé', 'danger')
        return redirect(url_for('projects'))
    if request.method == 'POST':
        project.name = request.form['name']
        project.description = request.form.get('description')
        project.client = request.form.get('client')
        project.start_date = request.form.get('start_date')
        project.end_date = request.form.get('end_date')
        project.status = request.form.get('status', 'En cours')
        db.session.commit()
        flash('Projet modifié', 'success')
        return redirect(url_for('projects'))
    return render_template('project_form.html', project=project)

@app.route('/projects/delete/<int:project_id>', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    if project.owner_id != current_user.id and current_user.role != 'admin':
        flash('Accès refusé', 'danger')
        return redirect(url_for('projects'))
    db.session.delete(project)
    db.session.commit()
    flash('Projet supprimé', 'success')
    return redirect(url_for('projects'))

@app.route('/rapport/assign/<report_id>', methods=['GET', 'POST'])
@login_required
def assign_report_project(report_id):
    # Vérifier que le rapport existe
    report_path = os.path.join(REPORTS_DIR, report_id)
    if not os.path.exists(report_path):
        flash('Rapport introuvable', 'danger')
        return redirect(url_for('rapport'))
    
    user_projects = Project.query.filter_by(owner_id=current_user.id).all()
    
    if request.method == 'POST':
        project_id = request.form.get('project_id')
        if project_id:
            # Supprimer l'association existante si elle existe
            existing_report = ProjectReport.query.filter_by(
                project_id=project_id, 
                report_filename=report_id
            ).first()
            if existing_report:
                db.session.delete(existing_report)
            
            # Déterminer le type de rapport basé sur le nom du fichier
            report_type = 'unknown'
            if 'nmap' in report_id.lower():
                report_type = 'nmap'
            elif 'hydra' in report_id.lower():
                report_type = 'hydra'
            elif 'dirsearch' in report_id.lower():
                report_type = 'dirsearch'
            elif 'clamav' in report_id.lower() or 'malware' in report_id.lower():
                report_type = 'malware'
            elif 'sqlmap' in report_id.lower():
                report_type = 'sqlmap'
            elif 'zap' in report_id.lower():
                report_type = 'zap'
            elif 'john' in report_id.lower():
                report_type = 'john'
            
            # Créer la nouvelle association
            project_report = ProjectReport(
                project_id=project_id,
                report_filename=report_id,
                report_type=report_type
            )
            db.session.add(project_report)
            db.session.commit()
            flash('Rapport associé au projet', 'success')
        return redirect(url_for('rapport'))
    
    # Récupérer le projet déjà associé si existant
    current_project = ProjectReport.query.filter_by(report_filename=report_id).first()
    current_project_id = current_project.project_id if current_project else None
    
    return render_template('assign_report_project.html', 
                         report_id=report_id, 
                         projects=user_projects, 
                         current_project_id=current_project_id)

@app.route('/projects/<int:project_id>/tasks', methods=['POST'])
@login_required
def add_task(project_id):
    project = Project.query.get_or_404(project_id)
    name = request.form.get('name')
    due_date = request.form.get('due_date')
    notes = request.form.get('notes')
    progress = int(request.form.get('progress', 0))
    if name:
        task = Task(project_id=project.id, name=name, due_date=due_date, notes=notes, progress=progress)
        db.session.add(task)
        db.session.commit()
        flash('Tâche ajoutée', 'success')
    return redirect(url_for('project_detail', project_id=project.id))

@app.route('/projects/<int:project_id>/tasks/<int:task_id>/edit', methods=['POST'])
@login_required
def edit_task(project_id, task_id):
    task = Task.query.get_or_404(task_id)
    if task.project_id != project_id:
        abort(404)
    task.name = request.form.get('name', task.name)
    task.due_date = request.form.get('due_date', task.due_date)
    task.notes = request.form.get('notes', task.notes)
    task.progress = int(request.form.get('progress', task.progress))
    db.session.commit()
    flash('Tâche modifiée', 'success')
    return redirect(url_for('project_detail', project_id=project_id))

@app.route('/projects/<int:project_id>/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(project_id, task_id):
    task = Task.query.get_or_404(task_id)
    if task.project_id != project_id:
        abort(404)
    db.session.delete(task)
    db.session.commit()
    flash('Tâche supprimée', 'success')
    return redirect(url_for('project_detail', project_id=project_id))

# Amélioration de la page de détail projet pour afficher les tâches et l'avancement global
def compute_project_progress(tasks):
    if not tasks:
        return 0
    return int(sum(t.progress for t in tasks) / len(tasks))

@app.route('/projects/<int:project_id>', methods=['GET', 'POST'])
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    if request.method == 'POST':
        if 'add_member' in request.form:
            username = request.form.get('username')
            role = request.form.get('role', 'contributeur')
            user = User.query.filter_by(username=username).first()
            if user:
                if not ProjectMember.query.filter_by(project_id=project.id, user_id=user.id).first():
                    db.session.add(ProjectMember(project_id=project.id, user_id=user.id, role=role))
                    db.session.commit()
                    flash('Membre ajouté', 'success')
                else:
                    flash('Utilisateur déjà membre', 'warning')
            else:
                flash('Utilisateur introuvable', 'danger')
        elif 'remove_member' in request.form:
            member_id = request.form.get('member_id')
            member = ProjectMember.query.get(member_id)
            if member and (project.owner_id == current_user.id or current_user.role == 'admin'):
                db.session.delete(member)
                db.session.commit()
                flash('Membre retiré', 'success')
        elif 'update_progress' in request.form:
            try:
                progress = int(request.form.get('progress', 0))
                project.progress = max(0, min(100, progress))
                db.session.commit()
                flash('Progression mise à jour', 'success')
            except Exception:
                flash('Valeur de progression invalide', 'danger')
        elif 'remove_report' in request.form:
            report_filename = request.form.get('report_filename')
            # Supprimer l'association depuis la base de données
            project_report = ProjectReport.query.filter_by(
                project_id=project.id, 
                report_filename=report_filename
            ).first()
            if project_report:
                db.session.delete(project_report)
                db.session.commit()
                flash('Rapport retiré du projet', 'success')
            else:
                flash('Association de rapport introuvable', 'danger')
        return redirect(url_for('project_detail', project_id=project.id))
    
    members = ProjectMember.query.filter_by(project_id=project.id).all()
    tasks = Task.query.filter_by(project_id=project.id).all()
    project_progress = compute_project_progress(tasks)
    
    # Récupérer les rapports associés au projet depuis la base de données
    project_reports = []
    project_report_entries = ProjectReport.query.filter_by(project_id=project.id).all()
    
    print(f"[DEBUG] Project {project.id}: {len(project_report_entries)} rapports trouvés dans la DB")
    
    for report_entry in project_report_entries:
        print(f"[DEBUG] Rapport DB: {report_entry.report_filename} ({report_entry.report_type})")
        # Vérifier que le fichier de rapport existe toujours
        report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports', report_entry.report_filename))
        if os.path.exists(report_path):
            print(f"[DEBUG] Fichier existe: {report_path}")
            # Extraire la date du nom de fichier
            date_str = 'Date inconnue'
            try:
                # Format attendu: tool_YYYYMMDD_HHMMSS.txt
                filename = report_entry.report_filename
                parts = filename.replace('.txt', '').split('_')
                if len(parts) >= 3:
                    date_part = parts[-2] + '_' + parts[-1]
                    if len(date_part) == 15:  # YYYYMMDD_HHMMSS
                        date_obj = datetime.strptime(date_part, '%Y%m%d_%H%M%S')
                        date_str = date_obj.strftime('%d/%m/%Y %H:%M')
            except:
                pass
            
            project_reports.append({
                'filename': report_entry.report_filename,
                'type': report_entry.report_type,
                'date': date_str
            })
            print(f"[DEBUG] Rapport ajouté: {report_entry.report_filename} ({report_entry.report_type}) - {date_str}")
        else:
            print(f"[DEBUG] Fichier manquant: {report_path}")
    
    print(f"[DEBUG] Total rapports pour template: {len(project_reports)}")
    
    # Trier les rapports par date (plus récents en premier)
    project_reports.sort(key=lambda x: x['date'], reverse=True)
    
    return render_template('project_detail.html', 
                         project=project, 
                         members=members, 
                         tasks=tasks, 
                         project_progress=project_progress,
                         project_reports=project_reports)

@app.route('/malware_native')
@login_required
def malware_native():
    return render_template('malware_native.html')

@app.route('/malware-history')
def malware_history():
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'results/malware'))
    if not os.path.exists(results_dir):
        return jsonify({"history": []})
    history = []
    for fname in os.listdir(results_dir):
        if fname.endswith('.json'):
            fpath = os.path.join(results_dir, fname)
            try:
                with open(fpath, 'r') as f:
                    data = json.load(f)
                    history.append(data)
            except Exception as e:
                continue
    # Tri par date décroissante
    history.sort(key=lambda x: x.get('date', ''), reverse=True)
    return jsonify({"history": history})

@app.route('/memory-analysis')
@login_required
def memory_analysis():
    # Liste des plugins Volatility3 les plus utiles
    plugins = {
        'windows': [
            {'value': 'windows.pslist', 'name': 'Process List', 'description': 'Liste des processus en cours d\'exécution'},
            {'value': 'windows.pstree', 'name': 'Process Tree', 'description': 'Arbre des processus'},
            {'value': 'windows.netscan', 'name': 'Network Connections', 'description': 'Connexions réseau actives'},
            {'value': 'windows.malfind', 'name': 'Malware Detection', 'description': 'Détection de code malveillant injecté'},
            {'value': 'windows.dlllist', 'name': 'DLL List', 'description': 'DLLs chargées par processus'},
            {'value': 'windows.handles', 'name': 'Handle List', 'description': 'Handles système ouverts'},
        ],
        'linux': [
            {'value': 'linux.pslist', 'name': 'Process List', 'description': 'Liste des processus Linux'},
            {'value': 'linux.pstree', 'name': 'Process Tree', 'description': 'Arbre des processus Linux'},
            {'value': 'linux.bash', 'name': 'Bash History', 'description': 'Historique des commandes bash'},
            {'value': 'linux.lsmod', 'name': 'Loaded Modules', 'description': 'Modules kernel chargés'},
            {'value': 'linux.netstat', 'name': 'Network Status', 'description': 'Connexions réseau actives'},
        ]
    }
    return render_template('memory_analysis.html', plugins=plugins)

@app.context_processor
def inject_lang():
    lang = session.get('lang', 'fr')
    return dict(lang=lang, t=TRANSLATIONS[lang])

def interpret_exit_code(tool, code):
    if tool == "ClamAV":
        if code == 0:
            return "Aucun virus trouvé", "success"
        elif code == 1:
            return "Virus détecté !", "infected"
        return "Erreur", "error"
    # Pour les autres outils
    if code == 0:
        return "Succès", "success"
    return "Erreur", "error"

@app.route('/api/analyze-malware', methods=['POST'])
def analyze_malware():
    results = []
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    file = request.files['file']
    samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../analysis/samples'))
    os.makedirs(samples_dir, exist_ok=True)
    temp_file_path = os.path.join(samples_dir, file.filename)
    file.save(temp_file_path)

    # Analyse avec Binwalk
    try:
        binwalk_output = subprocess.check_output(
            ["docker", "exec", "toolboxnewgenbackup-binwalk-1", "binwalk", f"/samples/{file.filename}"],
            stderr=subprocess.STDOUT
        ).decode()
        message, status = interpret_exit_code("Binwalk", 0)
    except subprocess.CalledProcessError as e:
        message, status = interpret_exit_code("Binwalk", e.returncode)
        binwalk_output = e.output.decode() if hasattr(e, "output") else str(e)
    results.append({
        "tool": "Binwalk",
        "status": status,
        "message": message,
        "details": binwalk_output,
        "timestamp": timestamp
    })

    # Analyse avec ClamAV
    try:
        clamav_output = subprocess.check_output(
            ["docker", "exec", "toolboxnewgenbackup-clamav-1", "clamscan", f"/scan/{file.filename}"],
            stderr=subprocess.STDOUT
        ).decode()
        message, status = interpret_exit_code("ClamAV", 0)
    except subprocess.CalledProcessError as e:
        message, status = interpret_exit_code("ClamAV", e.returncode)
        clamav_output = e.output.decode() if hasattr(e, "output") else str(e)
    results.append({
        "tool": "ClamAV",
        "status": status,
        "message": message,
        "details": clamav_output,
        "timestamp": timestamp
    })

    # --- Génération du rapport JSON structuré pour ClamAV ---
    lines = clamav_output.splitlines()
    infected = 0
    total = 0
    malware_types = {}
    for line in lines:
        m = re.match(r"^/scan/[^:]+: ([^ ]+) FOUND", line)
        if m:
            malware = m.group(1)
            malware_types[malware] = malware_types.get(malware, 0) + 1
    for line in lines:
        if line.startswith("Scanned files:"):
            total = int(line.split(":")[1].strip())
        if line.startswith("Infected files:"):
            infected = int(line.split(":")[1].strip())
    clean = total - infected if total >= infected else 0
    malware_json = {
        "date": datetime.now().isoformat(),
        "filename": file.filename,
        "total_files": total,
        "infected": infected,
        "clean": clean,
        "malware_types": malware_types
    }
    # Enregistrer le rapport JSON dans web/results/malware/
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'results/malware'))
    os.makedirs(results_dir, exist_ok=True)
    json_report_filename = f"malware_{timestamp}_{file.filename}.json"
    json_report_path = os.path.join(results_dir, json_report_filename)
    with open(json_report_path, "w") as json_file:
        json.dump(malware_json, json_file, indent=2)

    # Enregistrer le rapport texte dans web/results/
    results_dir_txt = os.path.abspath(os.path.join(os.path.dirname(__file__), 'results'))
    os.makedirs(results_dir_txt, exist_ok=True)
    report_filename = f"malware_{timestamp}_{file.filename}.txt"
    report_path = os.path.join(results_dir_txt, report_filename)
    with open(report_path, "w") as report_file:
        for result in results:
            report_file.write(f"Outil: {result['tool']}\n")
            report_file.write(f"Statut: {result['status']}\n")
            report_file.write(f"Message: {result['message']}\n")
            report_file.write(f"Détails:\n{result['details']}\n")
            report_file.write(f"Horodatage: {result['timestamp']}\n")
            report_file.write("-"*40 + "\n")

    return jsonify({"results": results, "malware_json": malware_json})

@app.route('/clean_hydra_tmp', methods=['POST'])
def clean_hydra_tmp():
    import glob
    import os
    files = glob.glob('/tmp/*_wordlist_hydra.txt')
    count = 0
    for f in files:
        try:
            os.remove(f)
            count += 1
        except Exception:
            pass
    return jsonify({'message': f'{count} fichier(s) supprimé(s) de /tmp.'})

# --- Module de défense simulée (défense blue team) ---
BLACKLIST_FILE = '/tmp/defense_blacklist.txt'
DEFENSE_LOG = '/tmp/defense_simulation.log'

def add_to_blacklist(ip):
    with open(BLACKLIST_FILE, 'a') as f:
        f.write(ip + '\n')

def is_blacklisted(ip):
    if not os.path.exists(BLACKLIST_FILE):
        return False
    with open(BLACKLIST_FILE, 'r') as f:
        return ip in [line.strip() for line in f]

def log_defense_event(event):
    with open(DEFENSE_LOG, 'a') as f:
        f.write(f"{datetime.now().isoformat()} | {event}\n")

@app.route('/defense-logs')
def defense_logs():
    logs = []
    if os.path.exists(DEFENSE_LOG):
        with open(DEFENSE_LOG, 'r') as f:
            logs = f.readlines()
    return jsonify({'logs': logs})

@app.route('/defense-blacklist')
def defense_blacklist():
    ips = []
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r') as f:
            ips = [line.strip() for line in f]
    return jsonify({'blacklist': ips})

@app.route('/remove-from-blacklist', methods=['POST'])
@login_required
def remove_from_blacklist():
    if current_user.role != 'admin':
        return jsonify({'error': 'Accès refusé'}), 403
    ip = request.json.get('ip')
    if not ip:
        return jsonify({'error': 'IP manquante'}), 400
    BLACKLIST_FILE = '/tmp/defense_blacklist.txt'
    if not os.path.exists(BLACKLIST_FILE):
        return jsonify({'error': 'Blacklist vide'}), 404
    with open(BLACKLIST_FILE, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]
    if ip not in lines:
        return jsonify({'error': 'IP non présente'}), 404
    lines = [line for line in lines if line != ip]
    with open(BLACKLIST_FILE, 'w') as f:
        for l in lines:
            f.write(l + '\n')
    return jsonify({'status': 'success', 'ip': ip})

@app.route('/admin/defense')
@login_required
def admin_defense():
    if current_user.role != 'admin':
        flash('Accès réservé à l\'admin', 'danger')
        return redirect(url_for('dashboard'))
    # Récupérer la blacklist
    BLACKLIST_FILE = '/tmp/defense_blacklist.txt'
    blacklist = []
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r') as f:
            blacklist = [line.strip() for line in f if line.strip()]
    # Récupérer les logs défensifs
    DEFENSE_LOG = '/tmp/defense_simulation.log'
    logs = []
    if os.path.exists(DEFENSE_LOG):
        with open(DEFENSE_LOG, 'r') as f:
            logs = [line.strip() for line in f if line.strip()]
    return render_template('admin_defense.html', blacklist=blacklist, logs=logs)

@app.route('/api/defense-blacklist')
@login_required
def api_defense_blacklist():
    if current_user.role != 'admin':
        return jsonify({'error': 'Accès refusé'}), 403
    BLACKLIST_FILE = '/tmp/defense_blacklist.txt'
    DEFENSE_LOG = '/tmp/defense_simulation.log'
    # Charger la blacklist
    blacklist = []
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, 'r') as f:
            blacklist = [line.strip() for line in f if line.strip()]
    # Charger les logs
    logs = []
    if os.path.exists(DEFENSE_LOG):
        with open(DEFENSE_LOG, 'r') as f:
            logs = [line.strip() for line in f if line.strip()]
    # Associer chaque IP à son dernier log (date + motif)
    ip_info = []
    for ip in blacklist:
        log_found = None
        for log in reversed(logs):
            if f"IP {ip} bloquée" in log:
                # Format attendu : date | DEFENSE | IP ... bloquée par ...
                parts = log.split('|')
                date = parts[0].strip() if len(parts) > 0 else ''
                motif = parts[2].strip() if len(parts) > 2 else log
                log_found = {'ip': ip, 'date': date, 'motif': motif}
                break
        if not log_found:
            log_found = {'ip': ip, 'date': '', 'motif': ''}
        ip_info.append(log_found)
    return jsonify({'blacklist': ip_info})

@app.route('/api/analyze-memory', methods=['POST'])
@login_required
def analyze_memory():
    file = request.files['file']
    plugin = request.form.get('plugin', 'windows.pslist')
    samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../analysis/samples'))
    os.makedirs(samples_dir, exist_ok=True)
    file_path = os.path.join(samples_dir, file.filename)
    file.save(file_path)

    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'results/memory'))
    os.makedirs(results_dir, exist_ok=True)
    base_filename = os.path.splitext(file.filename)[0]
    report_txt = f"{base_filename}.txt"
    report_json = f"{base_filename}.json"
    report_csv = f"{base_filename}.csv"
    report_path_txt = os.path.join(results_dir, report_txt)
    report_path_json = os.path.join(results_dir, report_json)
    report_path_csv = os.path.join(results_dir, report_csv)

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{samples_dir}:/data/samples:ro",
        "toolboxnewgenbackup-volatility3",
        "vol", "-f", f"/data/samples/{file.filename}", plugin
    ]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=300).decode(errors='replace')
        with open(report_path_txt, "w") as f:
            f.write(output)
        # Générer JSON et CSV même si succès
        report_obj = {"status": "ok", "output": output}
        with open(report_path_json, "w") as f:
            json.dump(report_obj, f, indent=2)
        with open(report_path_csv, "w") as f:
            f.write("status,output\n")
            f.write(f"ok,\"{output.replace('"', '""').replace(chr(10), ' ')}\"\n")
        # Copier les fichiers mémoire vers reports/ pour centralisation
        reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports'))
        os.makedirs(reports_dir, exist_ok=True)
        import shutil
        for ext in ['txt', 'json', 'csv']:
            src_file = os.path.join(results_dir, f"{base_filename}.{ext}")
            dst_file = os.path.join(reports_dir, f"{base_filename}.{ext}")
            if os.path.exists(src_file):
                shutil.copy2(src_file, dst_file)
                print(f'[DEBUG] Memory: Copié {src_file} vers {dst_file}')
        return jsonify({"status": "ok", "output": output, "filename": report_txt})
    except subprocess.CalledProcessError as e:
        error_output = e.output.decode(errors='replace')
        with open(report_path_txt, "w") as f:
            f.write(error_output)
        report_obj = {"status": "error", "output": error_output}
        with open(report_path_json, "w") as f:
            json.dump(report_obj, f, indent=2)
        with open(report_path_csv, "w") as f:
            f.write("status,output\n")
            f.write(f"error,\"{error_output.replace('"', '""').replace(chr(10), ' ')}\"\n")
        # Copier aussi les fichiers d'erreur vers reports/
        reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports'))
        os.makedirs(reports_dir, exist_ok=True)
        import shutil
        for ext in ['txt', 'json', 'csv']:
            src_file = os.path.join(results_dir, f"{base_filename}.{ext}")
            dst_file = os.path.join(reports_dir, f"{base_filename}.{ext}")
            if os.path.exists(src_file):
                shutil.copy2(src_file, dst_file)
                print(f'[DEBUG] Memory: Copié {src_file} vers {dst_file}')
        return jsonify({"status": "error", "output": error_output, "filename": report_txt})
    except Exception as e:
        error_output = str(e)
        with open(report_path_txt, "w") as f:
            f.write(error_output)
        report_obj = {"status": "error", "output": error_output}
        with open(report_path_json, "w") as f:
            json.dump(report_obj, f, indent=2)
        with open(report_path_csv, "w") as f:
            f.write("status,output\n")
            f.write(f"error,\"{error_output.replace('"', '""').replace(chr(10), ' ')}\"\n")
        # Copier aussi les fichiers d'erreur vers reports/
        reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports'))
        os.makedirs(reports_dir, exist_ok=True)
        import shutil
        for ext in ['txt', 'json', 'csv']:
            src_file = os.path.join(results_dir, f"{base_filename}.{ext}")
            dst_file = os.path.join(reports_dir, f"{base_filename}.{ext}")
            if os.path.exists(src_file):
                shutil.copy2(src_file, dst_file)
                print(f'[DEBUG] Memory: Copié {src_file} vers {dst_file}')
        return jsonify({"status": "error", "output": error_output, "filename": report_txt})

@app.route('/api/download-report')
@login_required
def download_report_api():
    report_type = request.args.get('type')  # ex: 'malware', 'memory', 'scan'
    filename = request.args.get('filename')
    fmt = request.args.get('format', 'txt').lower()  # txt, pdf, json, csv

    print(f'[DEBUG] Download request - type: {report_type}, filename: {filename}, format: {fmt}')

    if not report_type or not filename:
        print(f'[DEBUG] Missing parameters - type: {report_type}, filename: {filename}')
        return abort(400, 'Paramètres manquants')

    # Tous les rapports sont dans 'reports/'
    folder = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports'))
    print(f'[DEBUG] Reports folder: {folder}')

    base_name = os.path.splitext(filename)[0]
    txt_path = os.path.join(folder, base_name + '.txt')
    json_path = os.path.join(folder, base_name + '.json')
    csv_path = os.path.join(folder, base_name + '.csv')
    pdf_path = os.path.join(folder, base_name + '.pdf')
    html_path = os.path.join(folder, base_name + '.html')

    print(f'[DEBUG] File paths - TXT: {txt_path} (exists: {os.path.exists(txt_path)})')
    print(f'[DEBUG] File paths - JSON: {json_path} (exists: {os.path.exists(json_path)})')
    print(f'[DEBUG] File paths - CSV: {csv_path} (exists: {os.path.exists(csv_path)})')
    print(f'[DEBUG] File paths - HTML: {html_path} (exists: {os.path.exists(html_path)})')

    # TXT direct
    if fmt == 'txt' and os.path.exists(txt_path):
        print(f'[DEBUG] Serving TXT file: {txt_path}')
        return send_file(txt_path, as_attachment=True)
    # JSON direct
    if fmt == 'json' and os.path.exists(json_path):
        print(f'[DEBUG] Serving JSON file: {json_path}')
        return send_file(json_path, as_attachment=True)
    # CSV (génération à la volée si besoin)
    if fmt == 'csv':
        if os.path.exists(csv_path):
            print(f'[DEBUG] Serving CSV file: {csv_path}')
            return send_file(csv_path, as_attachment=True)
        # Générer à partir du JSON si possible
        if os.path.exists(json_path):
            print(f'[DEBUG] Generating CSV from JSON: {json_path}')
            with open(json_path, 'r') as f:
                data = json.load(f)
            output = io.StringIO()
            writer = csv.writer(output)
            # Simple : exporter les clés/valeurs à plat
            if isinstance(data, dict):
                writer.writerow(data.keys())
                writer.writerow(data.values())
            elif isinstance(data, list):
                writer.writerow(data[0].keys())
                for row in data:
                    writer.writerow(row.values())
            output.seek(0)
            return send_file(io.BytesIO(output.getvalue().encode()), as_attachment=True, download_name=base_name + '.csv', mimetype='text/csv')
        print(f'[DEBUG] CSV not available for: {filename}')
        return abort(404, 'CSV non disponible')
    # PDF (génération à la volée)
    if fmt == 'pdf':
        # Générer à partir du TXT si possible
        if os.path.exists(txt_path):
            print(f'[DEBUG] Generating PDF from TXT: {txt_path}')
            with open(txt_path, 'r') as f:
                content = f.read()
            
            class PDF(FPDF):
                def header(self):
                    # Logo et titre
                    self.set_font('Arial', 'B', 24)
                    self.set_text_color(0, 255, 200)  # Cyan néon
                    self.cell(0, 20, 'Toolbox Newgen', 0, 1, 'C')
                    self.set_font('Arial', 'B', 16)
                    self.set_text_color(255, 255, 255)  # Blanc
                    self.cell(0, 10, 'Rapport d\'Analyse Mémoire', 0, 1, 'C')
                    self.ln(10)

                def footer(self):
                    self.set_y(-15)
                    self.set_font('Arial', 'I', 8)
                    self.set_text_color(128, 128, 128)  # Gris
                    self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

            pdf = PDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.alias_nb_pages()
            pdf.add_page()

            # Fond sombre pour tout le document
            pdf.set_fill_color(40, 44, 52)  # Fond sombre
            pdf.rect(0, 0, 210, 297, 'F')  # A4 size

            # Information sur le fichier analysé
            pdf.set_fill_color(50, 54, 62)  # Fond légèrement plus clair
            pdf.set_text_color(255, 255, 255)  # Texte blanc
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 10, f"Fichier analysé : {base_name}", 1, 1, 'L', True)
            
            # Date et heure
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 8, f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M')}", 1, 1, 'L', True)
            pdf.ln(4)

            # Contenu principal avec mise en forme améliorée
            pdf.set_font('Arial', '', 11)
            
            # Séparation du contenu en sections
            sections = content.split('\n\n')
            for section in sections:
                if section.strip():
                    # Barre latérale cyan pour chaque section
                    pdf.set_fill_color(0, 255, 200)  # Cyan néon
                    pdf.cell(2, 10, '', 0, 0, 'L', True)
                    
                    # Contenu de la section
                    pdf.set_fill_color(50, 54, 62)  # Fond section
                    pdf.set_text_color(255, 255, 255)  # Texte blanc
                    pdf.multi_cell(0, 8, section.strip(), 1, 'L', True)
                    pdf.ln(2)

            pdf_buffer = BytesIO()
            pdf_bytes = pdf.output(dest='S').encode('latin1')
            pdf_buffer.write(pdf_bytes)
            pdf_buffer.seek(0)
            return send_file(pdf_buffer, as_attachment=True, download_name=base_name + '.pdf', mimetype='application/pdf')
        print(f'[DEBUG] PDF not available for: {filename}')
        return abort(404, 'PDF non disponible')
    # HTML ZAP
    if fmt == 'html' and os.path.exists(html_path):
        print(f'[DEBUG] Serving HTML file: {html_path}')
        return send_file(html_path, as_attachment=True, download_name=base_name + '.html', mimetype='text/html')
    
    print(f'[DEBUG] Format or file not available - type: {report_type}, filename: {filename}, format: {fmt}')
    return abort(404, 'Format ou fichier non disponible')

@app.route('/api/analyze-network', methods=['POST'])
@login_required
def analyze_network():
    file = request.files['file']
    fmt = request.form.get('format', 'txt').lower()  # txt, csv, json
    samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../analysis/network_samples'))
    os.makedirs(samples_dir, exist_ok=True)
    file_path = os.path.join(samples_dir, file.filename)
    file.save(file_path)

    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'results/network'))
    os.makedirs(results_dir, exist_ok=True)
    base_filename = os.path.splitext(file.filename)[0]
    report_txt = f"{base_filename}.txt"
    report_json = f"{base_filename}.json"
    report_csv = f"{base_filename}.csv"
    report_path_txt = os.path.join(results_dir, report_txt)
    report_path_json = os.path.join(results_dir, report_json)
    report_path_csv = os.path.join(results_dir, report_csv)

    # Commandes tshark selon le format
    docker_img = "toolboxnewgenbackup-tshark"
    filter_expr = request.form.get('filter', '').strip()
    if fmt == 'json':
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{samples_dir}:/data:ro",
            docker_img,
            "-r", f"/data/{file.filename}", "-T", "json"
        ]
        if filter_expr:
            cmd += ["-Y", filter_expr]
        out_path = report_path_json
    elif fmt == 'csv':
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{samples_dir}:/data:ro",
            docker_img,
            "-r", f"/data/{file.filename}", "-T", "fields",
            "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst", "-E", "header=y", "-E", "separator=,"
        ]
        out_path = report_path_csv
    else:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{samples_dir}:/data:ro",
            docker_img,
            "-r", f"/data/{file.filename}"
        ]
        out_path = report_path_txt
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=120).decode(errors='replace')
        with open(out_path, "w") as f:
            f.write(output)
        return jsonify({"status": "ok", "filename": os.path.basename(out_path), "format": fmt})
    except subprocess.CalledProcessError as e:
        error_output = e.output.decode(errors='replace')
        with open(out_path, "w") as f:
            f.write(error_output)
        return jsonify({"status": "error", "output": error_output}), 500

@app.route('/network-analysis')
@login_required
def network_analysis():
    return render_template('network_analysis.html')

@app.route('/api/system-stats')
@login_required
def api_system_stats():
    import psutil
    stats = {
        'cpu_percent': psutil.cpu_percent(interval=0.5),
        'ram_percent': psutil.virtual_memory().percent,
        'ram_used': psutil.virtual_memory().used,
        'ram_total': psutil.virtual_memory().total,
        'disk_percent': psutil.disk_usage('/').percent,
        'disk_used': psutil.disk_usage('/').used,
        'disk_total': psutil.disk_usage('/').total,
        'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
    }
    return jsonify(stats)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password=generate_password_hash('admin'), role='admin')
            db.session.add(admin)
            db.session.commit()
    print('Base users.db créée avec succès avec l\'utilisateur admin/admin.')
    app.run(debug=True, port=9797, ssl_context=('ssl/cert.pem', 'ssl/key.pem'))
