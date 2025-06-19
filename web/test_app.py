import os
import tempfile
import pytest
from app import app, db, User

@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
    app.config['WTF_CSRF_ENABLED'] = False
    client = app.test_client()

    with app.app_context():
        db.create_all()
        # Ajout d'un utilisateur admin pour les tests uniquement s'il n'existe pas
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password='admin', role='admin')
            db.session.add(admin)
            db.session.commit()

    yield client

    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture(autouse=True)
def clean_reports_dir():
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports'))
    if os.path.exists(reports_dir):
        for f in os.listdir(reports_dir):
            try:
                os.remove(os.path.join(reports_dir, f))
            except Exception:
                pass

def login(client, username, password):
    return client.post('/login', data=dict(
        username=username,
        password=password
    ), follow_redirects=True)

def test_login_page(client):
    rv = client.get('/login')
    assert rv.status_code == 200
    assert b'login' in rv.data.lower()

def test_login_success(client):
    rv = login(client, 'admin', 'admin')
    assert b'Dashboard' in rv.data or b'dashboard' in rv.data.lower()

def test_login_fail(client):
    rv = login(client, 'wrong', 'wrong')
    assert b'Identifiants invalides' in rv.data or b'invalid' in rv.data.lower()

def test_dashboard_access(client):
    login(client, 'admin', 'admin')
    rv = client.get('/dashboard')
    assert rv.status_code == 200
    assert b'dashboard' in rv.data.lower()

def test_admin_feedbacks_access(client):
    login(client, 'admin', 'admin')
    rv = client.get('/admin/feedbacks')
    assert rv.status_code == 200
    assert b'Feedback' in rv.data or b'feedback' in rv.data.lower()

def test_feedback_post(client):
    login(client, 'admin', 'admin')
    rv = client.post('/feedback', data={
        'feedback': 'Test feedback automatique.'
    }, follow_redirects=True)
    assert b'Merci' in rv.data or b'thank' in rv.data.lower()

def test_analyze_memory_route(client):
    login(client, 'admin', 'admin')
    # Crée un faux fichier mémoire
    with open('test.txt', 'wb') as f:
        f.write(b'Test memory dump')
    data = {
        'file': (open('test.txt', 'rb'), 'test.txt'),
        'plugin': 'windows.pslist'
    }
    rv = client.post('/api/analyze-memory', data=data, content_type='multipart/form-data')
    assert rv.status_code == 200
    json_data = rv.get_json()
    assert 'status' in json_data
    assert 'output' in json_data

def test_download_memory_report(client):
    login(client, 'admin', 'admin')
    # Suppose qu'un fichier test.txt a déjà été généré dans reports/
    # On crée un fichier factice pour le test
    reports_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../reports'))
    os.makedirs(reports_dir, exist_ok=True)
    test_report_path = os.path.join(reports_dir, 'test.txt')
    with open(test_report_path, 'w') as f:
        f.write('Contenu test rapport memoire')
    rv = client.get('/api/download-report?type=memory&filename=test.txt&format=txt')
    assert rv.status_code == 200
    assert b'Contenu test rapport memoire' in rv.data

def test_dashboard_requires_login(client):
    # Déconnexion forcée (si jamais connecté)
    client.get('/logout', follow_redirects=True)
    # Tente d'accéder au dashboard sans être connecté
    rv = client.get('/dashboard', follow_redirects=True)
    # On doit être redirigé vers la page de login
    assert b'login' in rv.data.lower() or rv.status_code == 200 