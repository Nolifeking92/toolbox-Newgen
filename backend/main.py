from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import os
from datetime import datetime
import tempfile
import shutil
from fastapi.responses import JSONResponse
import re
import json

app = FastAPI()

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production, spécifier les origines exactes
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def interpret_exit_code(tool, code):
    if code == 0:
        return "Analyse réussie : Aucun problème détecté.", "success"
    elif code == 1:
        return "Malware détecté !", "infected"
    elif code == 2:
        return "Fichier non supporté ou erreur d'accès (code 2)", "error"
    elif code == 3:
        return "Fichier non supporté ou erreur d'accès (code 3)", "error"
    else:
        return f"Erreur inconnue (code {code})", "error"

@app.post("/api/analyze-malware")
async def analyze_malware(file: UploadFile = File(...)):
    results = []
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Enregistrer le fichier dans analysis/samples pour qu'il soit accessible aux conteneurs
    samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../analysis/samples'))
    os.makedirs(samples_dir, exist_ok=True)
    temp_file_path = os.path.join(samples_dir, file.filename)
    with open(temp_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

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
    # Exemple de sortie ClamAV :
    # /scan/test.txt: Eicar-Test-Signature FOUND
    # ----------- SCAN SUMMARY -----------
    # Known viruses: 8576242
    # Engine version: 0.103.2
    # Scanned directories: 0
    # Scanned files: 1
    # Infected files: 1
    # Data scanned: 0.00 MB
    # Data read: 0.00 MB
    # Time: 6.123 sec (0 m 6 s)
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
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../web/results/malware'))
    os.makedirs(results_dir, exist_ok=True)
    json_report_filename = f"malware_{timestamp}_{file.filename}.json"
    json_report_path = os.path.join(results_dir, json_report_filename)
    with open(json_report_path, "w") as json_file:
        json.dump(malware_json, json_file, indent=2)

    # Enregistrer le rapport texte dans web/results/
    results_dir_txt = os.path.abspath(os.path.join(os.path.dirname(__file__), '../web/results'))
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

    return {"results": results, "malware_json": malware_json}

@app.post("/api/run-john")
async def run_john(file: UploadFile = File(...), wordlist: str = Form(None), format: str = Form(None), mode: str = Form(None)):
    samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../analysis/samples'))
    os.makedirs(samples_dir, exist_ok=True)
    hash_file_path = os.path.join(samples_dir, file.filename)
    with open(hash_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    # Construction de la commande John
    cmd = ["docker", "run", "--rm", "-v", f"{samples_dir}:/hashes", "john", f"/hashes/{file.filename}"]
    if wordlist:
        cmd.extend(["--wordlist", wordlist])
    if format:
        cmd.extend(["--format", format])
    if mode:
        if mode == "single":
            cmd.append("--single")
        elif mode == "wordlist":
            cmd.append("--wordlist")
        elif mode == "incremental":
            cmd.append("--incremental")
    try:
        john_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        status = "success"
    except subprocess.CalledProcessError as e:
        john_output = e.output.decode() if hasattr(e, "output") else str(e)
        status = "error"
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../web/results'))
    os.makedirs(results_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f"john_{timestamp}_{file.filename}.txt"
    report_path = os.path.join(results_dir, report_filename)
    with open(report_path, "w") as report_file:
        report_file.write(f"Outil: John the Ripper\n")
        report_file.write(f"Statut: {status}\n")
        report_file.write(f"Fichier: {file.filename}\n")
        report_file.write(f"Options: wordlist={wordlist}, format={format}, mode={mode}\n")
        report_file.write(f"Sortie:\n{john_output}\n")
        report_file.write(f"Horodatage: {timestamp}\n")
    return JSONResponse(content={"status": status, "output": john_output, "report": report_filename})

@app.post("/api/run-hydra")
async def run_hydra(username: str = Form(...), password: str = Form(None), service: str = Form(None), target: str = Form(...), passfile: UploadFile = File(None)):
    # Validation des paramètres requis
    if not username or not username.strip():
        return JSONResponse(content={"status": "error", "output": "Erreur : le nom d'utilisateur est requis pour Hydra."}, status_code=400)
    
    if not password and not passfile:
        return JSONResponse(content={"status": "error", "output": "Erreur : le mot de passe ou fichier de mots de passe est requis pour Hydra."}, status_code=400)
    
    samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../analysis/samples'))
    os.makedirs(samples_dir, exist_ok=True)
    
    # Construction de la commande Hydra
    cmd = ["docker", "run", "--rm", "-v", f"{samples_dir}:/data", "hydra"]
    
    # Ajout du nom d'utilisateur
    cmd.extend(["-l", username.strip()])
    
    # Gestion du mot de passe ou fichier
    if passfile:
        passfile_path = os.path.join(samples_dir, passfile.filename)
        with open(passfile_path, "wb") as buffer:
            shutil.copyfileobj(passfile.file, buffer)
        cmd.extend(["-P", f"/data/{passfile.filename}"])
    elif password and password.strip():
        cmd.extend(["-p", password.strip()])
    
    # Gestion du service et de la cible
    if service and service.strip():
        service = service.strip()
        if '://' in service:
            # Service avec URL complète
            cmd.append(service)
        else:
            # Service simple, construire l'URL
            service_url = f"{service}://{target}"
            cmd.append(service_url)
    else:
        # Service par défaut SSH
        service_url = f"ssh://{target}"
        cmd.append(service_url)
    
    try:
        hydra_output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
        status = "success"
    except subprocess.CalledProcessError as e:
        hydra_output = e.output.decode() if hasattr(e, "output") else str(e)
        status = "error"
    
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../web/results'))
    os.makedirs(results_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f"hydra_{timestamp}_{username}_{target}.txt"
    report_path = os.path.join(results_dir, report_filename)
    
    with open(report_path, "w") as report_file:
        report_file.write(f"Outil: Hydra\n")
        report_file.write(f"Statut: {status}\n")
        report_file.write(f"Utilisateur: {username}\n")
        report_file.write(f"Cible: {target}\n")
        report_file.write(f"Service: {service}\n")
        report_file.write(f"Commande: {' '.join(cmd)}\n")
        report_file.write(f"Sortie:\n{hydra_output}\n")
        report_file.write(f"Horodatage: {timestamp}\n")
    
    return JSONResponse(content={"status": status, "output": hydra_output, "report": report_filename})

@app.get("/api/malware-history")
def malware_history():
    results_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../web/results/malware'))
    if not os.path.exists(results_dir):
        return JSONResponse(content={"history": []})
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
    return JSONResponse(content={"history": history})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 