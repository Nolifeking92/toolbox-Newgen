#!/bin/bash
# monitor_toolbox.sh
# Vérifie que le port 9797 (Flask) répond

if nc -z localhost 9797; then
    echo "[OK] Toolbox Newgen est UP ($(date))"
else
    echo "[ALERTE] Toolbox Newgen ne répond pas ($(date))" | tee -a monitoring_alerts.log
    # Ici, tu peux ajouter une commande mail, Slack, etc.
fi 

cd web
source .venv/bin/activate
python app.py 