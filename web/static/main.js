console.log('JS version ZAP fix');
// Affichage dynamique des options Hydra
function setupHydraOptions() {
    const hydraCheckbox = document.querySelector('input[name="tools"][value="hydra"]');
    const hydraOptions = document.getElementById('hydra-options');
    const hydraPasslistSelect = document.getElementById('hydra-passlist-select');
    if (hydraCheckbox && hydraOptions && hydraPasslistSelect) {
        function toggleHydraOptions() {
            hydraOptions.style.display = hydraCheckbox.checked ? 'block' : 'none';
            hydraPasslistSelect.style.display = hydraCheckbox.checked ? 'block' : 'none';
        }
        hydraCheckbox.addEventListener('change', toggleHydraOptions);
        toggleHydraOptions();
    }
    // Remplir automatiquement le champ mot de passe/fichier si une passlist est choisie
    const passlistSelect = document.getElementById('hydra-passlist');
    const hydraPassword = document.getElementById('hydra-password');
    if (passlistSelect && hydraPassword) {
        passlistSelect.addEventListener('change', function() {
            if (this.value) {
                hydraPassword.value = this.value;
            }
        });
    }
}

// Affichage dynamique des options Dirsearch
function setupDirsearchOptions() {
    const dirsearchCheckbox = document.querySelector('input[name="tools"][value="dirsearch"]');
    const dirsearchOptions = document.getElementById('dirsearch-options');
    if (dirsearchCheckbox && dirsearchOptions) {
        function toggleDirsearchOptions() {
            dirsearchOptions.style.display = dirsearchCheckbox.checked ? 'block' : 'none';
        }
        dirsearchCheckbox.addEventListener('change', toggleDirsearchOptions);
        toggleDirsearchOptions();
    }
}

// Affichage dynamique des options ClamAV
function setupClamavOptions() {
    const clamavCheckbox = document.querySelector('input[name="tools"][value="clamav"]');
    const clamavOptions = document.getElementById('clamav-options');
    if (clamavCheckbox && clamavOptions) {
        function toggleClamavOptions() {
            clamavOptions.style.display = clamavCheckbox.checked ? 'block' : 'none';
        }
        clamavCheckbox.addEventListener('change', toggleClamavOptions);
        toggleClamavOptions();
    }
}

// Affichage dynamique des options SQLmap
function setupSqlmapOptions() {
    const sqlmapCheckbox = document.getElementById('sqlmap-checkbox');
    const sqlmapOptions = document.getElementById('sqlmap-options');
    if (sqlmapCheckbox && sqlmapOptions) {
        function toggleSqlmapOptions() {
            sqlmapOptions.style.display = sqlmapCheckbox.checked ? 'block' : 'none';
        }
        sqlmapCheckbox.addEventListener('change', toggleSqlmapOptions);
        toggleSqlmapOptions();
    }
}

// Affichage dynamique des options ZAP
function setupZapOptions() {
    const zapCheckbox = document.getElementById('zap-checkbox');
    const zapOptions = document.getElementById('zap-options');
    if (zapCheckbox && zapOptions) {
        function toggleZapOptions() {
            zapOptions.style.display = zapCheckbox.checked ? 'block' : 'none';
        }
        zapCheckbox.addEventListener('change', toggleZapOptions);
        toggleZapOptions();
    }
}

// Affichage dynamique des options John the Ripper
function setupJohnOptions() {
    const johnCheckbox = document.getElementById('john-checkbox');
    const johnOptions = document.getElementById('john-options');
    if (johnCheckbox && johnOptions) {
        function toggleJohnOptions() {
            johnOptions.style.display = johnCheckbox.checked ? 'block' : 'none';
        }
        johnCheckbox.addEventListener('change', toggleJohnOptions);
        toggleJohnOptions();
    }
}

// Affichage dynamique du profil de scan Nmap
const nmapCheckbox = document.querySelector('input[name="tools"][value="nmap"]');
const scanProfileDiv = document.getElementById('scan-profile-select');
if (nmapCheckbox && scanProfileDiv) {
    function toggleScanProfile() {
        scanProfileDiv.style.display = nmapCheckbox.checked ? 'block' : 'none';
    }
    nmapCheckbox.addEventListener('change', toggleScanProfile);
    toggleScanProfile();
}

// Fonction utilitaire pour détruire un graphique existant sur un canvas
function destroyChartIfExists(canvasId) {
    if (window._charts && window._charts[canvasId]) {
        window._charts[canvasId].destroy();
    }
}

// Initialisation du registre global si besoin
if (!window._charts) window._charts = {};

document.addEventListener('DOMContentLoaded', function() {
    setupHydraOptions();
    setupDirsearchOptions();
    setupClamavOptions();
    setupSqlmapOptions();
    setupZapOptions();
    setupJohnOptions();

    console.log('Initialisation des graphiques...');

    // --- Graphiques page Graphique ---
    // Graphique des vulnérabilités
    if (document.getElementById('vulnChart')) {
        console.log('Initialisation du graphique des vulnérabilités');
        const canvasId = 'vulnChart';
        destroyChartIfExists(canvasId);
        const chartConfigVuln = {
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: 'white' }
                }
            }
        };
        const vulnCtx = document.getElementById(canvasId).getContext('2d');
        console.log('Données des vulnérabilités:', window.vulnData);
        window._charts[canvasId] = new Chart(vulnCtx, {
            type: 'doughnut',
            data: {
                labels: ['Critiques', 'Élevées', 'Moyennes', 'Faibles'],
                datasets: [{
                    data: window.vulnData || [0,0,0,0],
                    backgroundColor: [
                        '#FF3366',
                        '#FF9933',
                        '#FFCC00',
                        '#00FFBB'
                    ]
                }]
            },
            options: chartConfigVuln
        });
    }

    // Graphique d'activité des scans
    if (document.getElementById('scanActivityChart')) {
        console.log('Initialisation du graphique d\'activité');
        console.log('Dates d\'activité:', window.activityDates);
        console.log('Nombre d\'activités:', window.activityCounts);
        const canvasId = 'scanActivityChart';
        destroyChartIfExists(canvasId);
        const chartConfigActivity = {
            plugins: {
                legend: { 
                    labels: { color: 'white' }
                },
                tooltip: {
                    callbacks: {
                        title: function(context) {
                            return 'Date: ' + context[0].label;
                        },
                        label: function(context) {
                            return 'Scans: ' + context.raw;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { 
                        color: 'rgba(0, 255, 187, 0.1)',
                        drawBorder: false
                    },
                    ticks: { 
                        color: 'white',
                        precision: 0,
                        stepSize: 1
                    }
                },
                x: {
                    grid: { 
                        color: 'rgba(0, 255, 187, 0.1)',
                        drawBorder: false,
                        display: true
                    },
                    ticks: { 
                        color: 'white',
                        maxRotation: 45,
                        minRotation: 45,
                        font: {
                            size: 11
                        },
                        padding: 8
                    }
                }
            },
            elements: {
                line: {
                    tension: 0.3,
                    borderWidth: 2
                },
                point: {
                    radius: 4,
                    hoverRadius: 6,
                    hitRadius: 30,
                    borderWidth: 2
                }
            },
            interaction: {
                intersect: false,
                mode: 'index'
            },
            maintainAspectRatio: false,
            layout: {
                padding: {
                    left: 10,
                    right: 25,
                    top: 20,
                    bottom: 15
                }
            }
        };
        const activityCtx = document.getElementById(canvasId).getContext('2d');
        window._charts[canvasId] = new Chart(activityCtx, {
            type: 'line',
            data: {
                labels: window.activityDates || [],
                datasets: [{
                    label: 'Nombre de scans',
                    data: window.activityCounts || [],
                    borderColor: '#00FFBB',
                    backgroundColor: 'rgba(0, 255, 187, 0.1)',
                    fill: true,
                    pointBackgroundColor: '#00FFBB',
                    pointBorderColor: '#FFFFFF',
                    pointHoverBackgroundColor: '#FFFFFF',
                    pointHoverBorderColor: '#00FFBB'
                }]
            },
            options: chartConfigActivity
        });
    }

    // Graphique des ports
    if (document.getElementById('portsChart')) {
        console.log('Initialisation du graphique des ports');
        console.log('Labels des ports:', window.portsLabels);
        console.log('Données des ports:', window.portsData);
        const canvasId = 'portsChart';
        destroyChartIfExists(canvasId);
        const chartConfigPorts = {
            plugins: {
                legend: { labels: { color: 'white' } }
            },
            scales: {
                y: {
                    grid: { color: 'rgba(0, 255, 187, 0.1)' },
                    ticks: { color: 'white' }
                },
                x: {
                    grid: { color: 'rgba(0, 255, 187, 0.1)' },
                    ticks: { color: 'white' }
                }
            }
        };
        const portsCtx = document.getElementById(canvasId).getContext('2d');
        window._charts[canvasId] = new Chart(portsCtx, {
            type: 'bar',
            data: {
                labels: window.portsLabels || [],
                datasets: [{
                    label: 'Ports',
                    data: window.portsData || [],
                    backgroundColor: '#FF0066',
                    borderColor: '#FF0066',
                    borderWidth: 1
                }]
            },
            options: chartConfigPorts
        });
    }

    // Graphique des services
    if (document.getElementById('servicesChart')) {
        console.log('Initialisation du graphique des services');
        console.log('Labels des services:', window.servicesLabels);
        console.log('Données des services:', window.servicesData);
        const canvasId = 'servicesChart';
        destroyChartIfExists(canvasId);
        const servicesCtx = document.getElementById(canvasId).getContext('2d');
        window._charts[canvasId] = new Chart(servicesCtx, {
            type: 'pie',
            data: {
                labels: window.servicesLabels || [],
                datasets: [{
                    data: window.servicesData || [],
                    backgroundColor: [
                        '#00FFBB',
                        '#FF0066',
                        '#FF3366',
                        '#FF9933',
                        '#FFCC00'
                    ]
                }]
            },
            options: {
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: 'white' }
                    }
                }
            }
        });
    }

    // --- Graphiques Malware ---
    if (document.getElementById('malwarePieChart')) {
        fetch('/malware-history')
          .then(r => r.json())
          .then(data => {
            const history = data.history || [];
            if (history.length === 0) return;
            // 1. Camembert infectés/sains (somme sur tout l'historique)
            let totalInfected = 0, totalClean = 0;
            let malwareTypesSum = {};
            history.forEach(h => {
              totalInfected += h.infected || 0;
              totalClean += h.clean || 0;
              if (h.malware_types) {
                for (const [type, count] of Object.entries(h.malware_types)) {
                  malwareTypesSum[type] = (malwareTypesSum[type] || 0) + count;
                }
              }
            });
            const pieCtx = document.getElementById('malwarePieChart').getContext('2d');
            window._charts['malwarePieChart'] && window._charts['malwarePieChart'].destroy();
            window._charts['malwarePieChart'] = new Chart(pieCtx, {
              type: 'doughnut',
              data: {
                labels: ['Infectés', 'Sains'],
                datasets: [{
                  data: [totalInfected, totalClean],
                  backgroundColor: ['#FF3366', '#00FFBB']
                }]
              },
              options: {
                plugins: { legend: { position: 'right', labels: { color: 'white' } } }
              }
            });
            // 2. Barres par type de malware (somme sur tout l'historique)
            const barCtx = document.getElementById('malwareBarChart').getContext('2d');
            const types = Object.keys(malwareTypesSum);
            const counts = Object.values(malwareTypesSum);
            window._charts['malwareBarChart'] && window._charts['malwareBarChart'].destroy();
            window._charts['malwareBarChart'] = new Chart(barCtx, {
              type: 'bar',
              data: {
                labels: types.length ? types : ['Aucun'],
                datasets: [{
                  label: 'Détections',
                  data: counts.length ? counts : [0],
                  backgroundColor: '#FF9933',
                  borderColor: '#FF9933',
                  borderWidth: 1
                }]
              },
              options: {
                plugins: { legend: { labels: { color: 'white' } } },
                scales: {
                  y: { ticks: { color: 'white' }, grid: { color: 'rgba(0, 255, 187, 0.1)' } },
                  x: { ticks: { color: 'white' }, grid: { color: 'rgba(0, 255, 187, 0.1)' } }
                }
              }
            });
            // 3. Timeline des infections
            const timelineCtx = document.getElementById('malwareTimelineChart').getContext('2d');
            const dates = history.map(h => {
              if (!h.date) return '';
              const d = new Date(h.date);
              // Format français : 2 chiffres pour jour/mois/année/heure/minute
              const pad = n => n.toString().padStart(2, '0');
              return `${pad(d.getDate())}/${pad(d.getMonth()+1)}/${d.getFullYear()} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
            });
            const infectedCounts = history.map(h => h.infected);
            window._charts['malwareTimelineChart'] && window._charts['malwareTimelineChart'].destroy();
            window._charts['malwareTimelineChart'] = new Chart(timelineCtx, {
              type: 'line',
              data: {
                labels: dates,
                datasets: [{
                  label: 'Fichiers infectés',
                  data: infectedCounts,
                  borderColor: '#FF3366',
                  backgroundColor: 'rgba(255,51,102,0.1)',
                  tension: 0.4
                }]
              },
              options: {
                plugins: { legend: { labels: { color: 'white' } } },
                scales: {
                  y: { ticks: { color: 'white' }, grid: { color: 'rgba(0, 255, 187, 0.1)' } },
                  x: { ticks: { color: 'white' }, grid: { color: 'rgba(0, 255, 187, 0.1)' } }
                }
              }
            });
          });
    }

    // --- Lancement des scans (Nmap, Dirsearch, ClamAV, etc.) ---
    const launchBtn = document.getElementById('launch-scans');
    if (launchBtn) {
        launchBtn.addEventListener('click', async function() {
            const selectedTools = Array.from(document.querySelectorAll('input[name="tools"]:checked')).map(cb => cb.value);
            const target = document.getElementById('target') ? document.getElementById('target').value : '';
            if (selectedTools.length === 0) {
                alert('Veuillez sélectionner au moins un outil');
                return;
            }
            if (!target && !selectedTools.includes('john')) {
                alert('Veuillez spécifier une cible');
                return;
            }
            // Réinitialiser et afficher les conteneurs de résultats
            selectedTools.forEach(tool => {
                const resultDiv = document.getElementById(`${tool}-result`);
                if (resultDiv) {
                    resultDiv.style.display = 'block';
                    resultDiv.querySelector('.result-content').textContent = 'Scan en cours...';
                }
            });
            // Récupérer les options Dirsearch et ClamAV si sélectionnés
            let dirsearchParams = {};
            if (selectedTools.includes('dirsearch')) {
                const extra = document.getElementById('dirsearch-extra');
                dirsearchParams = { extra: extra ? extra.value : '' };
            }
            let clamavParams = {};
            if (selectedTools.includes('clamav')) {
                const extra = document.getElementById('clamav-extra');
                clamavParams = { extra: extra ? extra.value : '' };
            }
            // Récupérer les options Hydra si sélectionné
            let hydraParams = {};
            let hydraPassfileObj = null;
            if (selectedTools.includes('hydra')) {
                const username = document.getElementById('hydra-username')?.value || '';
                const password = document.getElementById('hydra-password')?.value || '';
                const passfileInput = document.getElementById('hydra-passfile');
                hydraPassfileObj = passfileInput && passfileInput.files.length > 0 ? passfileInput.files[0] : null;
                const service = document.getElementById('hydra-service')?.value || '';
                const passlist = document.getElementById('hydra-passlist')?.value || '';
                hydraParams = { username, password, service, passlist };
            }
            // Récupérer les options ZAP si sélectionné
            let zapParams = {};
            if (selectedTools.includes('zap')) {
                const zapUrl = document.getElementById('zap-url')?.value || '';
                const zapExtra = document.getElementById('zap-extra')?.value || '';
                zapParams = { url: zapUrl, extra: zapExtra };
            }
            // Récupérer les options SQLMap si sélectionné
            let sqlmapParams = {};
            if (selectedTools.includes('sqlmap')) {
                const sqlmapUrl = document.getElementById('sqlmap-url')?.value || '';
                const sqlmapExtra = document.getElementById('sqlmap-extra')?.value || '';
                sqlmapParams = { url: sqlmapUrl, extra: sqlmapExtra };
            }
            // Récupérer le fichier de hash pour John the Ripper si sélectionné
            let johnHashfileObj = null;
            if (selectedTools.includes('john')) {
                const johnHashfileInput = document.getElementById('john-hashfile');
                johnHashfileObj = johnHashfileInput && johnHashfileInput.files.length > 0 ? johnHashfileInput.files[0] : null;
            }
            // Gestion du profil de scan Nmap
            const scanProfileSelect = document.getElementById('scan-profile');
            const customNmapOptions = document.getElementById('custom-nmap-options');
            if (scanProfileSelect && customNmapOptions) {
                scanProfileSelect.addEventListener('change', function() {
                    if (this.value === 'personnalise') {
                        customNmapOptions.style.display = 'block';
                    } else {
                        customNmapOptions.style.display = 'none';
                    }
                });
            }
            // Récupérer le profil de scan et options personnalisées UNIQUEMENT si Nmap est sélectionné
            let scanProfile = '';
            let customOptions = '';
            if (selectedTools.includes('nmap') && scanProfileSelect) {
                scanProfile = scanProfileSelect.value;
                customOptions = customNmapOptions && customNmapOptions.value ? customNmapOptions.value : '';
            }
            try {
                const formData = new FormData();
                formData.append('tools', JSON.stringify(selectedTools));
                formData.append('target', target);
                formData.append('dirsearch', JSON.stringify(dirsearchParams));
                formData.append('clamav', JSON.stringify(clamavParams));
                formData.append('hydra', JSON.stringify(hydraParams));
                formData.append('zap', JSON.stringify(zapParams));
                formData.append('sqlmap', JSON.stringify(sqlmapParams));
                formData.append('scan_profile', scanProfile);
                formData.append('custom_nmap_options', customOptions);
                if (hydraPassfileObj) {
                    formData.append('hydra_passfile', hydraPassfileObj);
                }
                if (johnHashfileObj) {
                    formData.append('john_hashfile', johnHashfileObj);
                }
                const response = await fetch('/run_tools', {
                    method: 'POST',
                    body: formData
                });
                // DEBUG: Afficher la réponse brute avant parsing
                const text = await response.text();
                console.log('Réponse brute:', text);
                let data;
                try {
                    data = JSON.parse(text);
                } catch (e) {
                    console.error('Erreur de parsing JSON:', e, text);
                    selectedTools.forEach(tool => {
                        const resultDiv = document.getElementById(`${tool}-result`);
                        if (resultDiv) {
                            resultDiv.querySelector('.result-content').textContent = 'Erreur lors du parsing JSON';
                        }
                    });
                    return;
                }
                Object.entries(data.results).forEach(([tool, result]) => {
                    const resultDiv = document.getElementById(`${tool}-result`);
                    if (resultDiv) {
                        let output = result.output || '';
                        let status = result.status || '';
                        let statusHtml = '';
                        // Cas spécial ClamAV infecté
                        if (tool === 'clamav' && status === 'infected') {
                            statusHtml = `<div style=\"color:#ff9933;font-weight:bold;\">⚠️ Fichier(s) infecté(s) détecté(s) !</div>`;
                        } else if (status === 'error' && tool !== 'zap') {
                            statusHtml = `<div style=\"color:#ff3366;font-weight:bold;\">Erreur lors du scan</div>`;
                        }
                        // Pour ZAP, n'afficher l'erreur que si output ET filename sont vides
                        const filename = result.filename || resultDiv.getAttribute('data-filename') || '';
                        const htmlReport = result.html_report || '';
                        
                        console.log(`[DEBUG] ${tool} - filename: ${filename}, htmlReport: ${htmlReport}`);
                        
                        if (tool === 'zap') {
                            if (!output && !filename) {
                                statusHtml = `<div style=\"color:#ff3366;font-weight:bold;\">Erreur lors du scan</div>`;
                            } else {
                                statusHtml = '';
                            }
                        }
                        // Mise en avant du mot de passe trouvé pour Hydra
                        if (tool === 'hydra' && output.includes('login:') && output.includes('password:')) {
                            output = output.replace(/(login:.*password:.*)/g, '<span style=\"color:#00ff88;font-weight:bold;font-size:1.1em;\">$1</span>');
                        }
                        // Affichage de la commande exécutée si présente
                        let cmdMatch = output.match(/Commande: (.*)/);
                        let cmdHtml = '';
                        if (cmdMatch) {
                            cmdHtml = `<div style='color:#00bfff;font-family:monospace;font-size:1em;margin-bottom:6px;'><b>Commande exécutée :</b> ${cmdMatch[1]}</div>`;
                        }
                        // Ajout des boutons de téléchargement pour tous les outils
                        let downloadBtns = '';
                        if (filename) {
                            // Stocker le nom de fichier dans l'attribut data-filename pour les futurs accès
                            resultDiv.setAttribute('data-filename', filename);
                            downloadBtns = `
                            <div class=\"download-btn-group\" style=\"margin:12px 0;display:flex;gap:10px;\">
                                <button class=\"neon-btn neon-btn-outline btn-txt\" onclick=\"window.open('/api/download-report?type=${tool}&filename=${encodeURIComponent(filename)}&format=txt','_blank')\">TXT</button>
                                <button class=\"neon-btn neon-btn-outline btn-pdf\" onclick=\"window.open('/api/download-report?type=${tool}&filename=${encodeURIComponent(filename)}&format=pdf','_blank')\">PDF</button>
                                <button class=\"neon-btn neon-btn-outline btn-json\" onclick=\"window.open('/api/download-report?type=${tool}&filename=${encodeURIComponent(filename)}&format=json','_blank')\">JSON</button>
                                <button class=\"neon-btn neon-btn-outline btn-csv\" onclick=\"window.open('/api/download-report?type=${tool}&filename=${encodeURIComponent(filename)}&format=csv','_blank')\">CSV</button>
                                ${tool === 'zap' && htmlReport ? `<button class=\"neon-btn neon-btn-outline btn-html\" onclick=\"window.open('/api/download-report?type=zap&filename=${encodeURIComponent(htmlReport)}&format=html','_blank')\">HTML</button>` : ''}
                            </div>`;
                            console.log(`[DEBUG] ${tool} - Boutons de téléchargement générés avec filename: ${filename}`);
                        } else {
                            console.log(`[DEBUG] ${tool} - Aucun nom de fichier disponible, pas de boutons de téléchargement`);
                        }
                        if (tool === 'zap') {
                            // N'affiche pas output, juste les boutons et un message
                            resultDiv.querySelector('.result-content').innerHTML = downloadBtns + "<div style='margin-top:10px;'>Scan terminé. Téléchargez le rapport ci-dessous.</div>";
                        } else {
                            resultDiv.querySelector('.result-content').innerHTML = downloadBtns + statusHtml + cmdHtml + (output ? output.replace(/\n/g, '<br>') : '');
                        }
                    }
                });
                // Après avoir affiché les résultats des outils
                fetch('/defense-logs')
                  .then(r => r.json())
                  .then(data => {
                    const logsDiv = document.getElementById('defense-logs');
                    if (logsDiv) {
                      logsDiv.innerHTML = '<b>Logs défensifs :</b><br>' + (data.logs || []).map(l => `<span style='color:#ff3366;'>${l}</span>`).join('<br>');
                    }
                  });
                fetch('/defense-blacklist')
                  .then(r => r.json())
                  .then(data => {
                    const blDiv = document.getElementById('defense-blacklist');
                    if (blDiv) {
                      blDiv.innerHTML = '<b>IP bloquées (simu) :</b> ' + (data.blacklist || []).join(', ');
                    }
                  });
            } catch (error) {
                console.error('Erreur:', error);
                selectedTools.forEach(tool => {
                    const resultDiv = document.getElementById(`${tool}-result`);
                    if (resultDiv) {
                        resultDiv.querySelector('.result-content').textContent = 'Erreur lors du scan';
                    }
                });
            }
        });
    }

    const cleanBtn = document.getElementById('clean-hydra-tmp');
    if (cleanBtn) {
        cleanBtn.addEventListener('click', async function() {
            const res = await fetch('/clean_hydra_tmp', { method: 'POST' });
            const data = await res.json();
            const resultDiv = document.getElementById('clean-hydra-tmp-result');
            if (resultDiv) {
                resultDiv.textContent = data.message || 'Nettoyage effectué.';
            }
        });
    }

    // Masquage dynamique du champ Cible si seul John the Ripper est sélectionné
    function toggleTargetInput() {
        const selectedTools = Array.from(document.querySelectorAll('input[name="tools"]:checked')).map(cb => cb.value);
        const targetInputDiv = document.querySelector('.target-input');
        if (targetInputDiv) {
            if (selectedTools.length === 1 && selectedTools[0] === 'john') {
                targetInputDiv.style.display = 'none';
            } else {
                targetInputDiv.style.display = 'block';
            }
        }
    }
    document.querySelectorAll('input[name="tools"]').forEach(cb => {
        cb.addEventListener('change', toggleTargetInput);
    });
    toggleTargetInput();
}); 