import sys
import os
import shutil
import subprocess
import datetime
import threading
import time
import queue
import re
from flask import Flask, request, jsonify, render_template_string, send_file
from concurrent.futures import ThreadPoolExecutor
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# --- CONFIGURATION ---
app = Flask(__name__)
REPORT_DIR = 'reports'
MAX_WORKERS = 15  # Increased to 15
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_WORKERS)
JOBS = {}
JOB_LOCK = threading.Lock()
SYSTEM_LOGS = []

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

if not shutil.which("nmap"):
    print("CRITICAL: Nmap missing. Run: sudo apt install nmap")
    sys.exit(1)

# --- UTILS ---
def log_system(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    with JOB_LOCK:
        SYSTEM_LOGS.insert(0, f"[{ts}] {msg}")
        if len(SYSTEM_LOGS) > 50: SYSTEM_LOGS.pop()

def clean_output(text):
    lines = text.split('\n')
    cleaned = []
    for line in lines:
        if any(x in line for x in ["defeat-rst-ratelimit", "Warning: OSScan", "Nmap done:", "scanned in", "Raw packets"]):
            continue
        cleaned.append(line)
    return '\n'.join(cleaned).strip()

# --- PDF ENGINE ---
class CyberPDF(FPDF):
    def header(self):
        self.set_fill_color(10, 10, 20)
        self.rect(0, 0, 210, 297, 'F')
        self.set_font('Courier', 'B', 14)
        self.set_text_color(0, 255, 255)
        self.set_xy(10, 10)
        self.cell(0, 10, 'APEX VANGUARD | CYBER INTELLIGENCE', border=0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_draw_color(0, 255, 255)
        self.line(10, 22, 200, 22)
        self.ln(15)

    def footer(self):
        self.set_y(-15)
        self.set_font('Courier', 'I', 8)
        self.set_text_color(100)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

def create_pdf(filename, title, target_list, is_critical=False):
    pdf = CyberPDF()
    
    # Cover
    if len(target_list) > 1:
        pdf.add_page()
        pdf.set_y(80)
        pdf.set_font("Courier", 'B', 24)
        pdf.set_text_color(255, 50, 50) if is_critical else pdf.set_text_color(0, 255, 0)
        pdf.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        pdf.set_font("Courier", '', 12)
        pdf.set_text_color(255, 255, 255)
        pdf.ln(10)
        pdf.cell(0, 8, f"GENERATED: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        pdf.cell(0, 8, f"TARGETS:   {len(target_list)}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')

    # Body
    for t in target_list:
        pdf.add_page()
        pdf.set_fill_color(20, 25, 35)
        pdf.rect(0, 30, 210, 20, 'F')
        pdf.set_xy(10, 35)
        
        pdf.set_font("Courier", 'B', 16)
        if "VULNERABLE" in t['output']:
            pdf.set_text_color(255, 50, 50)
            status = f"TARGET: {t['ip']} [THREAT]"
        else:
            pdf.set_text_color(0, 255, 0)
            status = f"TARGET: {t['ip']} [SECURE]"
            
        pdf.cell(0, 10, status, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        pdf.ln(10)
        pdf.set_font("Courier", '', 8)
        pdf.set_text_color(150)
        pdf.cell(0, 5, f"CMD: {t['cmd']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(5)
        
        pdf.set_font("Courier", '', 9)
        lines = clean_output(t['output']).encode('latin-1', 'replace').decode('latin-1').split('\n')
        
        for line in lines:
            if any(x in line for x in ['VULNERABLE:', 'CVE-', 'ERROR:']): pdf.set_text_color(255, 50, 50)
            elif "open" in line and "/tcp" in line: pdf.set_text_color(0, 255, 0)
            elif "PORT" in line and "STATE" in line: pdf.set_text_color(0, 255, 255)
            else: pdf.set_text_color(200)
            pdf.cell(0, 4, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    path = os.path.join(REPORT_DIR, filename)
    pdf.output(path)
    return path

# --- SCANNER ---
def run_scan(ip, scope, aggressive, vuln_mode, debug_mode):
    with JOB_LOCK:
        JOBS[ip]['status'] = 'ACTIVE'
        JOBS[ip]['start_time'] = time.time()
    
    log_system(f"Started scan on {ip}")

    cmd = ["nmap", "-n", "-Pn", "--open"]
    if debug_mode: cmd.append("-d")
    
    if scope == 'full':
        cmd.append("-p-")
        timeout = 3600 if vuln_mode else 1200
    else:
        cmd.extend(["--top-ports", "1000"])
        timeout = 1800 if vuln_mode else 600

    if vuln_mode:
        cmd.extend(["--script", "vuln", "--script-args=unsafe=1"])
        if scope != 'full': cmd.extend(["--min-rate", "500"])
    else:
        cmd.extend(["--min-rate", "2000"])

    if aggressive: cmd.append("-A")
    else: cmd.append("-sV")
    
    cmd.append(ip)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw_out = proc.stdout
        if debug_mode and proc.stderr: raw_out += "\n[DEBUG]\n" + proc.stderr
        
        output = clean_output(raw_out)
        status = 'COMPLETED'
        if proc.returncode != 0 and not output:
            output = proc.stderr or "Error"
            status = 'FAILED'
            
    except subprocess.TimeoutExpired:
        output = "TIMEOUT"
        status = 'FAILED'
    except Exception as e:
        output = str(e)
        status = 'FAILED'

    with JOB_LOCK:
        JOBS[ip]['status'] = status
        JOBS[ip]['output'] = output
        JOBS[ip]['cmd'] = " ".join(cmd)
        
        try:
            fname = f"{ip.replace('.','_')}.pdf"
            path = create_pdf(fname, f"REPORT: {ip}", [JOBS[ip]])
            JOBS[ip]['pdf_path'] = fname
        except: pass
    
    log_system(f"Finished {ip} [{status}]")

# --- ROUTES ---
@app.route('/')
def home(): return render_template_string(HTML_UI)

@app.route('/api/launch', methods=['POST'])
def launch():
    data = request.json
    targets = data.get('targets', [])
    if not targets: return jsonify({"error": "No targets"}), 400

    count = 0
    for ip in targets:
        ip = ip.strip()
        if ip and ip not in JOBS:
            JOBS[ip] = {'ip': ip, 'status': 'QUEUED', 'output': '', 'cmd': '', 'pdf_path': ''}
            EXECUTOR.submit(run_scan, ip, data.get('scope'), data.get('aggressive'), data.get('vuln'), data.get('debug'))
            count += 1
    
    log_system(f"Batch launched: {count} targets")
    return jsonify({"message": f"Queued {count}"})

@app.route('/api/stop', methods=['POST'])
def stop():
    JOBS.clear() 
    log_system("EMERGENCY STOP TRIGGERED")
    return jsonify({"message": "Stopped"})

@app.route('/api/status')
def status():
    with JOB_LOCK: return jsonify({'jobs': list(JOBS.values()), 'logs': SYSTEM_LOGS})

@app.route('/api/download_master')
def download_master():
    mode = request.args.get('mode', 'all')
    with JOB_LOCK:
        finished = [j for j in JOBS.values() if j['status'] in ['COMPLETED', 'FAILED']]
    
    if not finished: return "No data", 400

    if mode == 'vuln':
        filtered = [j for j in finished if "VULNERABLE" in j['output'] or "CVE-" in j['output']]
        fname = f"CRITICAL_THREAT_INTEL_{int(time.time())}.pdf"
        title = "CRITICAL THREAT DOSSIER"
        is_crit = True
    else:
        filtered = finished
        fname = f"FULL_NETWORK_DOSSIER_{int(time.time())}.pdf"
        title = "FULL NETWORK DOSSIER"
        is_crit = False

    path = create_pdf(fname, title, filtered, is_crit)
    return send_file(path, as_attachment=True)

@app.route('/api/download/<path:filename>')
def download_single(filename):
    return send_file(os.path.join(REPORT_DIR, filename), as_attachment=True)

@app.route('/api/clear', methods=['POST'])
def clear():
    with JOB_LOCK:
        to_del = [ip for ip, j in JOBS.items() if j['status'] in ['COMPLETED', 'FAILED']]
        for ip in to_del: del JOBS[ip]
    return jsonify({"status": "cleared"})

# --- UI (CYBER-OPS V10) ---
HTML_UI = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>APEX VANGUARD V10</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@500;600;700&display=swap');
        
        body { background-color: #030507; color: #94a3b8; font-family: 'Rajdhani', sans-serif; overflow: hidden; }
        .mono { font-family: 'Share Tech Mono', monospace; }
        
        /* Glass / Cyber Styling */
        .glass { background: rgba(10, 15, 25, 0.9); border: 1px solid rgba(0, 255, 255, 0.15); backdrop-filter: blur(8px); }
        .panel { border: 1px solid #1e293b; background: #0b1120; }
        
        /* Background Matrix Effect (CSS Only approximation) */
        .matrix-bg {
            position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1;
            background: linear-gradient(180deg, rgba(0, 255, 255, 0) 0%, rgba(0, 255, 255, 0.05) 50%, rgba(0, 255, 255, 0) 100%);
            background-size: 100% 3px; animation: scanline 8s linear infinite;
        }
        @keyframes scanline { 0% { background-position: 0 -100vh; } 100% { background-position: 0 100vh; } }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 5px; }
        ::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }
        
        /* Status Glows */
        @keyframes pulse-blue { 0% { box-shadow: 0 0 0 0 rgba(6, 182, 212, 0.4); } 70% { box-shadow: 0 0 0 10px rgba(6, 182, 212, 0); } 100% { box-shadow: 0 0 0 0 rgba(6, 182, 212, 0); } }
        .scanning-active { border: 1px solid #06b6d4; animation: pulse-blue 2s infinite; }
        
        .vuln-card { border-left: 4px solid #ef4444; background: linear-gradient(90deg, rgba(239,68,68,0.1) 0%, transparent 100%); }
        .clean-card { border-left: 4px solid #10b981; }
        
        .hl-vuln { color: #ff5555; text-shadow: 0 0 5px #ff0000; font-weight: bold; }
        .hl-port { color: #34d399; font-weight: bold; }
        .hl-head { color: #22d3ee; border-bottom: 1px solid #1e293b; display: block; margin-top: 5px; }
        
        .tab-btn { border-bottom: 2px solid transparent; opacity: 0.6; transition: all 0.2s; }
        .tab-btn.active { border-color: #22d3ee; opacity: 1; color: #22d3ee; text-shadow: 0 0 8px rgba(34, 211, 238, 0.5); }
    </style>
</head>
<body class="flex h-screen matrix-bg">

    <aside class="w-80 bg-black/90 border-r border-slate-800 flex flex-col z-20 shadow-2xl">
        <div class="h-16 flex items-center px-6 border-b border-slate-800 bg-slate-900/40">
            <i class="fas fa-network-wired text-cyan-500 text-xl mr-3"></i>
            <div>
                <h1 class="text-xl font-bold text-white tracking-widest">APEX <span class="text-cyan-500">V10</span></h1>
                <div class="text-[9px] text-slate-500 tracking-[0.3em] mono">CYBER WARFARE SUITE</div>
            </div>
        </div>

        <div class="p-5 flex-1 overflow-y-auto space-y-6">
            <div class="panel p-3 rounded">
                <label class="text-[10px] font-bold text-cyan-500 uppercase tracking-wider mb-2 block">Mission Targets</label>
                <textarea id="ipInput" placeholder="192.168.1.1..." class="w-full bg-black/50 border border-slate-700 rounded p-2 text-xs text-cyan-300 mono h-24 focus:border-cyan-500 outline-none resize-none mb-2"></textarea>
                <div class="flex justify-between items-center">
                    <label class="text-[10px] text-cyan-400 cursor-pointer hover:text-white flex items-center gap-2 border border-slate-800 px-2 py-1 rounded hover:bg-slate-800 transition">
                        <i class="fas fa-file-upload"></i> UPLOAD LIST
                        <input type="file" class="hidden" onchange="loadFile(this)">
                    </label>
                    <span id="targetCount" class="text-[10px] text-slate-400 mono">0 TARGETS</span>
                </div>
            </div>

            <div class="space-y-2">
                <label class="text-[10px] font-bold text-slate-500 uppercase tracking-wider block mb-1">Parameters</label>
                
                <div class="p-2 border border-slate-800 rounded bg-slate-900/30">
                    <label class="text-[9px] text-slate-500 block mb-1">SCOPE</label>
                    <select id="scope" class="w-full bg-black border border-slate-700 text-xs text-cyan-400 p-1 rounded outline-none">
                        <option value="standard">Top 1,000 Ports (Fast)</option>
                        <option value="full">Full Spectrum (65k Ports)</option>
                    </select>
                </div>

                <div class="grid grid-cols-1 gap-2">
                    <label class="flex items-center gap-3 p-3 rounded border border-red-900/30 bg-red-900/5 cursor-pointer hover:border-red-600 transition">
                        <input type="checkbox" id="vuln" checked class="accent-red-500 w-4 h-4">
                        <div>
                            <div class="text-xs font-bold text-red-400">Vuln Scan</div>
                            <div class="text-[9px] text-slate-500">CVE Scripts (Slower)</div>
                        </div>
                    </label>
                    
                    <label class="flex items-center gap-3 p-3 rounded border border-slate-800 bg-slate-900/30 cursor-pointer hover:border-cyan-500 transition">
                        <input type="checkbox" id="aggressive" checked class="accent-cyan-500 w-4 h-4">
                        <div>
                            <div class="text-xs font-bold text-cyan-100">Deep Scan</div>
                            <div class="text-[9px] text-slate-500">OS / Traceroute (-A)</div>
                        </div>
                    </label>
                </div>
                
                <div class="mt-2 text-right">
                   <label class="text-[9px] text-slate-600 flex items-center justify-end gap-2 cursor-pointer hover:text-slate-400">
                       <input type="checkbox" id="debug"> Debug Mode (-d)
                   </label>
                </div>
            </div>
        </div>

        <div class="p-5 border-t border-slate-800 space-y-2 bg-slate-900/30">
            <button onclick="launch()" class="w-full py-3 bg-cyan-700 hover:bg-cyan-600 text-white font-bold text-sm tracking-widest shadow-lg shadow-cyan-900/30 rounded transition transform active:scale-95">
                ENGAGE
            </button>
            <div class="grid grid-cols-2 gap-2">
                <button onclick="stop()" class="py-2 bg-red-900/20 border border-red-900/50 text-red-400 text-[10px] hover:bg-red-900/50 hover:text-white font-bold rounded transition">ABORT</button>
                <button onclick="clearHistory()" class="py-2 bg-slate-800 border border-slate-700 text-slate-400 text-[10px] hover:bg-slate-700 hover:text-white font-bold rounded transition">CLEAR</button>
            </div>
        </div>
        
        <div class="h-32 bg-black border-t border-slate-800 p-2 font-mono text-[9px] text-slate-500 overflow-y-auto" id="sysLog">
            <div>> SYSTEM ONLINE...</div>
        </div>
    </aside>

    <main class="flex-1 flex flex-col relative overflow-hidden bg-[#030507]">
        
        <div class="h-16 border-b border-slate-800 bg-slate-900/50 flex items-center justify-between px-6 backdrop-blur z-10">
            <div class="flex gap-6">
                <button onclick="setFilter('ALL')" class="tab-btn active text-xs font-bold pb-1" id="tabALL">ALL TARGETS</button>
                <button onclick="setFilter('ACTIVE')" class="tab-btn text-xs font-bold text-slate-400 pb-1" id="tabACTIVE">ACTIVE OPS</button>
                <button onclick="setFilter('VULN')" class="tab-btn text-xs font-bold text-red-400 pb-1" id="tabVULN">THREATS</button>
                <button onclick="setFilter('CLEAN')" class="tab-btn text-xs font-bold text-emerald-400 pb-1" id="tabCLEAN">CLEAN</button>
            </div>

            <div class="flex gap-8 text-[10px] font-bold mono tracking-wider bg-black/40 px-4 py-2 rounded border border-slate-800">
                <div class="text-slate-500">QUEUE: <span id="statQueue" class="text-white text-lg">0</span></div>
                <div class="text-slate-500">ACTIVE: <span id="statActive" class="text-cyan-400 text-lg">0</span></div>
                <div class="text-slate-500">THREATS: <span id="statVuln" class="text-red-500 text-lg">0</span></div>
            </div>
            
            <div class="relative group hidden" id="dlGroup">
                <button class="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white text-[10px] font-bold border border-slate-600 rounded flex gap-2 items-center transition">
                    <i class="fas fa-file-export text-cyan-400"></i> EXPORT REPORT
                </button>
                <div class="absolute right-0 mt-2 w-56 bg-slate-900 border border-slate-700 rounded shadow-2xl hidden group-hover:block z-50">
                    <a href="#" onclick="downloadMaster('all')" class="block px-4 py-3 text-[10px] text-slate-300 hover:bg-slate-800 hover:text-white border-b border-slate-800">
                        <i class="fas fa-globe mr-2"></i> FULL NETWORK DOSSIER
                    </a>
                    <a href="#" onclick="downloadMaster('vuln')" class="block px-4 py-3 text-[10px] text-red-400 hover:bg-slate-800 hover:text-red-300">
                        <i class="fas fa-biohazard mr-2"></i> CRITICAL THREAT INTEL
                    </a>
                </div>
            </div>
        </div>

        <div class="flex-1 overflow-y-auto p-6 relative" id="feedContainer">
            <div id="feed" class="grid grid-cols-1 xl:grid-cols-2 2xl:grid-cols-3 gap-4"></div>
            
            <div id="emptyState" class="absolute inset-0 flex flex-col items-center justify-center text-slate-800 pointer-events-none">
                <i class="fas fa-satellite text-9xl mb-4 opacity-20 animate-pulse"></i>
                <p class="font-mono text-xs tracking-[0.5em]">AWAITING TARGET DATA</p>
            </div>
        </div>
    </main>

    <script>
        let polling = false;
        let currentFilter = 'ALL';
        let globalData = [];

        function formatOutput(text) {
            if(!text) return '';
            return text.replace(/</g, "&lt;").replace(/>/g, "&gt;")
                       .split('\\n').map(line => {
                           if(line.includes('VULNERABLE') || line.includes('CVE-')) return `<span class="hl-vuln">${line}</span>`;
                           if(line.includes('open') && line.includes('/tcp')) return `<span class="hl-port">${line}</span>`;
                           if(line.startsWith('PORT')) return `<span class="hl-head">${line}</span>`;
                           return line;
                       }).join('\\n');
        }

        function loadFile(input) {
            const reader = new FileReader();
            reader.onload = (e) => {
                document.getElementById('ipInput').value = e.target.result;
                countTargets();
            };
            reader.readAsText(input.files[0]);
        }

        document.getElementById('ipInput').addEventListener('input', countTargets);
        function countTargets() {
            const c = document.getElementById('ipInput').value.split(/[\\n,]+/).filter(s=>s.trim()).length;
            document.getElementById('targetCount').innerText = `${c} TARGETS`;
        }

        async function launch() {
            const raw = document.getElementById('ipInput').value;
            const targets = raw.split(/[\\n,]+/).map(s=>s.trim()).filter(s=>s);
            if(!targets.length) return alert("NO TARGETS");

            document.getElementById('emptyState').classList.add('hidden');
            await fetch('/api/launch', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    targets,
                    scope: document.getElementById('scope').value,
                    aggressive: document.getElementById('aggressive').checked,
                    vuln: document.getElementById('vuln').checked,
                    debug: document.getElementById('debug').checked
                })
            });
            if(!polling) poll();
        }

        async function stop() { if(confirm("ABORT MISSION?")) await fetch('/api/stop', {method:'POST'}); }
        async function clearHistory() { await fetch('/api/clear', {method:'POST'}); }
        function downloadMaster(mode) { window.location.href = `/api/download_master?mode=${mode}`; }

        function setFilter(f) {
            currentFilter = f;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.getElementById('tab'+f).classList.add('active');
            render();
        }

        async function poll() {
            polling = true;
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                globalData = data.jobs;
                
                // Update Logs
                const logBox = document.getElementById('sysLog');
                logBox.innerHTML = data.logs.map(l => `<div>${l}</div>`).join('');
                
                // Update Stats
                const active = globalData.filter(j => ['QUEUED', 'ACTIVE'].includes(j.status)).length;
                const vulns = globalData.filter(j => j.output.includes("VULNERABLE") || j.output.includes("CVE-")).length;
                const completed = globalData.filter(j => j.status === 'COMPLETED').length;
                
                document.getElementById('statQueue').innerText = globalData.length - completed - active;
                document.getElementById('statActive').innerText = active;
                document.getElementById('statVuln').innerText = vulns;
                
                if(completed > 0) document.getElementById('dlGroup').classList.remove('hidden');
                render();
            } catch(e) {}
            setTimeout(poll, 1500);
        }

        function render() {
            const feed = document.getElementById('feed');
            let data = globalData;

            if (currentFilter === 'ACTIVE') data = globalData.filter(j => ['QUEUED', 'ACTIVE'].includes(j.status));
            if (currentFilter === 'VULN') data = globalData.filter(j => j.output.includes('VULNERABLE') || j.output.includes('CVE-'));
            if (currentFilter === 'CLEAN') data = globalData.filter(j => j.status === 'COMPLETED' && !j.output.includes('VULNERABLE') && !j.output.includes('CVE-'));

            feed.innerHTML = data.map(job => {
                let statusHtml, cardClass, pdfBtn = '';
                let isVuln = job.output.includes("VULNERABLE") || job.output.includes("CVE-");

                if (job.status === 'ACTIVE') {
                    statusHtml = `<span class="text-cyan-400 text-[10px] font-bold animate-pulse"><i class="fas fa-spinner fa-spin mr-1"></i> SCANNING...</span>`;
                    cardClass = 'scanning-active';
                } else if (job.status === 'COMPLETED') {
                    if (isVuln) {
                        statusHtml = `<span class="text-red-500 text-[10px] font-bold animate-pulse"><i class="fas fa-exclamation-triangle mr-1"></i> THREAT DETECTED</span>`;
                        cardClass = 'vuln-card';
                    } else {
                        statusHtml = `<span class="text-emerald-500 text-[10px] font-bold"><i class="fas fa-check-circle mr-1"></i> SECURE</span>`;
                        cardClass = 'clean-card';
                    }
                    pdfBtn = `<a href="/api/download/${job.pdf_path}" class="text-[9px] bg-black hover:bg-slate-800 hover:text-white text-slate-400 border border-slate-700 px-2 py-1 rounded transition"><i class="fas fa-file-pdf"></i> PDF</a>`;
                } else {
                    statusHtml = `<span class="text-slate-500 text-[10px] font-bold">QUEUED</span>`;
                    cardClass = 'border-l-4 border-slate-800';
                }

                return `
                <div class="glass p-0 rounded ${cardClass} transition-all duration-300 transform hover:scale-[1.01]">
                    <div class="bg-slate-900/50 p-2 flex justify-between items-center border-b border-slate-800/50">
                        <div>
                            <div class="text-sm font-bold text-white mono tracking-wide">${job.ip}</div>
                            ${statusHtml}
                        </div>
                        <div>${pdfBtn}</div>
                    </div>
                    <div class="bg-black/60 p-3 h-48 overflow-y-auto mono text-[10px] text-slate-400 whitespace-pre-wrap scrollbar-hide">${formatOutput(job.output) || '<span class="text-slate-700">Initializing probe sequence...</span>'}</div>
                </div>`;
            }).join('');
        }
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
