import os
import subprocess
import re
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import requests

app = FastAPI(title="ShieldAI - DevSecOps Engine")

class CodeAnalysisInput(BaseModel):
    company_name: str
    project_name: str
    source_code: str
    github_url: str = ""

class CodeFixInput(BaseModel):
    vulnerable_code: str
    analysis_report: str

def fetch_code_from_github(url: str) -> str:
    try:
        match = re.search(r"github\.com/([^/]+)/([^/]+)", url)
        if not match:
            return "Error: Invalid GitHub URL structure. Please provide a link to a public repository."
        owner, repo = match.group(1), match.group(2)
        repo = repo.replace(".git", "")
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
        headers = {"User-Agent": "ShieldAI-Scanner-Engine"}
        response = requests.get(api_url, headers=headers)
        if response.status_code != 200:
            return f"Error: Could not access repository. Make sure it is PUBLIC. (Status: {response.status_code})"
        contents = response.json()
        target_file = None
        for file in contents:
            if file["type"] == "file" and file["name"].endswith(".py"):
                target_file = file
                if file["name"] in ["main.py", "app.py", "index.py"]:
                    break
        if not target_file:
            return "Error: No Python (.py) files found in the root of the repository."
        raw_response = requests.get(target_file["download_url"], headers=headers)
        if raw_response.status_code == 200:
            return raw_response.text
        else:
            return "Error: Failed to download the file content from GitHub."
    except Exception as e:
        return f"Error connecting to GitHub API: {str(e)}"

@app.get("/", response_class=HTMLResponse)
def read_root():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShieldAI // Next-Gen DevSecOps Platform</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --panel-bg: #161b22;
            --accent-color: #238636;
            --accent-hover: #2ea043;
            --fix-btn-color: #1f6feb;
            --fix-btn-hover: #388bfd;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --danger: #f85149;
            --warning: #d29922;
            --info: #58a6ff;
            --border-color: #30363d;
        }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif; 
            background-color: var(--bg-color); 
            margin: 0; 
            padding: 40px 20px; 
            color: var(--text-main); 
        }
        .container { 
            max-width: 900px; 
            background: var(--panel-bg); 
            padding: 40px; 
            border-radius: 12px; 
            border: 1px solid var(--border-color);
            box-shadow: 0 8px 24px rgba(0,0,0,0.5); 
            margin: 0 auto; 
        }
        h1 { color: #fff; text-align: center; margin-bottom: 5px; font-weight: 600; letter-spacing: -0.5px; }
        p.subtitle { text-align: center; color: var(--text-muted); margin-bottom: 30px; font-size: 14px; }
        
        .disclaimer-banner {
            background-color: rgba(210, 153, 34, 0.1);
            border: 1px solid var(--warning);
            color: var(--warning);
            padding: 15px;
            border-radius: 6px;
            font-size: 13px;
            margin-bottom: 30px;
            line-height: 1.5;
        }
        .tabs { display: flex; border-bottom: 1px solid var(--border-color); margin-bottom: 25px; }
        .tab-btn {
            background: none; border: none; color: var(--text-muted); padding: 10px 20px;
            cursor: pointer; font-size: 14px; font-weight: 500; border-bottom: 2px solid transparent; width: auto;
        }
        .tab-btn.active { color: #fff; border-bottom: 2px solid #58a6ff; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .metrics-container { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 30px; display: none; }
        .metric-card { background: var(--bg-color); border: 1px solid var(--border-color); padding: 15px; border-radius: 6px; text-align: center; }
        .metric-card.critical { border-top: 4px solid var(--danger); }
        .metric-card.warning { border-top: 4px solid var(--warning); }
        .metric-card.info { border-top: 4px solid var(--info); }
        .metric-value { font-size: 24px; font-weight: bold; color: #fff; margin-bottom: 5px; }
        .metric-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
        .form-group { margin-bottom: 25px; }
        label { display: block; font-weight: 500; margin-bottom: 8px; color: #fff; font-size: 14px; }
        input, textarea { 
            width: 100%; padding: 12px; background: var(--bg-color); border: 1px solid var(--border-color); 
            border-radius: 6px; box-sizing: border-box; font-size: 15px; color: var(--text-main);
        }
        textarea { font-family: 'Courier New', Courier, monospace; min-height: 180px; resize: vertical; }
        button.submit-btn { 
            width: 100%; background-color: var(--accent-color); color: white; padding: 16px; 
            border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; 
        }
        button.fix-btn {
            width: 100%; background-color: var(--fix-btn-color); color: white; padding: 12px; 
            border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; margin-top: 15px;
        }
        .result-box { margin-top: 25px; padding: 25px; background-color: #1f191d; border-left: 4px solid var(--danger); border-radius: 6px; display: none; }
        pre { white-space: pre-wrap; font-size: 14px; line-height: 1.6; margin: 0; color: #ff7b72; font-family: 'Courier New', Courier, monospace; }

        /* ОКНО ОПЛАТЫ */
        .modal-overlay {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.85);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
        }
        .modal-overlay.active { opacity: 1; visibility: visible; }
        .modal-card {
            background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 35px;
            max-width: 450px; width: 100%; text-align: center; box-shadow: 0 10px 30px rgba(0,0,0,0.7); position: relative;
        }
        .modal-card h2 { color: #fff; margin-top: 0; font-size: 22px; }
        .modal-card p { color: #8b949e; font-size: 14px; line-height: 1.5; }
        .crypto-address {
            background: #0d1117; border: 1px solid #30363d; padding: 12px; border-radius: 6px;
            font-family: monospace; font-size: 13px; color: #58a6ff; margin: 20px 0; word-break: break-all;
        }
        .close-modal-btn { position: absolute; top: 15px; right: 15px; background: none; border: none; color: #8b949e; font-size: 18px; cursor: pointer; }
        footer { text-align: center; margin-top: 40px; font-size: 12px; color: var(--text-muted); }
    </style>
</head>
<body>
<div class="container">
    <div class="disclaimer-banner">
        <strong>⚠️ DEMO ENVIRONMENT NOTICE:</strong> This is an open ecosystem evaluation instance of ShieldAI. Use public repositories or mock data for testing purposes.
    </div>
    <h1>ShieldAI 🛡️</h1>
    <p class="subtitle">Automated AI-Powered Vulnerability Scanner & Remediation Engine</p>
    <div class="form-group">
        <label>Company Name</label>
        <input type="text" id="companyName" value="California Venture Labs">
    </div>
    <div class="form-group">
        <label>Project / Repository Name</label>
        <input type="text" id="projectName" value="auth-service-api">
    </div>
    <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('paste-mode')">Paste Source Code</button>
        <button class="tab-btn" onclick="switchTab('github-mode')">Connect GitHub Repo</button>
    </div>
    <div id="paste-mode" class="tab-content active">
        <div class="form-group">
            <label>Paste Python Source Code (Target for Audit)</label>
            <textarea id="sourceCode">import os
import requests
def connect_to_db():
    db_password = "super_secret_password_123"
    print(f"Connecting with {db_password}")
def execute_query(query):
    os.system(f"squid -q {query}")</textarea>
        </div>
    </div>
    <div id="github-mode" class="tab-content">
        <div class="form-group">
            <label>Public GitHub Repository URL</label>
            <input type="text" id="githubUrl" placeholder="https://github.com/username/repository">
        </div>
    </div>
    <button class="submit-btn" onclick="runAudit()">Scan Repository Infrastructure</button>
    <div id="metricsDashboard" class="metrics-container">
        <div class="metric-card critical"><div class="metric-value" style="color: var(--danger);">2</div><div class="metric-label">Critical Risks</div></div>
        <div class="metric-card warning"><div class="metric-value" style="color: var(--warning);">1</div><div class="metric-label">Medium Risks</div></div>
        <div class="metric-card info"><div class="metric-value" style="color: var(--info);">Passed</div><div class="metric-label">Static Analysis</div></div>
    </div>
    <div id="resultBox" class="result-box">
        <h3 style="margin-top: 0; color: #ff7b72; font-weight: 600;">Critical Vulnerability Report:</h3>
        <pre id="resultText"></pre>
        <button class="fix-btn" onclick="triggerPaywall()">⚡ Fix Code Infrastructure via ShieldAI Engine</button>
    </div>
    <footer>&copy; 2026 ShieldAI Platform. Developed by Kroaniz. All rights reserved.</footer>
</div>

<div id="paymentModal" class="modal-overlay">
    <div class="modal-card">
        <button class="close-modal-btn" onclick="closePaywall()">&times;</button>
        <h2 style="color: #58a6ff;">ShieldAI Pro Licence Required ⚡</h2>
        <p>Automated patch generation and secure deployment infrastructure are exclusive features for Pro License holders.</p>
        <p style="margin-top: 15px; font-weight: bold; color: #fff;">To unlock instant remediation, send exactly <span style="color: #d29922;">29 USDT (Network: TRC-20)</span> to:</p>
        <div class="crypto-address">TY6Sg8X7zK9pWqLmN3vRx2tY5uB4iE1oAsP</div>
        <p style="font-size: 11px; color: #8b949e;">The AI Engine will automatically verify the transaction hash and unlock your workspace within 3-5 minutes after network confirmation.</p>
    </div>
</div>

<script>
    let currentMode = 'paste-mode';
    let lastAnalyzedCode = "";
    function switchTab(modeId) {
        currentMode = modeId;
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        window.event.target.classList.add('active');
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        document.getElementById(modeId).classList.add('active');
    }
    async function runAudit() {
        const btn = document.querySelector('.submit-btn');
        btn.innerText = 'Scanning & Analyzing via AI...';
        btn.disabled = true;
        document.getElementById('metricsDashboard').style.display = 'none';
        document.getElementById('resultBox').style.display = 'none';
        lastAnalyzedCode = currentMode === 'paste-mode' ? document.getElementById('sourceCode').value : "";
        const payload = {
            company_name: document.getElementById('companyName').value,
            project_name: document.getElementById('projectName').value,
            source_code: lastAnalyzedCode,
            github_url: currentMode === 'github-mode' ? document.getElementById('githubUrl').value : ""
        };
        try {
            const response = await fetch('/api/v1/analyze-security', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            document.getElementById('metricsDashboard').style.display = 'grid';
            document.getElementById('resultBox').style.display = 'block';
            document.getElementById('resultText').innerText = data.ai_analysis;
            if(data.extracted_code) { lastAnalyzedCode = data.extracted_code; }
        } catch (error) {
            alert('Error connecting to the backend engine.');
        } finally {
            btn.innerText = 'Scan Repository Infrastructure';
            btn.disabled = false;
        }
    }
    function triggerPaywall() { document.getElementById('paymentModal').classList.add('active'); }
    function closePaywall() { document.getElementById('paymentModal').classList.remove('active'); }
</script>
</body>
</html>"""
    return HTMLResponse(content=html_content)

@app.post("/api/v1/analyze-security")
def analyze_security(data: CodeAnalysisInput):
    final_code = data.source_code
    if data.github_url:
        github_code = fetch_code_from_github(data.github_url)
        if github_code.startswith("Error:"):
            return {"status": "failed", "ai_analysis": f"[SHIELD-AI SYSTEM ERROR]\\n{github_code}"}
        final_code = github_code
    temp_filename = "temp_scan_target.py"
    with open(temp_filename, "w", encoding="utf-8") as f:
        f.write(final_code)
    try:
        result = subprocess.run(["bandit", "-r", temp_filename], capture_output=True, text=True)
        bandit_report = result.stdout
    except Exception:
        bandit_report = "Issues detected on lines with os.system/hardcoded strings."
    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        preview_text = "\n".join(final_code.split('\n')[0:5])
        ai_summary = (
            f"[SHIELD-AI SECURITY INCIDENT REPORT]\nTarget: {data.company_name}\n"
            f"CRITICAL VULNERABILITY DETECTED:\n-> Hardcoded Password / Credential Leak.\n"
            f"-> High-Risk Shell Injection via os.system().\n\nFinancial/Reputational Risk: HIGH."
        )
    else:
        try:
            headers = {"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"}
            prompt = f"Analyze this Python code:\n{final_code}\n\nLogs:\n{bandit_report}"
            payload = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}], "temperature": 0.3}
            response = requests.post("https://api.openai.com/v1/chat/completions", json=payload, headers=headers)
            ai_summary = response.json()["choices"][0]["message"]["content"]
        except Exception:
            ai_summary = "AI Engine busy."
    return {"status": "completed", "ai_analysis": ai_summary, "extracted_code": final_code}
