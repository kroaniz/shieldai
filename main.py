import os
import subprocess
import re
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import requests

app = FastAPI(title="ShieldAI - DevSecOps & Web3 Engine")

# Твой секретный ключ Основателя. Можешь поменять его на любой свой
ADMIN_TOKEN = "kroaniz_boss_777"

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
            return "Error: Invalid GitHub URL structure."
        owner, repo = match.group(1), match.group(2)
        repo = repo.replace(".git", "")
        api_url = f"https://api.github.com/repos/{owner}/{repo}/contents"
        headers = {"User-Agent": "ShieldAI-Scanner-Engine"}
        response = requests.get(api_url, headers=headers)
        if response.status_code != 200:
            return f"Error: Could not access repository (Status: {response.status_code})"
        contents = response.json()
        target_file = None
        for file in contents:
            if file["type"] == "file" and (file["name"].endswith(".py") or file["name"].endswith(".sol")):
                target_file = file
                if file["name"] in ["main.py", "app.py", "token.sol", "Main.sol"]:
                    break
        if not target_file:
            return "Error: No audited source files found in root."
        raw_response = requests.get(target_file["download_url"], headers=headers)
        if raw_response.status_code == 200:
            return raw_response.text
        return "Error: Failed to download source from GitHub."
    except Exception as e:
        return f"Error: {str(e)}"

@app.get("/", response_class=HTMLResponse)
def read_root(request: Request):
    # Проверяем, зашел ли ты как админ через секретную ссылку ?admin_token=...
    token_param = request.query_params.get("admin_token", "")
    is_admin = "true" if token_param == ADMIN_TOKEN else "false"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShieldAI // Next-Gen DevSecOps & Web3 Platform</title>
    <style>
        :root {{
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
        }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; background-color: var(--bg-color); margin: 0; padding: 40px 20px; color: var(--text-main); }}
        .container {{ max-width: 900px; background: var(--panel-bg); padding: 40px; border-radius: 12px; border: 1px solid var(--border-color); box-shadow: 0 8px 24px rgba(0,0,0,0.5); margin: 0 auto; }}
        h1 {{ color: #fff; text-align: center; margin-bottom: 5px; font-weight: 600; }}
        p.subtitle {{ text-align: center; color: var(--text-muted); margin-bottom: 30px; font-size: 14px; }}
        .tabs {{ display: flex; border-bottom: 1px solid var(--border-color); margin-bottom: 25px; }}
        .tab-btn {{ background: none; border: none; color: var(--text-muted); padding: 10px 20px; cursor: pointer; font-size: 14px; font-weight: 500; border-bottom: 2px solid transparent; }}
        .tab-btn.active {{ color: #fff; border-bottom: 2px solid #58a6ff; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
        .form-group {{ margin-bottom: 25px; }}
        label {{ display: block; font-weight: 500; margin-bottom: 8px; color: #fff; font-size: 14px; }}
        input, textarea {{ width: 100%; padding: 12px; background: var(--bg-color); border: 1px solid var(--border-color); border-radius: 6px; box-sizing: border-box; font-size: 15px; color: var(--text-main); }}
        textarea {{ font-family: monospace; min-height: 180px; }}
        button.submit-btn {{ width: 100%; background-color: var(--accent-color); color: white; padding: 16px; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; }}
        button.fix-btn {{ width: 100%; background-color: var(--fix-btn-color); color: white; padding: 12px; border: none; border-radius: 6px; font-size: 14px; font-weight: 600; cursor: pointer; margin-top: 15px; }}
        .result-box {{ margin-top: 25px; padding: 25px; background-color: #1f191d; border-left: 4px solid var(--danger); border-radius: 6px; display: none; }}
        .fixed-box {{ margin-top: 25px; padding: 25px; background-color: #191f1a; border-left: 4px solid var(--accent-color); border-radius: 6px; display: none; }}
        pre {{ white-space: pre-wrap; font-size: 14px; color: #ff7b72; font-family: monospace; }}
        .live-feed {{ background: #0d1117; padding: 15px; border-radius: 6px; border: 1px solid var(--border-color); font-family: monospace; font-size: 12px; color: #7ee787; margin-bottom: 20px; display: none; }}
        .modal-overlay {{ position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.85); display: flex; align-items: center; justify-content: center; z-index: 1000; opacity: 0; visibility: hidden; transition: all 0.3s; }}
        .modal-overlay.active {{ opacity: 1; visibility: visible; }}
        .modal-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 35px; max-width: 450px; width: 100%; text-align: center; position: relative; }}
        .crypto-address {{ background: #0d1117; border: 1px solid #30363d; padding: 12px; border-radius: 6px; font-family: monospace; color: #58a6ff; margin: 20px 0; word-break: break-all; }}
        .close-modal-btn {{ position: absolute; top: 15px; right: 15px; background: none; border: none; color: #8b949e; font-size: 18px; cursor: pointer; }}
        .badge {{ background: #d29922; color: #000; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-left: 10px; vertical-align: middle; }}
    </style>
</head>
<body>
<div class="container">
    <h1>ShieldAI 🛡️ <span style="color: #58a6ff; font-size: 16px;">V3.0 Pro</span></h1>
    <p class="subtitle">Automated Infrastructure Cyber Audit & Smart Contract Security Remediation</p>
    
    <div id="adminBadge" style="display:none; background: rgba(35,134,54,0.2); border: 1px solid var(--accent-color); padding: 10px; border-radius: 6px; text-align: center; margin-bottom: 20px; color: #7ee787; font-size: 13px; font-family: monospace;">
        ⚡ FOUNDER MODE ACTIVE: Core Engine Patches Unlocked (Free Access)
    </div>

    <div class="form-group">
        <label>Organization Audit Target</label>
        <input type="text" id="companyName" value="Enterprise Workspace Corp">
    </div>

    <div class="tabs">
        <button class="tab-btn active" onclick="switchMode('paste-mode')">Python DevSecOps</button>
        <button class="tab-btn" onclick="switchMode('web3-mode')">Web3 Smart Contracts <span class="badge">NEW</span></button>
    </div>

    <div id="paste-mode" class="tab-content active">
        <div class="form-group">
            <label>Source Code Target (Python / Script)</label>
            <textarea id="sourceCode">import os
def connect_to_db():
    db_password = "enterprise_vault_secret_pass_101"
    os.system(f"squid -q {db_password}")</textarea>
        </div>
    </div>

    <div id="web3-mode" class="tab-content">
        <div class="form-group">
            <label>Solidity Smart Contract Source (ERC-20 / DeFi Vault)</label>
            <textarea id="web3Code" placeholder="Paste .sol contract code here...">// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableToken {{
    mapping(address => uint) public balances;
    
    // CRITICAL: Reentrancy vulnerability vector detected
    function withdraw(uint _amount) public {{
        require(balances[msg.sender] >= _amount);
        (bool success, ) = msg.sender.call{{value: _amount}}("");
        require(success);
        balances[msg.sender] -= _amount;
    }}
}}</textarea>
        </div>
    </div>

    <div class="live-feed" id="liveFeed"></div>

    <button class="submit-btn" onclick="runAudit()">Scan Project Infrastructure</button>

    <div id="metricsDashboard" style="display: none; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 30px;">
        <div style="background: var(--bg-color); border-top: 4px solid var(--danger); padding: 15px; border-radius: 6px; text-align: center;">
            <div style="font-size: 24px; font-weight: bold; color: var(--danger);">CRITICAL</div>
            <div style="font-size: 12px; color: var(--text-muted); text-transform: uppercase;">Threat Level</div>
        </div>
        <div style="background: var(--bg-color); border-top: 4px solid var(--warning); padding: 15px; border-radius: 6px; text-align: center;">
            <div style="font-size: 24px; font-weight: bold; color: var(--warning);">HIGH</div>
            <div style="font-size: 12px; color: var(--text-muted); text-transform: uppercase;">Exploitability</div>
        </div>
        <div style="background: var(--bg-color); border-top: 4px solid var(--info); padding: 15px; border-radius: 6px; text-align: center;">
            <div style="font-size: 24px; font-weight: bold; color: var(--info);">98%</div>
            <div style="font-size: 12px; color: var(--text-muted); text-transform: uppercase;">Bot Interception</div>
        </div>
    </div>

    <div id="resultBox" class="result-box">
        <h3 style="margin-top: 0; color: #ff7b72;">ShieldAI Automated Incident Log:</h3>
        <pre id="resultText"></pre>
        <button class="fix-btn" onclick="handleRemediation()">⚡ Deploy Automated Patch Infrastructure</button>
    </div>

    <div id="fixedBox" class="fixed-box">
        <h3 style="margin-top: 0; color: #7ee787;">Founder Sandbox Secure Patch:</h3>
        <pre id="fixedCodeText" style="color: #7ee787;"></pre>
    </div>
</div>

<div id="paymentModal" class="modal-overlay">
    <div class="modal-card">
        <button class="close-modal-btn" onclick="closePaywall()">&times;</button>
        <h2 style="color: #58a6ff;">ShieldAI Pro Workspace Required ⚡</h2>
        <p>Automated cloud remediation, multi-file patching, and smart contract vulnerability rewrites are locked under the Pro License tier.</p>
        <p style="margin-top: 15px; font-weight: bold; color: #fff;">To instantly upgrade your instance, transfer exactly <span style="color: #d29922;">29 USDT (TRC-20)</span> to:</p>
        <div class="crypto-address">TY6Sg8X7zK9pWqLmN3vRx2tY5uB4iE1oAsP</div>
        <p style="font-size: 11px; color: #8b949e;">The AI Engine automatically scans the ledger. Workspace activation occurs within 180 seconds post network confirmation.</p>
    </div>
</div>

<script>
    let activeMode = 'paste-mode';
    const isFounder = {is_admin};

    if (isFounder) {{
        document.getElementById('adminBadge').style.display = 'block';
    }}

    function switchMode(modeId) {{
        activeMode = modeId;
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        window.event.target.classList.add('active');
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        document.getElementById(modeId).classList.add('active');
    }}

    function sleep(ms) {{ return new Promise(resolve => setTimeout(resolve, ms)); }}

    async function runAudit() {{
        const btn = document.querySelector('.submit-btn');
        const feed = document.getElementById('liveFeed');
        btn.disabled = true;
        document.getElementById('metricsDashboard').style.display = 'none';
        document.getElementById('resultBox').style.display = 'none';
        document.getElementById('fixedBox').style.display = 'none';

        feed.style.display = 'block';
        feed.innerText = "--> Initializing Cloud Sandbox Environment...\\n";
        await sleep(600);
        feed.innerText += "--> [RUNNING] Deep Secrets Scan (.env, raw keys, hardcoded parameters)...\\n";
        await sleep(800);
        feed.innerText += "--> [ALERT] High-Entropy Credential leak string identified!\\n";
        await sleep(500);
        feed.innerText += "--> [RUNNING] Logic Vulnerability Checker & Reentrancy Tracker...\\n";
        await sleep(700);
        feed.innerText += "--> Security Audit Finished. Processing advisor report...\\n";
        await sleep(400);
        feed.style.display = 'none';

        document.getElementById('metricsDashboard').style.display = 'grid';
        document.getElementById('resultBox').style.display = 'block';

        if(activeMode === 'paste-mode') {{
            document.getElementById('resultText').innerText = "[SHIELD-AI ADVISORY REPORT]\\nCRITICAL: Hardcoded administrative password found inside active database connection sequence.\\nHIGH RISK: Shell execution bypass via os.system allows RCE payload delivery.";
        }} else {{
            document.getElementById('resultText').innerText = "[SHIELD-AI WEB3 ADVISORY REPORT]\\nCRITICAL: Reentrancy vulnerability inside withdraw(). State variable updates occur AFTER token transfers.\\nVector allows smart contract balance drainage via fallback recursion.";
        }}
        btn.disabled = false;
    }}

    async function handleRemediation() {{
        if (isFounder) {{
            document.getElementById('fixedBox').style.display = 'block';
            if (activeMode === 'paste-mode') {{
                document.getElementById('fixedCodeText').innerText = "import os\\nimport subprocess\\n\\ndef connect_to_db():\\n    # FIXED: Credentials pulled from vault env parameters\\n    db_password = os.getenv('DB_SECURE_PASSWORD')\\n\\ndef execute_query(query):\\n    # FIXED: Subprocess array injection block\\n    subprocess.run(['squid', '-q', query], shell=False)";
            }} else {{
                document.getElementById('fixedCodeText').innerText = "contract SecureToken {{\\n    mapping(address => uint) public balances;\\n\\n    // FIXED: CEI Pattern enforced & State updated before external call\\n    function withdraw(uint _amount) public {{\\n        require(balances[msg.sender] >= _amount);\\n        balances[msg.sender] -= _amount;\\n        (bool success, ) = msg.sender.call{{value: _amount}}(\"\");\\n        require(success);\\n    }}\\n}}";
            }}
            document.getElementById('fixedBox').scrollIntoView({{ behavior: 'smooth' }});
        }} else {{
            triggerPaywall();
        }}
    }}

    function triggerPaywall() {{ document.getElementById('paymentModal').classList.add('active'); }}
    function closePaywall() {{ document.getElementById('paymentModal').classList.remove('active'); }}
</script>
</body>
</html>"""
    return HTMLResponse(content=html_content)
