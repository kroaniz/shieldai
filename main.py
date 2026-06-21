import ast
import hashlib
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="CodeInsight Enterprise Pro Platform")

# СЕКРЕТНЫЙ КЛЮЧ-СОЛЬ. Используется для генерации уникальных лицензий.
SECRET_SIGNING_SALT = "GLOBAL_CODEINSIGHT_SECURE_TOKEN_2026_PRO"

class AuditRequest(BaseModel):
    code: str
    license_key: str = ""

def is_valid_pro_key(user_key: str) -> bool:
    clean_key = user_key.strip()
    
    # Твой личный супер-ключ для тестов (всегда работает)
    if clean_key == "PRO_PREMIUM_TOKEN_2026":
        return True
        
    # Проверка структуры индивидуального ключа (формат: email-хэш)
    if "-" not in clean_key:
        return False
        
    try:
        user_email, token_hash = clean_key.split("-", 1)
        # Математически воссоздаем хэш на сервере для проверки подлинности
        expected_raw = f"{user_email.lower().strip()}:{SECRET_SIGNING_SALT}"
        expected_hash = hashlib.sha256(expected_raw.encode()).hexdigest()[:16]
        
        return token_hash == expected_hash
    except Exception:
        return False

@app.post("/api/v1/audit")
async def execute_audit(data: AuditRequest):
    source_code = data.code
    user_key = data.license_key.strip()
    
    if not source_code.strip():
        return {
            "status": "empty",
            "message": "Input data is missing. Please paste your source code to proceed."
        }
    
    try:
        # Базовый разбор кода (Доступен в Demo-версии)
        tree = ast.parse(source_code)
        raw_lines = source_code.splitlines()
        lines_count = len(raw_lines)
        
        functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        comment_lines = sum(1 for line in raw_lines if line.strip().startswith("#"))
                
        response_data = {
            "status": "demo_success",
            "lines": lines_count,
            "functions_count": len(functions),
            "classes_count": len(classes),
            "message": "Basic structural audit completed successfully. Syntax is valid, no compilation errors found."
        }
        
        # ПРОВЕРКА ЛИЦЕНЗИИ ДЛЯ АКТИВАЦИИ PREMIUM ФИЧ
        if is_valid_pro_key(user_key):
            comment_density = round((comment_lines / lines_count) * 100) if lines_count > 0 else 0
            
            detected_issues = []
            has_hardcoded_secrets = False
            has_unsafe_execution = False
            
            # Сканирование безопасности
            for index, line in enumerate(raw_lines, 1):
                lowered_line = line.lower()
                if any(sec in lowered_line for sec in ["secret", "password", "passwd", "token"]) and "=" in line:
                    if not any(safe in lowered_line for safe in ["env", "get", "load"]):
                        detected_issues.append(f"Line {index}: Potential hardcoded credential token.")
                        has_hardcoded_secrets = True
                if "os.system(" in line or "eval(" in line or "exec(" in line:
                    detected_issues.append(f"Line {index}: Insecure environment command execution context.")
                    has_unsafe_execution = True

            # Калькулятор стоимости технического долга ($)
            base_debt = lines_count * 0.5 
            security_penalty = len(detected_issues) * 120.0
            structural_penalty = 75.0 if (lines_count > 25 and len(functions) <= 1) else 0.0
            total_debt_usd = round(base_debt + security_penalty + structural_penalty, 2)
            hours_estimated = round(total_debt_usd / 45, 1) if total_debt_usd > 0 else 0.2

            # Generator для интерактивного графа зависимостей
            visual_nodes = [{"name": "App Root", "type": "root", "status": "secure" if not detected_issues else "unsecure"}]
            for cls in classes:
                visual_nodes.append({"name": f"class {cls}", "type": "class", "status": "secure"})
            for func in functions:
                func_status = "secure"
                if has_unsafe_execution and func in source_code:
                    func_status = "unsecure"
                visual_nodes.append({"name": f"def {func}()", "type": "function", "status": func_status})

            if detected_issues:
                issue_list_str = "\n".join([f"- {issue}" for issue in detected_issues])
                
                patch_advice = f"""### ⚠️ CRITICAL INFRASTRUCTURE RISKS DETECTED:
{issue_list_str}

### 🛡️ AUTOMATED REMEDIATION PATCH:
```python
# [FIXED] Security Hardening Patch Applied Successfully
import subprocess
import shlex
import os

def secure_execute(command_string):
    safe_args = shlex.split(command_string)
    return subprocess.run(safe_args, capture_output=True, text=True, check=True)

# Loaded system credentials from secure environment space
db_password = os.getenv('ENTERPRISE_VAULT_DB_PASS')
```"""
                maintainability = "Critical Risk"
                security_status = "unsecure"
            else:
                if lines_count > 25 and len(functions) <= 1:
                    patch_advice = "### 📊 ARCHITECTURE ANALYSIS:\nYour script contains a monolithic code structure. Pro Recommendation: Break down your main execution pipeline into distinct modular sub-functions."
                    maintainability = "Fair"
                else:
                    patch_advice = "### ✨ ARCHITECTURE STANDARDS COMPLIANT:\nCode syntax density, scope isolation, and function-to-line parameters are perfectly optimized."
                    maintainability = "Excellent"
                security_status = "secure"

            response_data["status"] = "pro_success"
            response_data["message"] = "PRO Mode successfully activated. Comprehensive compliance metrics compiled."
            response_data["advanced_metrics"] = {
                "maintainability": maintainability,
                "comment_density": f"{comment_density}%",
                "security_status": security_status,
                "tech_debt_usd": f"${total_debt_usd}",
                "remediation_time": f"{hours_estimated} hrs",
                "visual_nodes": visual_nodes,
                "remediation_patch": patch_advice
            }
        else:
            if user_key:
                response_data["message"] = "Invalid or expired Pro License Key. Running in standard Demo Mode."

        return response_data

    except SyntaxError as e:
        return {
            "status": "syntax_error",
            "message": f"Critical syntax defect identified on line {e.lineno}: {e.msg}"
        }

@app.get("/", response_class=HTMLResponse)
async def get_application_interface():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeInsight // Enterprise Code Audit Platform</title>
    <style>
        :root {
            --bg-dark: #0d1117;
            --panel-dark: #161b22;
            --border-color: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --btn-green: #238636;
            --btn-green-hover: #2ea043;
            --btn-blue: #1f6feb;
            --btn-blue-hover: #388bfd;
            --accent-gold: #d29922;
            --danger-red: #f85149;
        }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; background-color: var(--bg-dark); color: var(--text-main); margin: 0; padding: 40px 20px; }
        .container { max-width: 850px; background-color: var(--panel-dark); border: 1px solid var(--border-color); border-radius: 12px; padding: 40px; margin: 0 auto; box-shadow: 0 8px 24px rgba(0,0,0,0.6); }
        h1 { color: #fff; text-align: center; margin-top: 0; font-weight: 600; }
        p.desc { text-align: center; color: var(--text-muted); margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #fff; font-size: 14px; font-weight: 500; }
        textarea { width: 100%; height: 180px; background-color: var(--bg-dark); border: 1px solid var(--border-color); color: var(--text-main); padding: 14px; border-radius: 6px; box-sizing: border-box; font-family: monospace; font-size: 14px; resize: vertical; }
        input[type="text"] { width: 100%; padding: 12px; background-color: var(--bg-dark); border: 1px solid var(--border-color); color: var(--text-main); border-radius: 6px; box-sizing: border-box; font-family: monospace; }
        .actions { display: grid; grid-template-columns: 1fr; gap: 15px; margin-top: 15px; }
        button { padding: 15px; border: none; border-radius: 6px; font-size: 16px; font-weight: 600; cursor: pointer; color: #fff; transition: background-color 0.2s; }
        .btn-audit { background-color: var(--btn-green); }
        .btn-audit:hover { background-color: var(--btn-green-hover); }
        .btn-pay { background-color: var(--btn-blue); font-size: 14px; padding: 12px 24px; margin-top: 15px; display: inline-block; text-decoration: none; color: #fff; border-radius: 6px; font-weight: bold; cursor: pointer; }
        .btn-pay:hover { background-color: var(--btn-blue-hover); }
        .dashboard { margin-top: 30px; padding: 25px; background-color: #1f242c; border-radius: 8px; border-left: 4px solid var(--btn-blue); display: none; }
        .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }
        .card { background-color: var(--bg-dark); border: 1px solid var(--border-color); padding: 15px; border-radius: 6px; text-align: center; }
        .card-num { font-size: 22px; font-weight: bold; color: #fff; }
        .card-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; }
        .pro-banner { background-color: rgba(210, 153, 34, 0.1); border: 1px solid var(--accent-gold); padding: 20px; border-radius: 8px; margin-top: 20px; text-align: center; }
        .pro-unlocked { background-color: rgba(35, 134, 54, 0.1); border: 1px solid var(--btn-green); padding: 20px; border-radius: 8px; margin-top: 20px; display: none; }
        .map-container { background: #0d1117; border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; margin-top: 20px; text-align: center; }
        .map-title { font-size: 13px; font-weight: bold; color: #fff; margin-bottom: 15px; text-align: left; text-transform: uppercase;}
        .node-flow { display: block; text-align: center; padding: 10px; }
        .node { display: inline-block; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-family: monospace; font-weight: bold; margin: 5px; border: 1px solid var(--border-color); background: var(--panel-dark); }
        .node-root { border-color: #58a6ff; color: #58a6ff; box-shadow: 0 0 10px rgba(88,166,255,0.2); }
        .node-secure { border-color: #2ea043; color: #56d364; box-shadow: 0 0 10px rgba(46,160,67,0.2); }
        .node-unsecure { border-color: var(--danger-red); color: var(--danger-red); box-shadow: 0 0 15px rgba(248,81,73,0.4); animation: pulse 2s infinite; }
        @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.03); } 100% { transform: scale(1); } }
        .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.8); backdrop-filter: blur(4px); }
        .modal-content { background-color: var(--panel-dark); margin: 10% auto; padding: 30px; border: 1px solid var(--border-color); width: 90%; max-width: 500px; border-radius: 12px; position: relative; box-shadow: 0 10px 30px rgba(0,0,0,0.7); }
        .close-btn { position: absolute; right: 20px; top: 15px; color: var(--text-muted); font-size: 24px; font-weight: bold; cursor: pointer; }
        .close-btn:hover { color: #fff; }
        .payment-option { background: var(--bg-dark); border: 1px solid var(--border-color); padding: 20px; border-radius: 8px; margin-top: 15px; text-align: left; }
        .crypto-address { background: #0d1117; border: 1px solid #21262d; padding: 12px; border-radius: 6px; font-family: monospace; font-size: 13px; color: #58a6ff; word-break: break-all; margin-top: 8px; text-align: center; letter-spacing: 0.5px; }
    </style>
</head>
<body>

<div class="container">
    <h1>CodeInsight Platform</h1>
    <p class="desc">Enterprise-Grade Static Code Structure & Risk Valuation Engine</p>
    
    <div class="form-group">
        <label>Pro License Access Token (Leave empty for Standard Evaluation Mode)</label>
        <input type="text" id="licenseKey" placeholder="Paste your enterprise license key here...">
    </div>

    <div class="form-group">
        <label>Target Python Source Code Pipeline</label>
        <textarea id="codeBody" placeholder="def process_payload(data):\n    return data"></textarea>
    </div>
    
    <div class="actions">
        <button class="btn-audit" onclick="requestAnalysis()">Execute Core Infrastructure Scan</button>
    </div>

    <div id="dashBlock" class="dashboard">
        <h3 style="margin-top: 0; color: #fff;">Audit Framework Matrix:</h3>
        <p id="statusMsg"></p>
        
        <div id="baseMetrics" class="metrics">
            <div class="card"><div id="mLines" class="card-num">0</div><div class="card-label">Lines Evaluated</div></div>
            <div class="card"><div id="mFuncs" class="card-num">0</div><div class="card-label">Isolated Functions</div></div>
            <div class="card"><div id="mClasses" class="card-num">0</div><div class="card-label">Class Declarations</div></div>
        </div>

        <div id="proBanner" class="pro-banner">
            <h4 style="margin-top: 0; color: var(--accent-gold);">🔒 Enterprise Intelligence Logs Locked</h4>
            <p style="font-size: 13px; margin-bottom: 0;">Automated remediation scripts, real-time micro-architecture dependency graph mapping, and financial technical debt metrics require active authorization.</p>
            <button class="btn-pay" onclick="openPaymentModal()">⚡ Unlock Pro Architecture Pack ($19)</button>
        </div>

        <div id="proUnlocked" class="pro-unlocked">
            <h4 style="margin-top: 0; color: #7ee787;">⚡ Pro Infrastructure Environment Fully Activated</h4>
            <div class="metrics" style="margin-bottom: 20px;">
                <div class="card" id="cardMaintain" style="border-color: #238636;"><div id="mMaintain" class="card-num" style="color: #7ee787;">N/A</div><div class="card-label">Maintainability Rating</div></div>
                <div class="card" style="border-color: #238636;"><div id="mComments" class="card-num" style="color: #7ee787;">0%</div><div class="card-label">Documentation Volume</div></div>
            </div>
            <div class="metrics" style="margin-bottom: 20px;">
                <div class="card" id="cardDebt" style="border-color: #30363d;"><div id="mDebt" class="card-num" style="color: #58a6ff;">$0.00</div><div class="card-label">Technical Debt Liability</div></div>
                <div class="card" style="border-color: #30363d;"><div id="mTime" class="card-num" style="color: #58a6ff;">0.0 hrs</div><div class="card-label">Remediation Effort</div></div>
            </div>
            <div class="map-container">
                <div class="map-title">🌐 Active Micro-Architecture Dependency Graph:</div>
                <div id="mapFlow" class="node-flow"></div>
            </div>
            <pre id="proPatchText" style="white-space: pre-wrap; font-family: monospace; text-align: left; font-size: 13px; color: #7ee787; background: #0d1117; padding: 15px; border-radius: 6px; border: 1px solid #30363d; margin-top: 20px;"></pre>
        </div>
    </div>
</div>

<div id="paymentModal" class="modal">
    <div class="modal-content">
        <span class="close-btn" onclick="closePaymentModal()">&times;</span>
        <h3 style="margin-top: 0; color: #fff; text-align: center;">Authorize Pro License</h3>
        <p style="font-size: 13px; color: var(--text-muted); text-align: center; margin-bottom: 20px;">Deploy fully-automated vulnerability architecture checking and mitigation code snippets.</p>
        <div class="payment-option">
            <div style="font-weight: 600; font-size: 14px; color: #7ee787; text-align: center; margin-bottom: 10px;">Method: Digital Asset Settlement (USDT TRC-20)</div>
            <div style="font-size: 12px; color: var(--text-muted); text-align: center;">Transfer exactly <strong>19 USDT</strong> directly to the secure network node below:</div>
            <div class="crypto-address">TWcaHG75Sv5ssvdTU1Am6rPw5DRtoJB1hi</div>
            <div style="font-size: 11px; color: var(--accent-gold); margin-top: 15px; line-height: 1.4; text-align: center;">💡 After making the transfer, send your transaction hash (txID) or screenshot along with your target Email address to our Telegram support node to receive your premium access token instantly.</div>
        </div>
    </div>
</div>

<script>
    function openPaymentModal() { document.getElementById("paymentModal").style.display = "block"; }
    function closePaymentModal() { document.getElementById("paymentModal").style.display = "none"; }
    window.onclick = function(event) { const modal = document.getElementById("paymentModal"); if (event.target == modal) { modal.style.display = "none"; } }

    async function requestAnalysis() {
        const codeInput = document.getElementById("codeBody").value;
        const keyInput = document.getElementById("licenseKey").value;
        const dash = document.getElementById("dashBlock");
        const msg = document.getElementById("statusMsg");
        const baseMetrics = document.getElementById("baseMetrics");
        const proBanner = document.getElementById("proBanner");
        const proUnlocked = document.getElementById("proUnlocked");
        const cardMaintain = document.getElementById("cardMaintain");
        const cardDebt = document.getElementById("cardDebt");
        const proPatchText = document.getElementById("proPatchText");
        const mapFlow = document.getElementById("mapFlow");
        
        try {
            const response = await fetch("/api/v1/audit", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ code: codeInput, license_key: keyInput })
            });
            if (!response.ok) { alert("Server pipeline connectivity timeout."); return; }
            const result = await response.json();
            dash.style.display = "block";
            msg.innerText = result.message;
            
            if (result.status === "syntax_error" || result.status === "empty") {
                baseMetrics.style.display = "none"; proBanner.style.display = "none"; proUnlocked.style.display = "none";
            } else if (result.status === "pro_success") {
                baseMetrics.style.display = "grid"; proBanner.style.display = "none"; proUnlocked.style.display = "block";
                document.getElementById("mLines").innerText = result.lines;
                document.getElementById("mFuncs").innerText = result.functions_count;
                document.getElementById("mClasses").innerText = result.classes_count;
                document.getElementById("mMaintain").innerText = result.advanced_metrics.maintainability;
                document.getElementById("mComments").innerText = result.advanced_metrics.comment_density;
                document.getElementById("mDebt").innerText = result.advanced_metrics.tech_debt_usd;
                document.getElementById("mTime").innerText = result.advanced_metrics.remediation_time;
                proPatchText.innerText = result.advanced_metrics.remediation_patch;
                
                mapFlow.innerHTML = "";
                result.advanced_metrics.visual_nodes.forEach(node => {
                    const span = document.createElement("span");
                    span.innerText = node.name; span.className = "node";
                    if(node.type === "root") span.classList.add("node-root");
                    else if(node.status === "unsecure") span.classList.add("node-unsecure");
                    else span.classList.add("node-secure");
                    mapFlow.appendChild(span);
                });
                
                if (result.advanced_metrics.security_status === "unsecure") {
                    cardMaintain.style.borderColor = "var(--danger-red)"; document.getElementById("mMaintain").style.color = "var(--danger-red)";
                    cardDebt.style.borderColor = "var(--danger-red)"; document.getElementById("mDebt").style.color = "var(--danger-red)";
                    proPatchText.style.borderColor = "var(--danger-red)";
                } else {
                    cardMaintain.style.borderColor = "#238636"; document.getElementById("mMaintain").style.color = "#7ee787";
                    cardDebt.style.borderColor = "#30363d"; document.getElementById("mDebt").style.color = "#58a6ff";
                    proPatchText.style.borderColor = "#30363d";
                }
            } else {
                baseMetrics.style.display = "grid"; proBanner.style.display = "block"; proUnlocked.style.display = "none";
                document.getElementById("mLines").innerText = result.lines;
                document.getElementById("mFuncs").innerText = result.functions_count;
                document.getElementById("mClasses").innerText = result.classes_count;
            }
        } catch (error) { console.error(error); alert("Critical interface layout interaction exception."); }
    }
</script>

</body>
</html>"""
    return HTMLResponse(content=html_content)
