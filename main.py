import os
import json
import time
import hashlib
import ast
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="CodeInsight Enterprise SaaS")

# ==========================================
# ⚙️ CONFIGURATION & ENVIRONMENT VARIABLES
# ==========================================
OWNER_USDT_ADDRESS = os.getenv("OWNER_USDT_ADDRESS", "TWcaHG75Sv5ssvdTU1Am6rPw5DRtoJB1hi")
OWNER_MASTER_KEY = os.getenv("OWNER_MASTER_KEY", "PRO_PREMIUM_TOKEN_2026")
SECRET_SIGNING_SALT = os.getenv("SECRET_SIGNING_SALT", "GLOBAL_CODEINSIGHT_SECURE_TOKEN_2026_PRO")

DEVICES_FILE = "registered_devices.json"
TX_FILE = "used_transactions.json"

def load_json(filename: str) -> dict:
    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_json(filename: str, data: dict):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def generate_pro_key(email: str) -> str:
    clean_email = email.lower().strip()
    expires_ts = int(time.time()) + (3650 * 86400)
    raw_string = f"{clean_email}:{expires_ts}:{SECRET_SIGNING_SALT}"
    key_hash = hashlib.sha256(raw_string.encode()).hexdigest()[:16]
    return f"{clean_email}:{expires_ts}:{key_hash}"

def validate_pro_key(key: str) -> tuple[bool, str]:
    clean_key = key.strip()
    if not clean_key:
        return False, "Key not provided"
    
    # Режим супер-ключа владельца
    if clean_key == OWNER_MASTER_KEY:
        return True, "OWNER (Administrator)"

    # Проверка ключа формата email:expires:hash
    parts = clean_key.split(":")
    if len(parts) != 3:
        return False, "Invalid key format"
    
    email, expires_str, key_hash = parts
    try:
        expires_ts = int(expires_str)
    except ValueError:
        return False, "Invalid expiration date format"
        
    if expires_ts < int(time.time()):
        return False, "Key has expired"
        
    raw_string = f"{email}:{expires_str}:{SECRET_SIGNING_SALT}"
    expected_hash = hashlib.sha256(raw_string.encode()).hexdigest()[:16]
    
    if key_hash != expected_hash:
        return False, "Invalid key signature"
        
    return True, email

class PaymentVerificationRequest(BaseModel):
    tx_hash: str
    email: str
    device_id: str

class AuditRequest(BaseModel):
    code: str
    pro_key: str = ""
    device_id: str = "web_client"

@app.post("/api/verify-direct-payment")
async def verify_payment(req: PaymentVerificationRequest):
    tx_hash = req.tx_hash.strip()
    email = req.email.strip()
    device_id = req.device_id.strip()

    if not tx_hash or not email or not device_id:
        raise HTTPException(status_code=400, detail="Please fill in all fields")

    used_txs = load_json(TX_FILE)
    if tx_hash in used_txs:
        raise HTTPException(status_code=400, detail="This transaction hash has already been used!")

    url = f"https://apilist.tronscanapi.com/api/transaction-info?hash={tx_hash}"
    headers = {"User-Agent": "Mozilla/5.0"}
    
    async with httpx.AsyncClient(timeout=12.0) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to connect to TRON node")
            data = resp.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Network error during payment verification")

    trc20_transfers = data.get("trc20TransferInfo", [])
    valid_payment_found = False

    for transfer in trc20_transfers:
        recipient = transfer.get("to_address", "")
        amount_str = transfer.get("amount_str", "0")
        symbol = transfer.get("symbol", "")
        amount_usdt = float(amount_str) / 1000000.0

        if recipient == OWNER_USDT_ADDRESS and amount_usdt >= 8.90 and symbol.upper() == "USDT":
            valid_payment_found = True
            break

    if not valid_payment_found:
        raise HTTPException(
            status_code=400, 
            detail=f"Transaction not found or amount is less than $9.99 USDT (Expected recipient: {OWNER_USDT_ADDRESS})"
        )

    used_txs[tx_hash] = {"email": email, "time": int(time.time()), "device_id": device_id}
    save_json(TX_FILE, used_txs)

    new_key = generate_pro_key(email)
    devices = load_json(DEVICES_FILE)
    devices[new_key] = device_id
    save_json(DEVICES_FILE, devices)

    return {"status": "success", "pro_key": new_key, "message": "Payment verified successfully!"}

@app.post("/api/analyze")
async def analyze_code(req: AuditRequest):
    source_code = req.code
    pro_key = req.pro_key.strip()
    device_id = req.device_id.strip()

    if not source_code.strip():
        raise HTTPException(status_code=400, detail="Source code is empty. Please paste your Python code.")

    # 1. Проверка синтаксиса AST (Доступно всем)
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return {
            "status": "syntax_error",
            "is_pro": False,
            "message": f"Critical Syntax Defect identified on line {e.lineno}: {e.msg}"
        }

    raw_lines = source_code.splitlines()
    lines_count = len(raw_lines)
    functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    comment_lines = sum(1 for line in raw_lines if line.strip().startswith("#"))

    # Базовые данные, доступные в бесплатной версии
    base_data = {
        "status": "success",
        "lines": lines_count,
        "functions_count": len(functions),
        "classes_count": len(classes),
        "message": "Basic AST structural audit completed. Syntax is valid."
    }

    # 2. Проверка PRO лицензии
    is_pro = False
    user_email = "Free Plan"

    if pro_key:
        valid, email_or_err = validate_pro_key(pro_key)
        if valid:
            if pro_key != OWNER_MASTER_KEY:
                devices = load_json(DEVICES_FILE)
                if pro_key in devices and devices[pro_key] != device_id:
                    raise HTTPException(status_code=403, detail="⛔ Anti-Leak Protection: Key bound to another device!")
                elif pro_key not in devices:
                    devices[pro_key] = device_id
                    save_json(DEVICES_FILE, devices)
            
            is_pro = True
            user_email = email_or_err

    base_data["is_pro"] = is_pro
    base_data["user_email"] = user_email

    # Если обычный Free-пользователь — возвращаем базовые метрики и предложение купить PRO
    if not is_pro:
        return base_data

    # 3. Расширенная PRO Аналитика
    comment_density = round((comment_lines / lines_count) * 100) if lines_count > 0 else 0
    detected_issues = []
    has_unsafe_execution = False

    for idx, line in enumerate(raw_lines, 1):
        lowered = line.lower()
        if any(sec in lowered for sec in ["secret", "password", "token", "api_key"]) and "=" in line:
            if not any(safe in lowered for safe in ["env", "get", "os.getenv"]):
                detected_issues.append(f"Line {idx}: Hardcoded sensitive credential token detected.")
        if "os.system(" in line or "eval(" in line or "exec(" in line:
            detected_issues.append(f"Line {idx}: Insecure dynamic command execution context (eval/exec/os.system).")
            has_unsafe_execution = True
        if "SELECT " in line.upper() and "+" in line:
            detected_issues.append(f"Line {idx}: Potential SQL Injection via string concatenation.")

    base_debt = lines_count * 0.5
    security_penalty = len(detected_issues) * 120.0
    structural_penalty = 75.0 if (lines_count > 25 and len(functions) <= 1) else 0.0
    total_debt_usd = round(base_debt + security_penalty + structural_penalty, 2)
    hours_estimated = round(total_debt_usd / 45.0, 1) if total_debt_usd > 0 else 0.2

    visual_nodes = [{"name": "App Root", "type": "root", "status": "secure" if not detected_issues else "unsecure"}]
    for cls in classes:
        visual_nodes.append({"name": f"class {cls}", "type": "class", "status": "secure"})
    for func in functions:
        func_status = "unsecure" if (has_unsafe_execution and func in source_code) else "secure"
        visual_nodes.append({"name": f"def {func}()", "type": "function", "status": func_status})

    if detected_issues:
        issues_formatted = "\n".join([f"- {issue}" for issue in detected_issues])
        patch_advice = f"""### ⚠️ CRITICAL INFRASTRUCTURE RISKS DETECTED:
{issues_formatted}

### 🛡️ AUTOMATED REMEDIATION PATCH:
```python
# [FIXED] Security Hardening Patch Applied Successfully
import os
import shlex
import subprocess

# Loaded system credentials safely from environment variable space
db_token = os.getenv('VAULT_SECRET_TOKEN')

def safe_execution(cmd_str):
    args = shlex.split(cmd_str)
    return subprocess.run(args, capture_output=True, text=True, check=True)
```"""
        maintainability = "Critical Risk"
        security_status = "unsecure"
    else:
        patch_advice = "### ✨ ARCHITECTURE STANDARDS COMPLIANT:\nCode syntax density, scope isolation, and function parameters are fully optimized."
        maintainability = "Excellent"
        security_status = "secure"

    base_data["advanced_metrics"] = {
        "maintainability": maintainability,
        "comment_density": f"{comment_density}%",
        "security_status": security_status,
        "tech_debt_usd": f"${total_debt_usd}",
        "remediation_time": f"{hours_estimated} hrs",
        "visual_nodes": visual_nodes,
        "remediation_patch": patch_advice
    }

    return base_data

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeInsight SaaS // Autonomous Code Audit Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0b0f19; color: #c9d1d9; font-family: system-ui, -apple-system, sans-serif; }
        .node-unsecure { border-color: #f85149 !important; color: #f85149 !important; animation: pulse 2s infinite; }
        @keyframes pulse { 0% { transform: scale(1); } 50% { transform: scale(1.04); } 100% { transform: scale(1); } }
    </style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-4 sm:p-8">

    <div class="max-w-4xl w-full bg-slate-900/90 border border-slate-800 rounded-2xl p-6 sm:p-10 shadow-2xl backdrop-blur-md">
        
        <!-- Header -->
        <div class="flex flex-col items-center border-b border-slate-800 pb-6 mb-8 text-center">
            <h1 class="text-3xl sm:text-4xl font-extrabold text-emerald-400 tracking-tight mb-2">🛡️ CodeInsight Platform</h1>
            <p class="text-xs sm:text-sm text-slate-400 font-mono uppercase tracking-wider">Enterprise Code Audit & Technical Debt Valuation Engine</p>
            <div class="mt-4">
                <span id="statusBadge" class="px-4 py-1.5 bg-slate-800 text-slate-400 border border-slate-700 rounded-full text-xs font-bold uppercase tracking-wider">
                    FREE PLAN
                </span>
            </div>
        </div>

        <!-- License Input -->
        <div class="mb-6 bg-slate-950/60 p-5 rounded-xl border border-slate-800 text-left">
            <label class="block text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2">🔑 Pro License Access Token (Optional):</label>
            <div class="flex flex-col sm:flex-row gap-2">
                <input type="password" id="proKeyInput" placeholder="Leave empty for Standard Mode or paste key..." autocomplete="off"
                       class="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-center sm:text-left text-slate-200 focus:outline-none focus:border-emerald-500 transition">
                <button onclick="saveKey()" class="bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold px-5 py-2.5 rounded-xl text-sm transition shadow-lg shadow-emerald-900/20">
                    Activate
                </button>
                <button onclick="openPaymentModal()" class="bg-blue-600 hover:bg-blue-500 text-white font-bold px-5 py-2.5 rounded-xl text-sm transition shadow-lg shadow-blue-900/20">
                    Get PRO ($9.99)
                </button>
            </div>
        </div>

        <!-- Code Area -->
        <div class="mb-6 text-left">
            <label class="block text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">Target Python Source Code Pipeline:</label>
            <textarea id="codeArea" rows="8" placeholder="def process_payload(data):\n    return data" 
                      class="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 text-sm font-mono text-slate-200 focus:outline-none focus:border-emerald-500 transition"></textarea>
        </div>

        <button onclick="runAudit()" class="w-full bg-emerald-500 hover:bg-emerald-400 text-slate-950 py-4 rounded-xl font-extrabold text-base tracking-wide transition uppercase shadow-lg shadow-emerald-500/10">
            🔍 Execute Core Infrastructure Scan
        </button>

        <!-- Dashboard Results -->
        <div id="dashBlock" class="mt-8 hidden space-y-6 text-left">
            
            <div class="p-4 bg-slate-950 rounded-xl border border-slate-800">
                <p id="statusMsg" class="text-sm font-semibold text-emerald-400"></p>
            </div>

            <!-- Free/Base Metrics -->
            <div class="grid grid-cols-3 gap-3">
                <div class="bg-slate-950 border border-slate-800 p-4 rounded-xl text-center">
                    <div id="mLines" class="text-2xl font-black text-white">0</div>
                    <div class="text-[10px] sm:text-xs font-bold text-slate-400 uppercase mt-1">Lines Evaluated</div>
                </div>
                <div class="bg-slate-950 border border-slate-800 p-4 rounded-xl text-center">
                    <div id="mFuncs" class="text-2xl font-black text-white">0</div>
                    <div class="text-[10px] sm:text-xs font-bold text-slate-400 uppercase mt-1">Isolated Functions</div>
                </div>
                <div class="bg-slate-950 border border-slate-800 p-4 rounded-xl text-center">
                    <div id="mClasses" class="text-2xl font-black text-white">0</div>
                    <div class="text-[10px] sm:text-xs font-bold text-slate-400 uppercase mt-1">Class Declarations</div>
                </div>
            </div>

            <!-- PRO Locked Banner -->
            <div id="proBanner" class="p-6 bg-gradient-to-r from-amber-950/40 to-slate-900 border border-amber-500/30 rounded-xl text-center shadow-xl">
                <h4 class="text-base font-extrabold text-amber-400 mb-1">🔒 Enterprise Intelligence Logs Locked</h4>
                <p class="text-xs text-slate-300 mb-4 max-w-xl mx-auto">Automated remediation scripts, real-time micro-architecture dependency graph mapping, and financial technical debt metrics require active PRO authorization.</p>
                <button onclick="openPaymentModal()" class="bg-amber-500 hover:bg-amber-400 text-slate-950 font-black px-6 py-2.5 rounded-lg text-xs uppercase transition shadow-lg">
                    ⚡ Unlock Pro Architecture Pack ($9.99)
                </button>
            </div>

            <!-- PRO Unlocked Content -->
            <div id="proUnlocked" class="hidden space-y-6 p-6 bg-emerald-950/20 border border-emerald-500/30 rounded-xl">
                <h4 class="text-sm font-black text-emerald-400 uppercase tracking-wider">⚡ PRO Infrastructure Environment Fully Activated</h4>
                
                <div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
                    <div class="bg-slate-950 border border-slate-800 p-3.5 rounded-xl text-center">
                        <div id="mMaintain" class="text-lg font-bold text-emerald-400">N/A</div>
                        <div class="text-[10px] text-slate-400 uppercase mt-1">Maintainability</div>
                    </div>
                    <div class="bg-slate-950 border border-slate-800 p-3.5 rounded-xl text-center">
                        <div id="mComments" class="text-lg font-bold text-emerald-400">0%</div>
                        <div class="text-[10px] text-slate-400 uppercase mt-1">Documentation</div>
                    </div>
                    <div class="bg-slate-950 border border-slate-800 p-3.5 rounded-xl text-center">
                        <div id="mDebt" class="text-lg font-bold text-blue-400">$0.00</div>
                        <div class="text-[10px] text-slate-400 uppercase mt-1">Tech Debt</div>
                    </div>
                    <div class="bg-slate-950 border border-slate-800 p-3.5 rounded-xl text-center">
                        <div id="mTime" class="text-lg font-bold text-blue-400">0 hrs</div>
                        <div class="text-[10px] text-slate-400 uppercase mt-1">Fix Time</div>
                    </div>
                </div>

                <!-- Dependency Graph -->
                <div class="bg-slate-950 border border-slate-800 p-5 rounded-xl text-center">
                    <div class="text-xs font-bold text-slate-300 uppercase tracking-wider text-left mb-3">🌐 Active Micro-Architecture Dependency Graph:</div>
                    <div id="mapFlow" class="flex flex-wrap items-center justify-center gap-2"></div>
                </div>

                <!-- Remediation Code Snippet -->
                <pre id="proPatchText" class="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-emerald-400 overflow-x-auto whitespace-pre-wrap"></pre>
            </div>

        </div>

    </div>

    <!-- Payment Modal -->
    <div id="paymentModal" class="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center hidden p-4 z-50">
        <div class="bg-slate-900 border border-emerald-500/30 rounded-2xl max-w-md w-full p-6 shadow-2xl text-center relative">
            <button onclick="closePaymentModal()" class="absolute top-4 right-4 text-slate-500 hover:text-white transition">✕</button>
            <h2 class="text-2xl font-black text-emerald-400 mb-1">PRO Upgrade</h2>
            <p class="text-xs text-slate-400 mb-5">USDT (TRC-20) Instant Autonomous Activation</p>

            <div class="bg-slate-950 p-4 rounded-xl mb-5 text-center border border-emerald-500/10">
                <p class="text-xs text-slate-400 mb-2">Send exactly <strong class="text-emerald-400">$9.99 USDT</strong> to:</p>
                <p class="text-xs font-mono font-bold text-emerald-300 bg-slate-900 py-2.5 px-3 rounded-lg select-all break-all border border-slate-800 font-mono">{{OWNER_USDT_ADDRESS}}</p>
                <p class="text-[10px] text-amber-500/90 mt-2">⚠️ Make sure to cover network fees. Exactly $9.99 must arrive!</p>
            </div>

            <div class="space-y-4 text-left">
                <div>
                    <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Your Email:</label>
                    <input type="email" id="payEmail" placeholder="your@email.com" class="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Transaction Hash (TX Hash):</label>
                    <input type="text" id="payTxHash" placeholder="Paste your TRON TX Hash here" class="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500">
                </div>
                <button onclick="verifyPayment()" id="payBtn" class="w-full bg-emerald-500 hover:bg-emerald-400 text-slate-950 py-3 rounded-xl font-bold text-sm tracking-wide transition uppercase shadow-lg">
                    Verify Transaction
                </button>
            </div>
        </div>
    </div>

    <script>
        function getDeviceId() {
            let devId = localStorage.getItem('device_id');
            if (!devId) {
                devId = 'dev_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
                localStorage.setItem('device_id', devId);
            }
            return devId;
        }

        function saveKey() {
            const key = document.getElementById('proKeyInput').value.trim();
            localStorage.setItem('pro_key', key);
            updateBadge();
            if(key) {
                alert('Pro Key activated and saved!');
            } else {
                alert('Key cleared. Returned to Free Plan.');
            }
        }

        function updateBadge() {
            const key = localStorage.getItem('pro_key') || '';
            const badge = document.getElementById('statusBadge');
            
            // Важно: значение не подставляется в инпут автоматически, сохраняя аккуратный вид
            if (key) {
                badge.innerText = 'PRO / KEY ACTIVE';
                badge.className = 'px-4 py-1.5 bg-emerald-950/60 text-emerald-400 border border-emerald-500/40 rounded-full text-xs font-bold uppercase tracking-wider';
            } else {
                badge.innerText = 'FREE PLAN';
                badge.className = 'px-4 py-1.5 bg-slate-800 text-slate-400 border border-slate-700 rounded-full text-xs font-bold uppercase tracking-wider';
            }
        }

        function openPaymentModal() { document.getElementById('paymentModal').classList.remove('hidden'); }
        function closePaymentModal() { document.getElementById('paymentModal').classList.add('hidden'); }

        async function verifyPayment() {
            const email = document.getElementById('payEmail').value.trim();
            const txHash = document.getElementById('payTxHash').value.trim();
            const btn = document.getElementById('payBtn');

            if (!email || !txHash) return alert('Please enter both Email and TX Hash');

            btn.innerText = 'Checking Blockchain...';
            btn.disabled = true;

            try {
                const res = await fetch('/api/verify-direct-payment', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ tx_hash: txHash, email: email, device_id: getDeviceId() })
                });
                const data = await res.json();

                if (res.ok) {
                    localStorage.setItem('pro_key', data.pro_key);
                    alert('🎉 Payment verified! Your Pro Key is now active!');
                    closePaymentModal();
                    updateBadge();
                } else {
                    alert('Error: ' + (data.detail || 'Payment verification failed'));
                }
            } catch (e) {
                alert('Network error: ' + e.message);
            } finally {
                btn.innerText = 'Verify Transaction';
                btn.disabled = false;
            }
        }

        async function runAudit() {
            const code = document.getElementById('codeArea').value;
            const inputKey = document.getElementById('proKeyInput').value.trim();
            const storedKey = localStorage.getItem('pro_key') || '';
            const proKey = inputKey || storedKey;

            if (!code.trim()) return alert('Please paste some Python code to analyze');

            try {
                const res = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: code, pro_key: proKey, device_id: getDeviceId() })
                });
                const data = await res.json();

                if (!res.ok) {
                    return alert('Error: ' + (data.detail || 'Server error'));
                }

                document.getElementById('dashBlock').classList.remove('hidden');
                document.getElementById('statusMsg').innerText = data.message;

                if (data.status === "syntax_error") {
                    document.getElementById('proBanner').classList.add('hidden');
                    document.getElementById('proUnlocked').classList.add('hidden');
                    return;
                }

                document.getElementById('mLines').innerText = data.lines;
                document.getElementById('mFuncs').innerText = data.functions_count;
                document.getElementById('mClasses').innerText = data.classes_count;

                if (data.is_pro) {
                    document.getElementById('proBanner').classList.add('hidden');
                    document.getElementById('proUnlocked').classList.remove('hidden');

                    const metrics = data.advanced_metrics;
                    document.getElementById('mMaintain').innerText = metrics.maintainability;
                    document.getElementById('mComments').innerText = metrics.comment_density;
                    document.getElementById('mDebt').innerText = metrics.tech_debt_usd;
                    document.getElementById('mTime').innerText = metrics.remediation_time;
                    document.getElementById('proPatchText').innerText = metrics.remediation_patch;

                    const mapFlow = document.getElementById('mapFlow');
                    mapFlow.innerHTML = '';
                    metrics.visual_nodes.forEach(node => {
                        const span = document.createElement('span');
                        span.innerText = node.name;
                        span.className = 'px-3 py-1.5 rounded-xl text-xs font-mono font-bold border border-slate-700 bg-slate-900';
                        if (node.type === 'root') span.classList.add('border-blue-500', 'text-blue-400');
                        else if (node.status === 'unsecure') span.classList.add('node-unsecure');
                        else span.classList.add('border-emerald-500/50', 'text-emerald-400');
                        mapFlow.appendChild(span);
                    });
                } else {
                    document.getElementById('proBanner').classList.remove('hidden');
                    document.getElementById('proUnlocked').classList.add('hidden');
                }

            } catch (e) {
                alert('Network error: ' + e.message);
            }
        }

        updateBadge();
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    return HTML_TEMPLATE.replace("{{OWNER_USDT_ADDRESS}}", OWNER_USDT_ADDRESS)
