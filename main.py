import os
import json
import time
import hashlib
import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="CodeInsight Anti-Leak SaaS")

# ==========================================
# ⚙️ CONFIGURATION & ENVIRONMENT VARIABLES
# ==========================================
OWNER_USDT_ADDRESS = os.getenv("OWNER_USDT_ADDRESS", "TYourTronUSDTAddressHere")
OWNER_MASTER_KEY = os.getenv("OWNER_MASTER_KEY", "SUPER_SECRET_OWNER_KEY_123")
SECRET_SIGNING_SALT = os.getenv("SECRET_SIGNING_SALT", "MY_SUPER_SALT_99")

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
    if not key:
        return False, "Key not provided"
    parts = key.split(":")
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
    device_id: str

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
    code = req.code
    pro_key = req.pro_key.strip()
    device_id = req.device_id.strip()

    is_owner = False
    is_pro = False
    user_email = "Free User"

    if pro_key and pro_key == OWNER_MASTER_KEY:
        is_owner = True
        is_pro = True
        user_email = "OWNER (Administrator)"
    elif pro_key:
        valid, email_or_err = validate_pro_key(pro_key)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Key error: {email_or_err}")
        
        devices = load_json(DEVICES_FILE)
        if pro_key in devices:
            if devices[pro_key] != device_id:
                raise HTTPException(status_code=403, detail="⛔ Anti-Leak Protection: Key bound to another device!")
        else:
            devices[pro_key] = device_id
            save_json(DEVICES_FILE, devices)
        
        is_pro = True
        user_email = email_or_err

    findings = []
    lines = code.split("\n")
    
    for idx, line in enumerate(lines, 1):
        if "eval(" in line or "exec(" in line:
            findings.append({"line": idx, "type": "CRITICAL", "msg": "Dangerous dynamic code execution found (eval/exec)"})
        if "SELECT " in line.upper() and "+" in line:
            findings.append({"line": idx, "type": "HIGH", "msg": "Potential SQL Injection via string concatenation"})
        if "api_key" in line.lower() or "secret" in line.lower():
            if "=" in line and not line.strip().startswith("#"):
                findings.append({"line": idx, "type": "MEDIUM", "msg": "Exposed API Key or plaintext secret detected"})

    if not is_pro and len(findings) > 1:
        hidden_count = len(findings) - 1
        findings = findings[:1]
    else:
        hidden_count = 0

    return {
        "status": "success",
        "user_status": "OWNER" if is_owner else ("PRO" if is_pro else "FREE"),
        "user_email": user_email,
        "total_lines_analyzed": len(lines),
        "findings": findings,
        "hidden_findings_count": hidden_count,
        "is_pro": is_pro
    }

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeInsight — Autonomous Security Audit</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style> 
        body { background-color: #0b0f19; color: #f8fafc; } 
    </style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-4">
    <div class="max-w-3xl w-full bg-slate-900 border border-emerald-500/30 rounded-2xl p-8 shadow-2xl shadow-emerald-950/20 text-center">
        
        <div class="flex flex-col items-center border-b border-slate-800 pb-6 mb-6">
            <h1 class="text-3xl font-extrabold text-emerald-400 tracking-tight mb-1">🛡️ CodeInsight SaaS</h1>
            <p class="text-xs text-emerald-500/70 font-mono tracking-wider uppercase">Autonomous Anti-Leak Vulnerability Scanner</p>
            <div class="mt-4">
                <span id="statusBadge" class="px-4 py-1.5 bg-slate-800 text-slate-400 border border-slate-700 rounded-full text-xs font-bold uppercase tracking-wider">FREE Plan</span>
            </div>
        </div>

        <div class="mb-6 bg-slate-950/60 p-5 rounded-xl border border-emerald-500/10 text-left">
            <label class="block text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2">🔑 Your Pro / Owner Key:</label>
            <div class="flex flex-col sm:flex-row gap-2">
                <input type="password" id="proKeyInput" placeholder="Enter Pro Key or Master Password" 
                       class="flex-1 bg-slate-900 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-center sm:text-left focus:outline-none focus:border-emerald-500 transition">
                <button onclick="saveKey()" class="bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold px-5 py-2.5 rounded-xl text-sm transition shadow-lg shadow-emerald-900/20">
                    Activate
                </button>
                <button onclick="openPaymentModal()" class="bg-slate-800 hover:bg-slate-700 border border-emerald-500/20 text-emerald-400 font-bold px-5 py-2.5 rounded-xl text-sm transition">
                    Get PRO ($9.99)
                </button>
            </div>
        </div>

        <div class="mb-6 text-left">
            <label class="block text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2">Source Code for Audit:</label>
            <textarea id="codeArea" rows="9" placeholder="Paste your Python source code here..." 
                      class="w-full bg-slate-950 border border-slate-700 rounded-xl p-4 text-sm font-mono focus:outline-none focus:border-emerald-500 transition"></textarea>
        </div>

        <button onclick="runAudit()" class="w-full bg-emerald-500 hover:bg-emerald-400 text-slate-950 py-3.5 rounded-xl font-extrabold text-base tracking-wide shadow-lg shadow-emerald-500/10 transition uppercase">
            🔍 Run Secure Audit
        </button>

        <div id="results" class="mt-6 hidden bg-slate-950 p-5 rounded-xl border border-slate-800 text-left">
            <h3 class="text-sm font-bold text-slate-300 uppercase tracking-wider mb-3">Audit Report:</h3>
            <div id="findingsList" class="space-y-2.5"></div>
        </div>
    </div>

    <div id="paymentModal" class="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center hidden p-4 z-50">
        <div class="bg-slate-900 border border-emerald-500/30 rounded-2xl max-w-md w-full p-6 shadow-2xl text-center relative">
            <button onclick="closePaymentModal()" class="absolute top-4 right-4 text-slate-500 hover:text-white transition">✕</button>
            <h2 class="text-2xl font-black text-emerald-400 mb-1">PRO Upgrade</h2>
            <p class="text-xs text-slate-400 mb-5">USDT (TRC-20) Instant Autonomous Activation</p>

            <div class="bg-slate-950 p-4 rounded-xl mb-5 text-center border border-emerald-500/10">
                <p class="text-xs text-slate-400 mb-2">Send exactly <strong class="text-emerald-400">$9.99 USDT</strong> to:</p>
                <p class="text-xs font-mono font-bold text-emerald-300 bg-slate-900 py-2 px-3 rounded-lg select-all break-all border border-slate-800">{{OWNER_USDT_ADDRESS}}</p>
                <p class="text-[10px] text-amber-500/90 mt-2">⚠️ If sending from an exchange, make sure to cover network fees. Exactly $9.99 must arrive!</p>
            </div>

            <div class="space-y-4 text-left">
                <div>
                    <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Your Email (for key generation):</label>
                    <input type="email" id="payEmail" placeholder="your@email.com" class="w-full bg-slate-950 border border-slate-750 rounded-lg p-2.5 text-sm focus:outline-none focus:border-emerald-500">
                </div>
                <div>
                    <label class="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">Transaction Hash (TX Hash):</label>
                    <input type="text" id="payTxHash" placeholder="Paste your TRON TX Hash here" class="w-full bg-slate-950 border border-slate-750 rounded-lg p-2.5 text-sm focus:outline-none focus:border-emerald-500">
                </div>
                <button onclick="verifyPayment()" id="payBtn" class="w-full bg-emerald-500 hover:bg-emerald-400 text-slate-950 py-3 rounded-xl font-bold text-sm tracking-wide transition uppercase">
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
            alert('Key saved locally!');
            updateBadge();
        }

        function updateBadge() {
            const key = localStorage.getItem('pro_key') || '';
            document.getElementById('proKeyInput').value = key;
            const badge = document.getElementById('statusBadge');
            if (key) {
                badge.innerText = 'PRO / KEY ACTIVE';
                badge.className = 'px-4 py-1.5 bg-emerald-950/40 text-emerald-400 border border-emerald-500/40 rounded-full text-xs font-bold uppercase tracking-wider';
            } else {
                badge.innerText = 'FREE Plan';
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
            const proKey = localStorage.getItem('pro_key') || '';

            if (!code) return alert('Please paste some code to analyze');

            try {
                const res = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: code, pro_key: proKey, device_id: getDeviceId() })
                });
                const data = await res.json();

                if (!res.ok) return alert('Error: ' + (data.detail || 'Server error'));

                const resultsDiv = document.getElementById('results');
                const findingsList = document.getElementById('findingsList');
                resultsDiv.classList.remove('hidden');
                findingsList.innerHTML = '';

                if (data.findings.length === 0) {
                    findingsList.innerHTML = '<p class="text-emerald-400 text-sm font-semibold">✅ No critical vulnerabilities detected.</p>';
                } else {
                    data.findings.forEach(f => {
                        findingsList.innerHTML += `
                            <div class="p-3 bg-slate-900 border border-slate-800 rounded-xl text-xs flex flex-col gap-1">
                                <span class="font-bold uppercase tracking-wide text-rose-400">[Line ${f.line}] [${f.type}]</span> 
                                <span class="text-slate-300">${f.msg}</span>
                            </div>
                        `;
                    });
                }

                if (data.hidden_findings_count > 0) {
                    findingsList.innerHTML += `
                        <div class="p-4 bg-amber-950/30 border border-amber-500/20 rounded-xl text-xs text-amber-400 mt-2 font-medium">
                            🔒 Bound protection: ${data.hidden_findings_count} more vulnerabilities found. Activate your PRO key to unhide the full report!
                        </div>
                    `;
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
