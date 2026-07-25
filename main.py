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
# ⚙️ НАСТРОЙКИ И ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ
# ==========================================
OWNER_USDT_ADDRESS = os.getenv("OWNER_USDT_ADDRESS", "TYourTronUSDTAddressHere")
OWNER_MASTER_KEY = os.getenv("OWNER_MASTER_KEY", "SUPER_SECRET_OWNER_KEY_123")
SECRET_SIGNING_SALT = os.getenv("SECRET_SIGNING_SALT", "MY_SUPER_SALT_99")

DEVICES_FILE = "registered_devices.json"
TX_FILE = "used_transactions.json"

# ==========================================
# 📂 ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ХРАНЕНИЯ
# ==========================================
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

# ==========================================
# 🔑 ГЕНЕРАЦИЯ И ВАЛИДАЦИЯ КЛЮЧЕЙ
# ==========================================
def generate_pro_key(email: str) -> str:
    clean_email = email.lower().strip()
    expires_ts = int(time.time()) + (3650 * 86400) # Ключ на 10 лет
    raw_string = f"{clean_email}:{expires_ts}:{SECRET_SIGNING_SALT}"
    key_hash = hashlib.sha256(raw_string.encode()).hexdigest()[:16]
    return f"{clean_email}:{expires_ts}:{key_hash}"

def validate_pro_key(key: str) -> tuple[bool, str]:
    if not key:
        return False, "Ключ не предоставлен"
    
    parts = key.split(":")
    if len(parts) != 3:
        return False, "Неверный формат ключа"
    
    email, expires_str, key_hash = parts
    try:
        expires_ts = int(expires_str)
    except ValueError:
        return False, "Неверный формат даты в ключе"
    
    if expires_ts < int(time.time()):
        return False, "Срок действия ключа истек"
    
    raw_string = f"{email}:{expires_ts}:{SECRET_SIGNING_SALT}"
    expected_hash = hashlib.sha256(raw_string.encode()).hexdigest()[:16]
    
    if key_hash != expected_hash:
        return False, "Подпись ключа недействительна"
    
    return True, email

# ==========================================
# 📦 МОДЕЛИ ЗАПРОСОВ (PYDANTIC)
# ==========================================
class PaymentVerificationRequest(BaseModel):
    tx_hash: str
    email: str
    device_id: str

class AuditRequest(BaseModel):
    code: str
    pro_key: str = ""
    device_id: str

# ==========================================
# 🚀 API ЭНДПОИНТЫ
# ==========================================

@app.post("/api/verify-direct-payment")
async def verify_payment(req: PaymentVerificationRequest):
    tx_hash = req.tx_hash.strip()
    email = req.email.strip()
    device_id = req.device_id.strip()

    if not tx_hash or not email or not device_id:
        raise HTTPException(status_code=400, detail="Заполните все поля")

    # 1. Проверка на повторный ввод хэша
    used_txs = load_json(TX_FILE)
    if tx_hash in used_txs:
        raise HTTPException(status_code=400, detail="Этот хэш транзакции уже был использован!")

    # 2. Запрос к TronScan API с маскировкой под браузер (User-Agent)
    url = f"https://apilist.tronscanapi.com/api/transaction-info?hash={tx_hash}"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    
    async with httpx.AsyncClient(timeout=12.0) as client:
        try:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                raise HTTPException(status_code=400, detail="Не удалось связаться с нодой TRON")
            data = resp.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Ошибка сети при проверке транзакции")

    # 3. Валидация перевода USDT
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
            detail=f"Транзакция не найдена или сумма меньше $9.99 USDT (Адрес получателя: {OWNER_USDT_ADDRESS})"
        )

    # 4. Фиксация транзакции
    used_txs[tx_hash] = {"email": email, "time": int(time.time()), "device_id": device_id}
    save_json(TX_FILE, used_txs)

    # 5. Выдача ключа и привязка к Device ID
    new_key = generate_pro_key(email)
    devices = load_json(DEVICES_FILE)
    devices[new_key] = device_id
    save_json(DEVICES_FILE, devices)

    return {"status": "success", "pro_key": new_key, "message": "Оплата успешно подтверждена!"}


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
        user_email = "OWNER (Администратор)"
    elif pro_key:
        valid, email_or_err = validate_pro_key(pro_key)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Ошибка ключа: {email_or_err}")
        
        devices = load_json(DEVICES_FILE)
        if pro_key in devices:
            if devices[pro_key] != device_id:
                raise HTTPException(
                    status_code=403, 
                    detail="⛔ Защита от слива: Этот ключ привязан к другому устройству!"
                )
        else:
            devices[pro_key] = device_id
            save_json(DEVICES_FILE, devices)
        
        is_pro = True
        user_email = email_or_err

    findings = []
    lines = code.split("\n")
    
    for idx, line in enumerate(lines, 1):
        if "eval(" in line or "exec(" in line:
            findings.append({"line": idx, "type": "CRITICAL", "msg": "Опасное выполнение динамического кода (eval/exec)"})
        if "SELECT " in line.upper() and "+" in line:
            findings.append({"line": idx, "type": "HIGH", "msg": "Возможная SQL-инъекция через конкатенацию строк"})
        if "api_key" in line.lower() or "secret" in line.lower():
            if "=" in line and not line.strip().startswith("#"):
                findings.append({"line": idx, "type": "MEDIUM", "msg": "Обнаружен открытый API ключ или секрет в коде"})

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

# ==========================================
# 🖥️ ВЕБ-ИНТЕРФЕЙС (HTML ШАБЛОН)
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeInsight — Автономный Аудит Безопасности</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #0f172a; color: #f8fafc; }
    </style>
</head>
<body class="min-h-screen flex flex-col items-center justify-center p-4">
    <div class="max-w-4xl w-full bg-slate-800 border border-slate-700 rounded-2xl p-6 shadow-2xl">
        <div class="flex justify-between items-center border-b border-slate-700 pb-4 mb-6">
            <div>
                <h1 class="text-2xl font-bold text-indigo-400">🛡️ CodeInsight SaaS</h1>
                <p class="text-xs text-slate-400">Автономный анти-лик сканер уязвимостей</p>
            </div>
            <div class="text-right">
                <span id="statusBadge" class="px-3 py-1 bg-slate-700 text-slate-300 rounded-full text-xs font-semibold">FREE Plan</span>
            </div>
        </div>

        <div class="mb-4 bg-slate-900/50 p-4 rounded-xl border border-slate-700/50">
            <label class="block text-xs font-semibold text-slate-400 mb-1">🔑 Ваш Pro / Owner Ключ:</label>
            <div class="flex gap-2">
                <input type="password" id="proKeyInput" placeholder="Вставьте ключ или Master-пароль" 
                       class="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-indigo-500">
                <button onclick="saveKey()" class="bg-indigo-600 hover:bg-indigo-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition">
                    Сохранить
                </button>
                <button onclick="openPaymentModal()" class="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-semibold transition">
                    Купить PRO ($9.99)
                </button>
            </div>
        </div>

        <div class="mb-4">
            <label class="block text-xs font-semibold text-slate-400 mb-1">Исходный код для аудита:</label>
            <textarea id="codeArea" rows="8" placeholder="Вставьте ваш Python код здесь..." 
                      class="w-full bg-slate-900 border border-slate-700 rounded-xl p-3 text-sm font-mono focus:outline-none focus:border-indigo-500"></textarea>
        </div>

        <button onclick="runAudit()" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white py-3 rounded-xl font-bold text-base shadow-lg transition">
            🔍 Запустить Безопасный Аудит
        </button>

        <div id="results" class="mt-6 hidden bg-slate-900 p-4 rounded-xl border border-slate-700">
            <h3 class="text-sm font-bold text-slate-300 mb-2">Отчет аудита:</h3>
            <div id="findingsList" class="space-y-2"></div>
        </div>
    </div>

    <div id="paymentModal" class="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center hidden p-4">
        <div class="bg-slate-800 border border-slate-700 rounded-2xl max-w-md w-full p-6 shadow-2xl relative">
            <button onclick="closePaymentModal()" class="absolute top-4 right-4 text-slate-400 hover:text-white">✕</button>
            <h2 class="text-xl font-bold text-emerald-400 mb-2">Оплата PRO через USDT (TRC-20)</h2>
            <p class="text-xs text-slate-400 mb-4">Автономная активация без посредников за 10 секунд.</p>

            <div class="bg-slate-900 p-3 rounded-xl mb-4 text-center border border-slate-700">
                <p class="text-xs text-slate-400 mb-1">Отправьте ровно <strong class="text-emerald-400">$9.99 USDT</strong> на адрес:</p>
                <p class="text-xs font-mono font-bold text-slate-200 select-all break-all">{{OWNER_USDT_ADDRESS}}</p>
                <p class="text-[10px] text-amber-400 mt-2">⚠️ При выводе с биржи учитывайте комиссию, на кошелек должно прийти не менее $9.99!</p>
            </div>

            <div class="space-y-3">
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Ваш Email (для генерации ключа):</label>
                    <input type="email" id="payEmail" placeholder="your@email.com" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm">
                </div>
                <div>
                    <label class="block text-xs text-slate-400 mb-1">Хэш транзакции (TX Hash):</label>
                    <input type="text" id="payTxHash" placeholder="Введите TX Hash из кошелька" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-2 text-sm">
                </div>
                <button onclick="verifyPayment()" id="payBtn" class="w-full bg-emerald-600 hover:bg-emerald-500 text-white py-2.5 rounded-xl font-bold text-sm transition">
                    Проверить транзакцию
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
            alert('Ключ сохранен!');
            updateBadge();
        }

        function updateBadge() {
            const key = localStorage.getItem('pro_key') || '';
            document.getElementById('proKeyInput').value = key;
            const badge = document.getElementById('statusBadge');
            if (key) {
                badge.innerText = 'PRO / KEY ACTIVE';
                badge.className = 'px-3 py-1 bg-emerald-900/50 text-emerald-400 border border-emerald-700/50 rounded-full text-xs font-semibold';
            }
        }

        function openPaymentModal() { document.getElementById('paymentModal').classList.remove('hidden'); }
        function closePaymentModal() { document.getElementById('paymentModal').classList.add('hidden'); }

        async function verifyPayment() {
            const email = document.getElementById('payEmail').value.trim();
            const txHash = document.getElementById('payTxHash').value.trim();
            const btn = document.getElementById('payBtn');

            if (!email || !txHash) return alert('Заполните Email и TX Hash');

            btn.innerText = 'Проверка в блокчейне...';
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
                    alert('🎉 Оплата подтверждена! Ваш Pro-ключ активирован!');
                    closePaymentModal();
                    updateBadge();
                } else {
                    alert('Ошибка: ' + (data.detail || 'Не удалось подтвердить платеж'));
                }
            } catch (e) {
                alert('Ошибка сети: ' + e.message);
            } finally {
                btn.innerText = 'Проверить транзакцию';
                btn.disabled = false;
            }
        }

        async function runAudit() {
            const code = document.getElementById('codeArea').value;
            const proKey = localStorage.getItem('pro_key') || '';

            if (!code) return alert('Вставьте код для анализа');

            try {
                const res = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ code: code, pro_key: proKey, device_id: getDeviceId() })
                });
                const data = await res.json();

                if (!res.ok) return alert('Ошибка: ' + (data.detail || 'Ошибка сервера'));

                const resultsDiv = document.getElementById('results');
                const findingsList = document.getElementById('findingsList');
                resultsDiv.classList.remove('hidden');
                findingsList.innerHTML = '';

                if (data.findings.length === 0) {
                    findingsList.innerHTML = '<p class="text-emerald-400 text-sm">✅ Явных критических уязвимостей не обнаружено.</p>';
                } else {
                    data.findings.forEach(f => {
                        findingsList.innerHTML += `
                            <div class="p-2.5 bg-slate-800 rounded-lg border border-slate-700 text-xs">
                                <span class="font-bold text-rose-400">[Строка ${f.line}] [${f.type}]</span> 
                                <span class="text-slate-200">${f.msg}</span>
                            </div>
                        `;
                    });
                }

                if (data.hidden_findings_count > 0) {
                    findingsList.innerHTML += `
                        <div class="p-3 bg-amber-950/40 border border-amber-800/50 rounded-lg text-xs text-amber-300 mt-2">
                            🔒 Найдено еще ${data.hidden_findings_count} уязвимостей. Активируйте PRO ключ, чтобы раскрыть полный отчет!
                        </div>
                    `;
                }
            } catch (e) {
                alert('Ошибка сети: ' + e.message);
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
