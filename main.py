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
    
    # Твой личный супер-ключ для тестов и демонстраций (всегда работает)
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

            # Генератор узлов для интерактивного графа зависимостей
            visual_nodes = [{"name": "App Root", "type": "root", "status": "secure" if not detected_issues else "unsecure"}]
            for cls in classes:
                visual_nodes.append({"name": f"class {cls}", "type": "class", "status": "secure"})
            for func in functions:
                func_status = "secure"
                if has_unsafe_execution and func in source_code:
                    func_status = "unsecure"
                visual_nodes.append({"name": f"def {func}()", "type": "function", "status": func_status})

            if detected_issues:
                issue_list_str = "\\n".join([f"- {issue}" for issue in detected_issues])
                
                # Формируем чистый текстовый патч безопасности в одну строку, исключая синтаксические разрывы
                patch_advice = f"### ⚠️ CRITICAL INFRASTRUCTURE RISKS DETECTED:\\n{issue_list_str}\\n\\n### 🛡️ AUTOMATED REMEDIATION PATCH:\\n
http://googleusercontent.com/immersive_entry_chip/0
