import ast
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="CodeInsight Pro Platform")

# Secret key to activate Pro features
PRO_LICENSE_KEY = "PRO_PREMIUM_TOKEN_2026"

class AuditRequest(BaseModel):
    code: str
    license_key: str = ""

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
        # Базовый парсинг структуры кода через AST
        tree = ast.parse(source_code)
        raw_lines = source_code.splitlines()
        lines_count = len(raw_lines)
        
        functions = [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        classes = [node.name for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
        
        # Подсчет комментариев (для Pro-аналитики)
        comment_lines = 0
        for line in raw_lines:
            if line.strip().startswith("#"):
                comment_lines += 1
                
        response_data = {
            "status": "demo_success",
            "lines": lines_count,
            "functions_count": len(functions),
            "classes_count": len(classes),
            "message": "Basic structural audit completed successfully. Syntax is valid, no compilation errors found."
        }
        
        # Расширенный коммерческий функционал (Активируется по ключу)
        if user_key == PRO_LICENSE_KEY:
            # Вычисляем плотность комментариев в процентах
            comment_density = round((comment_lines / lines_count) * 100) if lines_count > 0 else 0
            
            # Динамическая генерация архитектурных рекомендаций на основе реального кода
            if lines_count > 25 and len(functions) <= 1:
                patch_advice = (
                    "## High Complexity Detected:\\n"
                    "Your script contains a large block of monolithic code. "
                    "Pro Recommendation: Break down your logic into distinct modular functions "
                    "to lower cognitive load and improve testability."
                )
                maintainability = "Fair"
            elif lines_count == 0:
                patch_advice = "## Empty File:\\nNo structural patterns could be verified."
                maintainability = "N/A"
            else:
                patch_advice = (
                    "## Architecture Standard Compliant:\\n"
                    "Code syntax density and function-to-line ratio are well balanced. "
                    "No immediate architectural refactoring required."
                )
                maintainability = "Excellent"

            response_data["status"] = "pro_success"
            response_data["message"] = "PRO Mode successfully activated. Advanced structural metrics generated."
            response_data["advanced_metrics"] = {
                "maintainability": maintainability,
                "comment_density": f"{comment_density}%",
                "remediation_patch": patch_advice
            }
        
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
            --accent-gold: #d29922;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background-color: var(--bg-dark);
            color: var(--text-main);
            margin: 0;
            padding: 40px 20px;
        }
        .container {
            max-width: 850px;
            background-color: var(--panel-dark);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 40px;
            margin: 0 auto;
            box-shadow: 0 8px 24px rgba(0,0,0,0.6);
        }
        h1 { color: #fff; text-align: center; margin-top: 0; font-weight: 600; }
        p.desc { text-align: center; color: var(--text-muted); margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #fff; font-size: 14px; font-weight: 500; }
        textarea {
            width: 100%; height: 180px; background-color: var(--bg-dark);
            border: 1px solid var(--border-color); color: var(--text-main);
            padding: 14px; border-radius: 6px; box-sizing: border-box;
            font-family: monospace; font-size: 14px; resize: vertical;
        }
        input[type="text"] {
            width: 100%; padding: 12px; background-color: var(--bg-dark);
            border: 1px solid var(--border-color); color: var(--text-main);
            border-radius: 6px; box-sizing: border-box; font-family: monospace;
        }
        .actions { display: grid; grid-template-columns: 1fr; gap: 15px; margin-top: 15px; }
        button {
            padding: 15px; border: none; border-radius: 6px; font-size: 16px;
            font-weight: 600; cursor: pointer; color: #fff; transition: background-color 0.2s;
        }
        .btn-audit { background-color: var(--btn-green); }
        .btn-audit:hover { background-color: var(--btn-green-hover); }
        .dashboard {
            margin-top: 30px; padding: 25px; background-color: #1f242c;
            border-radius: 8px; border-left: 4px solid var(--btn-blue); display: none;
        }
        .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }
        .card { background-color: var(--bg-dark); border: 1px solid var(--border-color); padding: 15px; border-radius: 6px; text-align: center; }
        .card-num { font-size: 22px; font-weight: bold; color: #fff; }
        .card-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; }
        .pro-banner {
            background-color: rgba(210, 153, 34, 0.1); border: 1px solid var(--accent-gold);
            padding: 20px; border-radius: 8px; margin-top: 20px; text-align: center;
        }
        .pro-unlocked {
            background-color: rgba(35, 134, 54, 0.1); border: 1px solid var(--btn-green);
            padding: 20px; border-radius: 8px; margin-top: 20px; display: none;
        }
    </style>
</head>
<body>

<div class="container">
    <h1>CodeInsight Platform</h1>
    <p class="desc">Professional Static Structure Analysis and Application Metrics Audit Tool</p>
    
    <div class="form-group">
        <label>Pro License Key (Leave blank for Demo Mode)</label>
        <input type="text" id="licenseKey" placeholder="Enter your premium access token...">
    </div>

    <div class="form-group">
        <label>Source Code for Analysis (Python)</label>
        <textarea id="codeBody" placeholder="def calculate_total(price, tax):\n    return price + tax"></textarea>
    </div>
    
    <div class="actions">
        <button class="btn-audit" onclick="requestAnalysis()">Launch Infrastructure Scan</button>
    </div>

    <div id="dashBlock" class="dashboard">
        <h3 style="margin-top: 0; color: #fff;">Audit Report Summary:</h3>
        <p id="statusMsg"></p>
        
        <div id="baseMetrics" class="metrics">
            <div class="card"><div id="mLines" class="card-num">0</div><div class="card-label">Lines of Code</div></div>
            <div class="card"><div id="mFuncs" class="card-num">0</div><div class="card-label">Functions Found</div></div>
            <div class="card"><div id="mClasses" class="card-num">0</div><div class="card-label">Classes Defined</div></div>
        </div>

        <div id="proBanner" class="pro-banner">
            <h4 style="margin-top: 0; color: var(--accent-gold);">🔒 Advanced Pro Metrics Available</h4>
            <p style="font-size: 13px; margin-bottom: 0;">Automated architecture remediation recommendations, maintainability index, and compliance logs are exclusive to active Pro License holders.</p>
        </div>

        <div id="proUnlocked" class="pro-unlocked">
            <h4 style="margin-top: 0; color: #7ee787;">⚡ Pro Analytics & Infrastructure Package Unlocked</h4>
            <div class="metrics" style="margin-bottom: 20px;">
                <div class="card" style="border-color: #238636;"><div id="mMaintain" class="card-num" style="color: #7ee787;">N/A</div><div class="card-label">Maintainability</div></div>
                <div class="card" style="border-color: #238636;"><div id="mComments" class="card-num" style="color: #7ee787;">0%</div><div class="card-label">Comment Density</div></div>
            </div>
            <pre id="proPatchText" style="white-space: pre-wrap; font-family: monospace; text-align: left; font-size: 13px; color: #7ee787; background: #0d1117; padding: 15px; border-radius: 6px; border: 1px solid #30363d;"></pre>
        </div>
    </div>
</div>

<script>
    async function requestAnalysis() {
        const codeInput = document.getElementById("codeBody").value;
        const keyInput = document.getElementById("licenseKey").value;
        
        const dash = document.getElementById("dashBlock");
        const msg = document.getElementById("statusMsg");
        const baseMetrics = document.getElementById("baseMetrics");
        const proBanner = document.getElementById("proBanner");
        const proUnlocked = document.getElementById("proUnlocked");
        
        try {
            const response = await fetch("/api/v1/audit", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ code: codeInput, license_key: keyInput })
            });
            
            if (!response.ok) {
                alert("Server connection error during processing.");
                return;
            }
            
            const result = await response.json();
            dash.style.display = "block";
            msg.innerText = result.message;
            
            if (result.status === "syntax_error" || result.status === "empty") {
                baseMetrics.style.display = "none";
                proBanner.style.display = "none";
                proUnlocked.style.display = "none";
            } else if (result.status === "pro_success") {
                baseMetrics.style.display = "grid";
                proBanner.style.display = "none";
                proUnlocked.style.display = "block";
                
                document.getElementById("mLines").innerText = result.lines;
                document.getElementById("mFuncs").innerText = result.functions_count;
                document.getElementById("mClasses").innerText = result.classes_count;
                
                // Дополнительные Pro-метрики
                document.getElementById("mMaintain").innerText = result.advanced_metrics.maintainability;
                document.getElementById("mComments").innerText = result.advanced_metrics.comment_density;
                document.getElementById("proPatchText").innerText = result.advanced_metrics.remediation_patch;
            } else {
                baseMetrics.style.display = "grid";
                proBanner.style.display = "block";
                proUnlocked.style.display = "none";
                
                document.getElementById("mLines").innerText = result.lines;
                document.getElementById("mFuncs").innerText = result.functions_count;
                document.getElementById("mClasses").innerText = result.classes_count;
            }
        } catch (error) {
            console.error(error);
            alert("Critical client-side routing exception occurred.");
        }
    }
</script>

</body>
</html>"""
    return HTMLResponse(content=html_content)
