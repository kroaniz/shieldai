import ast
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

app = FastAPI(title="Python Code Insight Platform")

# Описываем структуру данных, которую бэкенд принимает от браузера
class CodeRequest(BaseModel):
    code: str

# API-маршрут для реального анализа синтаксиса
@app.post("/api/analyze")
async def analyze_code(data: CodeRequest):
    source_code = data.code
    if not source_code.strip():
        return {
            "status": "warning",
            "message": "Код для проверки не введен. Пожалуйста, вставьте скрипт Python.",
            "lines": 0,
            "functions": 0,
            "classes": 0
        }
    
    try:
        # Анализируем код с помощью встроенного абстрактного синтаксического дерева Python
        tree = ast.parse(source_code)
        
        lines_count = len(source_code.splitlines())
        functions_count = sum(1 for node in ast.walk(tree) if isinstance(node, ast.FunctionDef))
        classes_count = sum(1 for node in ast.walk(tree) if isinstance(node, ast.ClassDef))
        
        return {
            "status": "success",
            "message": "Анализ успешно завершен: синтаксис корректен, критических структурных ошибок не обнаружено.",
            "lines": lines_count,
            "functions": functions_count,
            "classes": classes_count
        }
    except SyntaxError as e:
        # Если в коде пользователя есть синтаксическая ошибка, возвращаем информацию о ней
        return {
            "status": "error",
            "message": f"Найден дефект синтаксиса! Строка {e.lineno}: {e.msg}",
            "lines": 0,
            "functions": 0,
            "classes": 0
        }

# Главная страница, отдающая чистый и современный HTML-интерфейс
@app.get("/", response_class=HTMLResponse)
async def get_home():
    html_content = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodeInsight // Анализатор Python Кода</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --panel-bg: #161b22;
            --accent-color: #238636;
            --accent-hover: #2ea043;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --border-color: #30363d;
            --danger: #f85149;
            --success: #58a6ff;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 40px 20px;
        }
        .container {
            max-width: 800px;
            background-color: var(--panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 40px;
            margin: 0 auto;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        }
        h1 { color: #fff; text-align: center; margin-bottom: 5px; font-weight: 600; }
        p.subtitle { text-align: center; color: var(--text-muted); margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 25px; }
        label { display: block; font-weight: 500; margin-bottom: 8px; color: #fff; font-size: 14px; }
        textarea {
            width: 100%;
            height: 200px;
            background-color: var(--bg-color);
            border: 1px solid var(--border-color);
            color: var(--text-main);
            padding: 14px;
            border-radius: 6px;
            box-sizing: border-box;
            font-family: 'Courier New', Courier, monospace;
            font-size: 14px;
            resize: vertical;
        }
        button {
            width: 100%;
            background-color: var(--accent-color);
            color: white;
            border: none;
            padding: 16px;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        button:hover { background-color: var(--accent-hover); }
        .result-box {
            margin-top: 30px;
            padding: 25px;
            background-color: #1f242c;
            border-radius: 8px;
            border-left: 4px solid var(--success);
            display: none;
            text-align: left;
        }
        .result-box.error-state {
            border-left-color: var(--danger);
            background-color: #251e22;
        }
        .metric-group {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 15px;
            margin-top: 20px;
        }
        .metric-card {
            background-color: var(--bg-color);
            border: 1px solid var(--border-color);
            padding: 15px;
            border-radius: 6px;
            text-align: center;
        }
        .metric-val {
            font-size: 24px;
            font-weight: bold;
            color: #fff;
        }
        .metric-lbl {
            font-size: 12px;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-top: 5px;
        }
    </style>
</head>
<body>

<div class="container">
    <h1>CodeInsight 🛡️</h1>
    <p class="subtitle">Профессиональный статический анализ и аудит структуры Python-кода</p>
    
    <div class="form-group">
        <label>Исходный код скрипта для проверки</label>
        <textarea id="codeArea" placeholder="import os\n\ndef check_status():\n    print('Сервер активен')"></textarea>
    </div>
    
    <button onclick="analyzePythonCode()">Запустить аудит инфраструктуры</button>
    
    <div id="resPanel" class="result-box">
        <h3 style="margin-top: 0; color: #fff;">Отчет парсера:</h3>
        <p id="resMsg" style="line-height: 1.5; font-size: 15px;"></p>
        
        <div id="metricsBlock" class="metric-group">
            <div class="metric-card">
                <div id="valLines" class="metric-val">0</div>
                <div class="metric-lbl">Строк кода</div>
            </div>
            <div class="metric-card">
                <div id="valFuncs" class="metric-val">0</div>
                <div class="metric-lbl">Функции (def)</div>
            </div>
            <div class="metric-card">
                <div id="valClasses" class="metric-val">0</div>
                <div class="metric-lbl">Классы (class)</div>
            </div>
        </div>
    </div>
</div>

<script>
    async function analyzePythonCode() {
        const codeContent = document.getElementById("codeArea").value;
        const panel = document.getElementById("resPanel");
        const msg = document.getElementById("resMsg");
        const metrics = document.getElementById("metricsBlock");
        
        try {
            const response = await fetch("/api/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ code: codeContent })
            });
            
            if (!response.ok) {
                alert("Не удалось получить корректный ответ от бэкенда.");
                return;
            }
            
            const data = await response.json();
            panel.style.display = "block";
            msg.innerText = data.message;
            
            if (data.status === "error") {
                panel.classList.add("error-state");
                metrics.style.display = "none";
            } else {
                panel.classList.remove("error-state");
                metrics.style.display = "grid";
                document.getElementById("valLines").innerText = data.lines;
                document.getElementById("valFuncs").innerText = data.functions;
                document.getElementById("valClasses").innerText = data.classes;
            }
        } catch (e) {
            console.error(e);
            alert("Произошла критическая ошибка на стороне клиента.");
        }
    }
</script>

</body>
</html>"""
    return HTMLResponse(content=html_content)
