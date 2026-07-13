import os
import re
import json
import base64
import asyncio
import aiohttp
import discord
from fastapi import FastAPI, HTTPException # type: ignore
from pydantic import BaseModel
from dotenv import load_dotenv # type: ignore

# Загрузка переменных окружения
load_dotenv()
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Настройки файлов
DB_FILE = "threats.json"
CONFIG_FILE = "config.json"

# Инициализация хранилищ
if not os.path.exists(DB_FILE):
    with open(DB_FILE, "w") as f: json.dump([], f)
if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w") as f: 
        json.dump({"delete_all_links": False, "mrtp_enabled": True, "block_all_messages": False}, f)

def load_db():
    with open(DB_FILE, "r") as f: return json.load(f)

def save_db(data):
    with open(DB_FILE, "w") as f: json.dump(data, f, indent=4)

def load_config():
    with open(CONFIG_FILE, "r") as f: return json.load(f)

def save_config(data):
    with open(CONFIG_FILE, "w") as f: json.dump(data, f, indent=4)

# Инициализация Discord и FastAPI
intents = discord.Intents.default()
intents.message_content = True
bot = discord.Client(intents=intents)
app = FastAPI()

# Регулярное выражение для поиска ссылок
URL_REGEX = re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+')

# --- ВСПОМОГАТЕЛЬНЫЕ АСИНХРОННЫЕ ФУНКЦИИ ---

async def ask_gemini(prompt: str) -> str:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={GEMINI_API_KEY}"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload) as resp:
            if resp.status == 200:
                data = await resp.json()
                try:
                    return data["candidates"][0]["content"]["parts"][0]["text"].strip()
                except KeyError:
                    return "Ошибка парсинга ответа Gemini"
            return "Ошибка API Gemini"

async def check_virustotal(url: str):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}
    
    async with aiohttp.ClientSession() as session:
        async with session.get(vt_endpoint, headers=headers) as resp:
            if resp.status == 200:
                data = await resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return stats, data
            return None, None

# --- ЛОГИКА DISCORD БОТА ---

@bot.event
async def on_ready():
    print(f'Бот {bot.user} успешно запущен и готов к работе!')
    config = load_config()
    status = discord.Status.online if config["mrtp_enabled"] else discord.Status.offline
    await bot.change_presence(status=status)

@bot.event
async def on_message(message: discord.Message):
    if message.author == bot.user:
        return

    config = load_config()
    
    # 1. Проверка MRTP (выключен -> игнор)
    if not config["mrtp_enabled"]:
        return

    # 2. Проверка Блокировки всех сообщений
    if config["block_all_messages"]:
        await message.delete()
        return

    urls = URL_REGEX.findall(message.content)
    if not urls:
        return

    # 3. Проверка Удаления всех ссылок
    if config["delete_all_links"]:
        await message.delete()
        return

    db = load_db()
    for url in urls:
        # Шаг 1: Локальная проверка
        if any(entry["link"] == url for entry in db):
            await message.delete()
            return

        # Шаг 2: Проверка VirusTotal
        stats, full_report = await check_virustotal(url)
        if stats:
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            # СЦЕНАРИЙ В (Вредоносная)
            if malicious > 0:
                await message.delete()
                prompt = f"Проанализируй этот отчет VirusTotal и напиши простыми словами для администратора, что это за тип вируса/угрозы и чем он опасен: {json.dumps(stats)}"
                gemini_desc = await ask_gemini(prompt)
                
                db.append({
                    "user_id": str(message.author.id),
                    "username": str(message.author.name),
                    "link": url,
                    "threat_type": "Malicious",
                    "description": gemini_desc
                })
                save_db(db)
                return

            # СЦЕНАРИЙ Б (Подозрительная)
            elif suspicious > 0:
                prompt = f"Эта ссылка {url} помечена как suspicious. Проанализируй её контекст и ответь строго одним словом: УДАЛИТЬ или ОСТАВИТЬ"
                gemini_decision = await ask_gemini(prompt)
                if "УДАЛИТЬ" in gemini_decision.upper():
                    await message.delete()
                return

# --- ИНТЕГРАЦИЯ FASTAPI (УПРАВЛЕНИЕ) ---

class WarnModel(BaseModel):
    user_id: str

@app.get("/logs")
def get_logs():
    return load_db()

@app.get("/config")
def get_config():
    return load_config()

@app.post("/toggle/{setting}")
async def toggle_setting(setting: str):
    config = load_config()
    if setting in config:
        config[setting] = not config[setting]
        save_config(config)
        
        if setting == "mrtp_enabled":
            status = discord.Status.online if config[setting] else discord.Status.offline
            await bot.change_presence(status=status)
            
        return {"status": "success", "new_state": config[setting]}
    raise HTTPException(status_code=400, detail="Invalid setting")

@app.post("/warn")
async def warn_user(data: WarnModel):
    try:
        user = await bot.fetch_user(int(data.user_id))
        await user.send("Вам выдан Varning, если вы думаете что это ошибка, обратитесь к Администратору.")
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Запуск бота в фоне при старте FastAPI
@app.on_event("startup")
async def startup_event():
    asyncio.create_task(bot.start(DISCORD_TOKEN))

# Запуск для локального теста: uvicorn server:app --host 0.0.0.0 --port 8000