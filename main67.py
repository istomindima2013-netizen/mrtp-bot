import discord
from discord.ext import commands
import aiohttp
from aiohttp import web
import asyncio
import re
import base64
import os
import json
from datetime import datetime

import gspread
from google.oauth2.service_account import Credentials

# Настройки
TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
ALLOWED_USER_ID = 1281520404057427994
TECH_CHANNEL_NAME = "👨‍🔧тех-отдел-для-персонала-1-2-3-класов👨‍🔧"
GOOGLE_SHEET_ID = "1bwVV_3b9l8YecmwqjI4GWfk-8jMD5u6_KKCJROArCxw"

IS_ACTIVE = True
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

url_queue = asyncio.Queue()
URL_REGEX = re.compile(r'https?://[^\s]+')

MALICIOUS_URLS_CACHE = set()
sheet_instance = None

# Твоя строгая классификация угроз
THRESHOLDS = {
    "malicious": [
        "downloader", "dropper", "spy", "stealer", "trojan", 
        "ransomware", "ransom", "worm", "exploit", "packed", 
        "crypt", "obfuscated", "phishing", "malware", "malicious"
    ],
    "suspicious": [
        "suspicious", "heuristic", "heur", "generic", "riskware", 
        "tool", "pup", "pua", "spam"
    ]
}

# Человеческие описания для тех-отдела (строго по твоему ТЗ)
THREAT_DESCRIPTIONS = {
    "downloader": "Trojan-Downloader (Скачивает из сети другие вирусы)",
    "dropper": "Trojan-Dropper (Содержит скрытые файлы и выбрасывает их в систему при запуске)",
    "spy": "Trojan-Spy / Stealer (Инфостилеры: ворует пароли из браузеров, куки и данные карт)",
    "stealer": "Trojan-Spy / Stealer (Инфостилеры: ворует пароли из браузеров, куки и данные карт)",
    "trojan": "Trojan (Маскируется под полезный софт, но внутри содержит злой код)",
    "ransomware": "Ransomware (Вымогатель / Блокировщик данных)",
    "ransom": "Ransomware (Вымогатель / Блокировщик данных)",
    "worm": "Worm (Сетевой червь)",
    "exploit": "Exploit (Использует уязвимости системы)",
    "packed": "Packed / Crypt / Obfuscated (Код запакован или скрыт от антивирусов)",
    "crypt": "Packed / Crypt / Obfuscated (Код запакован или скрыт от антивирусов)",
    "obfuscated": "Packed / Crypt / Obfuscated (Код запакован или скрыт от антивирусов)",
    "phishing": "Phishing (Фишинг / Кража аккаунтов)",
    "malware": "Malware (Вредоносное ПО)",
    "malicious": "Malicious (Вредоносный код)",
    "suspicious": "Suspicious (Подозрительный файл/скрипт)",
    "heuristic": "Heuristic / Heur (Сработало эвристическое обнаружение подозрительного поведения)",
    "heur": "Heuristic / Heur (Сработало эвристическое обнаружение подозрительного поведения)",
    "generic": "Generic (Общее подозрение / Дженерик)",
    "riskware": "Riskware / Tool (Утилиты риска / Потенциально опасный софт)",
    "tool": "Riskware / Tool (Утилиты риска / Потенциально опасный софт)",
    "pup": "PUP / PUA (Потенциально нежелательное приложение)",
    "pua": "PUP / PUA (Потенциально нежелательное приложение)",
    "spam": "Spam (Ссылка замечена в спам-рассылках)"
}

def init_google_sheets():
    global sheet_instance, MALICIOUS_URLS_CACHE
    try:
        creds_json = os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON")
        if not creds_json:
            print("⚠️ Переменная GOOGLE_SERVICE_ACCOUNT_JSON отсутствует.")
            return
        
        scopes = ["https://www.googleapis.com/auth/spreadsheets"]
        creds = Credentials.from_service_account_info(json.loads(creds_json), scopes=scopes)
        gc = gspread.authorize(creds)
        sheet_instance = gc.open_by_key(GOOGLE_SHEET_ID).sheet1
        
        records = sheet_instance.get_all_records()
        for row in records:
            if "URL" in row and row["URL"]:
                MALICIOUS_URLS_CACHE.add(str(row["URL"]).strip().lower())
        print(f"📊 База синхронизирована. Ссылок в кэше: {len(MALICIOUS_URLS_CACHE)}")
    except Exception as e:
        print(f"❌ Ошибка Sheets: {e}")

def add_to_db(url, exact_verdicts, internal_classes, status_type):
    global sheet_instance, MALICIOUS_URLS_CACHE
    cleaned_url = url.strip().lower()
    if cleaned_url in MALICIOUS_URLS_CACHE:
        return
    
    MALICIOUS_URLS_CACHE.add(cleaned_url)
    if sheet_instance:
        try:
            date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Записываем всё: ссылку, дату, точные вердикты, нашу классификацию и статус
            sheet_instance.append_row([url, date_str, ", ".join(exact_verdicts), ", ".join(internal_classes), status_type])
            print(f"💾 Ссылка занесена в таблицу со статусом {status_type}")
        except Exception as e:
            print(f"❌ Ошибка записи в таблицу: {e}")

async def check_url_vt(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data['data']['attributes']['last_analysis_results']
    return None

# Функция точного разбора детектов без выдумывания данных
def parse_detections(results):
    exact_verdicts = []
    detected_classes = set()
    formatted_details = []
    
    is_malicious_found = False
    is_suspicious_found = False

    for av_name, av_data in results.items():
        if av_data['category'] in ['malicious', 'suspicious']:
            result_text = av_data.get('result')
            if not result_text:
                continue
            
            exact_verdicts.append(f"{av_name}: {result_text}")
            result_lower = result_text.lower()
            
            # Ищем совпадения по нашей базе ключевых слов
            matched_descr = []
            
            # Проверяем на жесткие малвари
            for kw in THRESHOLDS["malicious"]:
                if kw in result_lower:
                    is_malicious_found = True
                    detected_classes.add(kw)
                    if THREAT_DESCRIPTIONS[kw] not in matched_descr:
                        matched_descr.append(THREAT_DESCRIPTIONS[kw])
            
            # Проверяем на подозрения
            for kw in THRESHOLDS["suspicious"]:
                if kw in result_lower:
                    is_suspicious_found = True
                    detected_classes.add(kw)
                    if THREAT_DESCRIPTIONS[kw] not in matched_descr:
                        matched_descr.append(THREAT_DESCRIPTIONS[kw])
            
            # Собираем красивую строчку для тех-канала
            descr_suffix = f" ➡️ ({', '.join(matched_descr)})" if matched_descr else ""
            formatted_details.append(f"🔹 **{av_name}**: `{result_text}`{descr_suffix}")

    # Определяем финальный статус на основе приоритета малвари
    final_status = "Safe"
    if is_malicious_found:
        final_status = "Malicious"
    elif is_suspicious_found:
        final_status = "Suspicious"

    return final_status, exact_verdicts, list(detected_classes), formatted_details

class TechModerationView(discord.ui.View):
    def __init__(self, original_msg: discord.Message, url: str, exact_verdicts, detected_classes):
        super().__init__(timeout=86400)
        self.original_msg = original_msg
        self.url = url
        self.exact_verdicts = exact_verdicts
        self.detected_classes = detected_classes

    @discord.ui.button(label="Удалить ссылку", style=discord.ButtonStyle.danger, emoji="🔴")
    async def delete_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        try:
            await self.original_msg.delete()
            await interaction.response.send_message(f"✅ Сообщение `{self.url}` удалено.", ephemeral=True)
        except discord.errors.NotFound:
            await interaction.response.send_message("❌ Сообщение уже удалено.", ephemeral=True)
        
        add_to_db(self.url, self.exact_verdicts, self.detected_classes, "Suspicious (Удалено вручную)")
        for child in self.children: child.disabled = True
        await interaction.message.edit(view=self)

    @discord.ui.button(label="Оставить сообщение", style=discord.ButtonStyle.success, emoji="🟢")
    async def leave_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        for child in self.children: child.disabled = True
        await interaction.message.edit(view=self)
        await interaction.response.send_message("🟢 Сообщение оставлено в чате.", ephemeral=True)

    @discord.ui.button(label="Выдать Варн", style=discord.ButtonStyle.secondary, emoji="⚠️")
    async def warn_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        await self.original_msg.channel.send(f"⚠️ {self.original_msg.author.mention}, вам выдан **Варн** за отправку подозрительных ссылок!")
        await interaction.response.send_message(f"✅ Варн выдан пользователю {self.original_msg.author.name}.", ephemeral=True)

async def queue_worker():
    global IS_ACTIVE
    while True:
        message, url = await url_queue.get()
        if not IS_ACTIVE:
            url_queue.task_done()
            continue
        try:
            results = await check_url_vt(url)
            if not results:
                url_queue.task_done()
                await asyncio.sleep(15)
                continue
            
            final_status, exact_verdicts, detected_classes, formatted_details = parse_detections(results)
            
            # СЦЕНАРИЙ 1: Найдена малварь (Авто-удаление)
            if final_status == "Malicious":
                try:
                    await message.delete()
                except discord.errors.NotFound: pass
                
                await message.channel.send(f"❌ {message.author.mention}, сообщение удалено! Обнаружен критический вредонос. Авто-варн!")
                add_to_db(url, exact_verdicts, detected_classes, "Malicious (Авто-удаление)")
                
                tech_channel = discord.utils.get(message.guild.text_channels, name=TECH_CHANNEL_NAME)
                if tech_channel:
                    emb = discord.Embed(title="🚨 Критическая угроза (Авто-удаление)", color=discord.Color.red())
                    emb.add_field(name="Пользователь", value=message.author.mention)
                    emb.add_field(name="Ссылка", value=f"`{url}`")
                    emb.add_field(name="Обнаруженные типы", value=", ".join(detected_classes) or "Malicious")
                    emb.set_footer(text="Данные внесены в базу Google Sheets автоматически.")
                    await tech_channel.send(embed=emb)

            # СЦЕНАРИЙ 2: Только Подозрения (Кнопки модерации, сообщение НЕ удаляется)
            elif final_status == "Suspicious":
                tech_channel = discord.utils.get(message.guild.text_channels, name=TECH_CHANNEL_NAME)
                if tech_channel:
                    embed_tech = discord.Embed(title="🕵️‍♂️ Подозрительная ссылка (Ожидание решения)", color=discord.Color.orange())
                    embed_tech.add_field(name="👤 Отправитель", value=message.author.mention, inline=True)
                    embed_tech.add_field(name="📁 Канал", value=message.channel.mention, inline=True)
                    embed_tech.add_field(name="🔗 Ссылка", value=f"`{url}`", inline=False)
                    
                    # Показываем только первые 12 строк логов антивирусов, чтобы лимит Дискорда не упал
                    details_text = "\n".join(formatted_details[:12])
                    if len(formatted_details) > 12:
                        details_text += f"\n... и еще {len(formatted_details) - 12} детектов."
                        
                    embed_tech.add_field(name="🛑 Точные логи антивирусов и их разбор:", value=details_text, inline=False)
                    
                    view = TechModerationView(message, url, exact_verdicts, detected_classes)
                    await tech_channel.send(embed=embed_tech, view=view)

        except Exception as e:
            print(f"Ошибка воркера: {e}")
        url_queue.task_done()
        await asyncio.sleep(15)

async def web_handle(request):
    return web.Response(text="Бот MRTP онлайн. Анализ логов активирован.")

@bot.event
async def on_ready():
    print(f"🟢 Проект MRTP успешно запущен! Бот {bot.user.name} охраняет хату марселя.")
    init_google_sheets()
    bot.loop.create_task(queue_worker())
    
    app = web.Application()
    app.router.add_get('/', web_handle)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("PORT", 10000))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()

@bot.event
async def on_message(message):
    if message.author.bot: return
    global IS_ACTIVE

    if message.content.startswith("!mrtp"):
        if message.author.id != ALLOWED_USER_ID: return
        args = message.content.split()
        if len(args) > 1:
            if args[1] == "off":
                IS_ACTIVE = False
                await message.channel.send("🔴 Защита выключена.")
            elif args[1] == "on":
                IS_ACTIVE = True
                await message.channel.send("🟢 Защита включена.")
        return

    urls = URL_REGEX.findall(message.content)
    if urls and IS_ACTIVE:
        for url in urls:
            cleaned_url = url.strip().lower()
            
            if cleaned_url in MALICIOUS_URLS_CACHE:
                try:
                    await message.delete()
                except discord.errors.NotFound: pass
                await message.channel.send(f"❌ {message.author.mention}, ссылка заблокирована моментально (уже есть в базе Google Таблиц)!")
                
                tech_channel = discord.utils.get(message.guild.text_channels, name=TECH_CHANNEL_NAME)
                if tech_channel:
                    await tech_channel.send(f"🛡️ **База Данных:** Молниеносный блок ссылки `{url}` от {message.author.mention}.")
                continue
            
            await url_queue.put((message, url))

    await bot.process_commands(message)

bot.run(TOKEN)
