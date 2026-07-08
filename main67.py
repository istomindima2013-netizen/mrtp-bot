import os
import discord
from discord.ext import commands
import aiohttp
from aiohttp import web
import asyncio
import re
import base64

# Берем секретные ключи из настроек Render (чтобы никто их не украл на GitHub)
TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
PORT = int(os.getenv("PORT", 8080))

if not TOKEN:
    print("❌ СТОП: В настройках Render переменная DISCORD_TOKEN ВООБЩЕ ПУСТАЯ или названа неверно!")
else:
    print(f"🤖 Токен обнаружен! Длина: {len(TOKEN)} символов. Начинается на: {TOKEN[:10]}...")

# Статус защиты (включен/выключен) хранится прямо в памяти
BOT_STATUS = {"is_active": True}

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

url_queue = asyncio.Queue()
URL_REGEX = re.compile(r'https?://[^\s]+')

async def check_url_vt(url):
    """Проверка ссылки в VirusTotal API v3"""
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data['data']['attributes']['last_analysis_stats'], data['data']['attributes']['last_analysis_results']
    return None, None

async def queue_worker():
    """Очередь: 1 запрос раз в 15 секунд (лимит бесплатного VT)"""
    while True:
        message, url = await url_queue.get()
        if not BOT_STATUS["is_active"]:
            url_queue.task_done()
            continue
        try:
            stats, results = await check_url_vt(url)
            if not stats:
                url_queue.task_done()
                await asyncio.sleep(15)
                continue
            
            suspicious = stats.get('suspicious', 0)
            malicious = stats.get('malicious', 0)
            
            if malicious > 0 or suspicious >= 4:
                await message.delete()
                await message.channel.send(f"❌ Сообщение от {message.author.mention} удалено. Обнаружен вирус ({malicious} малварь, {suspicious} подозрительно). Выдан варн!")
            elif suspicious >= 1:
                bad_antiviruses = [av for av, res in results.items() if res['category'] in ['malicious', 'suspicious']]
                av_list = ", ".join(bad_antiviruses[:10])
                embed = discord.Embed(title="⚠️ Подозрительная ссылка!", color=discord.Color.orange())
                embed.add_field(name="Отправитель", value=message.author.mention)
                embed.add_field(name="Подозрительно", value=str(suspicious))
                embed.add_field(name="Ругаются антивирусы", value=av_list or "Неизвестно")
                await message.channel.send(embed=embed)
        except Exception as e:
            print(f"Ошибка проверки: {e}")
        url_queue.task_done()
        await asyncio.sleep(15)

@bot.event
async def on_ready():
    print(f"Бот {bot.user.name} успешно запущен!")
    bot.loop.create_task(queue_worker())

@bot.event
async def on_message(message):
    if message.author.bot: return
    urls = URL_REGEX.findall(message.content)
    if urls and BOT_STATUS["is_active"]:
        for url in urls:
            await url_queue.put((message, url))
            if url_queue.qsize() > 1:
                await message.channel.send("⏳ Ссылка добавлена в очередь на проверку VirusTotal...", delete_after=5)
    await bot.process_commands(message)

# --- ВЕБ СЕРВЕР ДЛЯ ОБМАНА RENDER И ДЛЯ ТУМБЛЕРА ВЫКЛЮЧЕНИЯ ---
async def handle_home(request):
    status = "РАБОТАЕТ" if BOT_STATUS["is_active"] else "ВЫКЛЮЧЕНА"
    return web.Response(text=f"Система MRTP: {status}")

async def handle_toggle(request):
    BOT_STATUS["is_active"] = not BOT_STATUS["is_active"]
    status = "ВКЛЮЧЕНА" if BOT_STATUS["is_active"] else "ВЫКЛЮЧЕНА"
    return web.Response(text=f"Защита хаты марселя теперь: {status}")

async def start_server():
    app = web.Application()
    app.router.add_get('/', handle_home)
    app.router.add_get('/toggle', handle_toggle) # Ссылка для вкл/выкл
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', PORT)
    await site.start()

async def main():
    await start_server()
    await bot.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
