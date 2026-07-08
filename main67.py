import discord
from discord.ext import commands
import aiohttp
from aiohttp import web  # Добавили встроенный веб-сервер
import asyncio
import re
import base64
import os

# Чтение ключей из панели управления Render
TOKEN = os.getenv("DISCORD_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
ALLOWED_USER_ID = 1281520404057427994  # Твой Дискорд ID

IS_ACTIVE = True
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

url_queue = asyncio.Queue()
URL_REGEX = re.compile(r'https?://[^\s]+')

async def check_url_vt(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    async with aiohttp.ClientSession() as session:
        async with session.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers) as response:
            if response.status == 200:
                data = await response.json()
                return data['data']['attributes']['last_analysis_stats'], data['data']['attributes']['last_analysis_results']
    return None, None

async def queue_worker():
    global IS_ACTIVE
    while True:
        message, url = await url_queue.get()
        if not IS_ACTIVE:
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
                await message.channel.send(f"❌ Сообщение от {message.author.mention} удалено! Обнаружен опасный вирус ({malicious} малварь, {suspicious} подозрительно). Выдан варн!")
            
            elif suspicious >= 1:
                bad_antiviruses = [av for av, res in results.items() if res['category'] in ['malicious', 'suspicious']]
                av_list = ", ".join(bad_antiviruses[:10])
                embed = discord.Embed(title="⚠️ Подозрительная ссылка!", color=discord.Color.orange())
                embed.add_field(name="Отправитель", value=message.author.mention)
                embed.add_field(name="Подозрительно", value=str(suspicious))
                embed.add_field(name="Ругаются антивирусы", value=av_list or "Неизвестно")
                await message.channel.send(embed=embed)
        except Exception as e:
            print(f"Ошибка очереди: {e}")
        url_queue.task_done()
        await asyncio.sleep(15)

# Ответ для Render, что наш "сайт" живой
async def web_handle(request):
    return web.Response(text="Бот MRTP онлайн и успешно работает!")

@bot.event
async def on_ready():
    print(f"🟢 Проект MRTP успешно запущен! Бот {bot.user.name} охраняет хату марселя.")
    bot.loop.create_task(queue_worker())
    
    # 🔥 Обманка для Render: запускаем фоновый сервер на порту хостинга
    app = web.Application()
    app.router.add_get('/', web_handle)
    runner = web.AppRunner(app)
    await runner.setup()
    port = int(os.getenv("PORT", 10000))
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    print(f"🌐 Микро веб-сервер запущен на порту {port}")

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
                await message.channel.send("🔴 **Защита MRTP ВЫКЛЮЧЕНА.** Ссылки больше не проверяются.")
            elif args[1] == "on":
                IS_ACTIVE = True
                await message.channel.send("🟢 **Защита MRTP ВКЛЮЧЕНА.** Сервер под охраной.")
        return

    urls = URL_REGEX.findall(message.content)
    if urls and IS_ACTIVE:
        for url in urls:
            await url_queue.put((message, url))
            if url_queue.qsize() > 1:
                await message.channel.send("⏳ Ссылка добавлена в очередь проверки VirusTotal...", delete_after=5)

    await bot.process_commands(message)

bot.run(TOKEN)
