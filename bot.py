import logging
import json
import os
import ssl
import socket
from datetime import datetime, timedelta
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from urllib.parse import urlparse
import base64
import requests
from Levenshtein import distance as levenshtein_distance
import re

WHOISXML_API_KEY = "ВАШ_ТОКЕН"
VIRUSTOTAL_API_KEY = "ВАШ_ТОКЕН"
TELEGRAM_BOT_TOKEN = "ВАШ_ТОКЕН"

# Настройка логгирования
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Инициализация кэша и баз данных
PHISHING_DB_FILE = os.path.join(os.getcwd(), "phishing_database.json")
CACHE_FILE = os.path.join(os.getcwd(), "cache.json")
TRUSTED_SITE_LIST = os.path.join(os.getcwd(), "sitelist.json")
sitelist = []
phishing_db = []


def load_data():
    global sitelist, phishing_db
    # Загрузка доверенных сайтов
    if os.path.exists(TRUSTED_SITE_LIST):
        with open(TRUSTED_SITE_LIST, "r", encoding="utf-8") as f:
            sitelist = json.load(f)

    # Загрузка фишинговой базы
    if os.path.exists(PHISHING_DB_FILE):
        with open(PHISHING_DB_FILE, "r", encoding="utf-8") as f:
            phishing_db = json.load(f)

def save_data():
    with open(PHISHING_DB_FILE, "w", encoding="utf-8") as f:
        json.dump(phishing_db, f, indent=2)


def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    return {}

def save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, "w", encoding="utf-8") as file:
        json.dump(cache, file, ensure_ascii=False, indent=4)
    logger.info(f"Кэш сохранен в файл: {CACHE_FILE}")


# Проверка SSL-сертификата
def check_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expire_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        remaining_days = (expire_date - datetime.now()).days

        if remaining_days < 0:
            return "просрочен", "высокий"
        elif remaining_days < 7:
            return "истекает через {} дней".format(remaining_days), "средний"
        return "действителен", "низкий"

    except Exception as e:
        logger.error(f"SSL check error: {str(e)}")
        return "ошибка проверки", "низкий"


# Проверка в фишинговой базе
def check_phishing_db(domain):
    return domain in phishing_db

# Проверяем, ссылка ли это
def is_url(text):
    try:
        result = urlparse(text)
        return all([result.scheme in ["http", "https"], result.netloc])
    except:
        return False

# Поиск по базе доверенных сайтов
def is_domain_sus(domain, sitelist, threshold):
    for legit_domain in sitelist:
        if domain == legit_domain:
            return False
    for legit_domain in sitelist:
        if levenshtein_distance(domain, legit_domain) <= threshold:
            return True
    return False

def check_virustotal(url):
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        # Проверяем статус ответа
        if response.status_code == 200:
            data = response.json()
            if 'data' in data and 'attributes' in data['data']:
                malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
                return malicious_count > 1
            else:
                logger.warning(f"VirusTotal: неожиданный формат ответа для {url}")
                return False
        else:
            logger.warning(f"VirusTotal: ошибка запроса для {url}. Код: {response.status_code}")
            return False

    except Exception as e:
        logger.error(f"VirusTotal: ошибка при проверке {url}: {str(e)}")
        return False

# Получение даты создания домена
def get_domain_creation_date(domain):
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOISXML_API_KEY}&domainName={domain}&outputFormat=JSON"
    try:
        response = requests.get(url)
        data = response.json()
        creation_date = data.get("WhoisRecord", {}).get("createdDate", None)
        if creation_date:
            return datetime.strptime(creation_date, "%Y-%m-%dT%H:%M:%SZ")
    except Exception as e:
        logger.error(f"Ошибка при запросе WHOIS: {e}")
    return None

# Проверка на содержание кириллических символов
def contains_cyrillic(text):
    return bool(re.search('[а-яА-Я]', text))

# Основная функция проверки
def check_phishing(url):
    if url in cache:
        logger.info(f"Результат для {url} взят из кеша")
        return cache[url]

    report = []
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    try:
        # Проверка в фишинговой базе
        if check_phishing_db(domain):
            report.append({"issue": "Найден в базе фишинговых сайтов", "risk": "высокий"})

        # Проверка WHOIS
        creation_date = get_domain_creation_date(domain)
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            if age_days < 30:
                report.append({"issue": f"Молодой домен ({age_days} дней)", "risk": "средний"})

        # Проверка SSL
        cert_status, cert_risk = check_ssl_certificate(domain)
        report.append({"issue": f"Сертификат: {cert_status}", "risk": cert_risk})

        # Проверка кириллицы
        if contains_cyrillic(domain):
            report.append({"issue": "Кириллица в домене", "risk": "высокий"})

        # Проверка HTTPS
        if not url.startswith("https"):
            report.append({"issue": "Отсутствует HTTPS", "risk": "средний"})

        # Подозрительные символы
        if any(c in domain for c in ['-', '_', '0']):
            report.append({"issue": "Подозрительные символы", "risk": "средний"})

        # Проверка VirusTotal
        if check_virustotal(url):
            report.append({"issue": "Обнаружен в VirusTotal", "risk": "высокий"})

        # Проверка схожести с доверенными сайтами
        if is_domain_sus(domain, sitelist, 2):
            report.append({"issue": "Копирует сайт из списка доверенных", "risk": "высокий"})

    except Exception as e:
        logger.error(f"Check error: {str(e)}")
        report.append({"issue": "Ошибка при проверке (возможно ссылка недействительна)", "risk": "низкий"})

    # Определение общего уровня риска
    risk_counts = {"высокий": 0, "средний": 0, "низкий": 0}
    for item in report:
        risk_counts[item["risk"]] += 1

    if risk_counts["высокий"] > 0 or risk_counts["средний"] >= 2:
        overall_risk = "🔴 Высокий риск"
    elif risk_counts["средний"] > 0:
        overall_risk = "🟡 Средний риск"
    else:
        overall_risk = "🟢 Низкий риск"

    result = {
        "overall_risk": overall_risk,
        "report": report
    }

    cache[url] = result
    save_cache(cache)
    return result


# Форматирование отчета
def format_report(result):
    report_text = "\n".join([
        result['overall_risk'],
        "Детали проверки:",
        *[f"- {item['issue']} ({item['risk'].capitalize()})" for item in result['report']]
    ])
    return report_text


# Обработчик сообщений
async def check_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    if is_url(text):
        result = check_phishing(text)
        await update.message.reply_text(format_report(result))
    else:
        await update.message.reply_text("❌ Это не похоже на URL")

async def start(update: Update, context):
    await update.message.reply_text(
        "Привет! Я бот для проверки URL на фишинг. Отправь мне ссылку, и я проверю её. (Ссылку нужно отправить в полном формамте, включая протокол)"
    )

def main():
    application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_url))

    application.run_polling()

# Инициализация при запуске
load_data()
cache = load_cache()

if __name__ == "__main__":
    main()
