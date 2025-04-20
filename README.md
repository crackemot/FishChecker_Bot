# FishChecker_Bot

## Возможности

- Проверка SSL-сертификата (срок действия, валидность)
- Анализ WHOIS (возраст домена)
- Проверка в базе фишинговых сайтов
- Поиск кириллических символов в домене
- Проверка через VirusTotal API
- Анализ схожести с доверенными сайтами (расстояние Левенштейна)
- Кэширование результатов проверки

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/crackemot/FishChecker_Bot
   cd FishChecker_Bot

2. Установите requirements
   ```bash
   pip install -r requirements.txt

3. Замените в коде токены:

   ```python
   WHOISXML_API_KEY = "ВАШ_ТОКЕН"       # WHOIS API (https://whois.whoisxmlapi.com)
   VIRUSTOTAL_API_KEY = "ВАШ_ТОКЕН"     # VirusTotal API (https://www.virustotal.com)
   TELEGRAM_BOT_TOKEN = "ВАШ_ТОКЕН"     # Telegram Bot Token (@BotFather)

## Использование бота

Найдите своего бота в Telegram

Отправьте ссылку для проверки (обязательно с http/https)

Получите детализированный отчет:

Пример вывода:

        🔴 Высокий риск
        Детали проверки:
        - Найден в базе фишинговых сайтов (Высокий)
        - Сертификат: истекает через 3 дней (Средний)
        - Кириллица в домене (Высокий)
        - Обнаружен в VirusTotal (Высокий)
