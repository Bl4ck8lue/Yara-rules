# Yara-rules
Репозиторий с набором YARA-правил и скриптов для анализа файлов в Linux-средах. Основная цель — собрать, отформатировать и применить сигнатуры для выявления вредоносного содержимого, а также предоставить утилиты для автоматической конвертации/подготовки правил.

Содержание репозитория.
rulesDir/ — каталог с YARA-правилами (набор .yar / .yara файлов). 
clamav_to_yara.py — утилита для преобразования сигнатур ClamAV в YARA-формат. 
main_file.py — главный скрипт проекта. 
wg.py — вспомогательный модуль. 
requirements.txt — список Python-зависимостей. 
.idea/ и прочие конфигурационные каталоги.

# Установка и подготовка
# Клонирование:
git clone https://github.com/Bl4ck8lue/Yara-rules.git
cd Yara-rules
# Создание виртуального окружения и установка зависимостей:
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
