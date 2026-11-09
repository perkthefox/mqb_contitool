# Участие в разработке / Contributing

🇷🇺 [Русский](#-русский) · 🇬🇧 [English](#-english)

## 🇷🇺 Русский

### Сообщить о проблеме

- **Проще всего — из программы.** После ошибки нажмите «Создать отчёт…»: ContiTool сохранит архив с журналами
  (без дампов памяти) и откроет форму issue уже заполненной. Опишите, что делали, и перетащите архив.
- Без программы — [форма «Проблема»](https://github.com/perkthefox/mqb_contitool/issues/new/choose).
- **Вопросы** («как подключить», «какой драйвер») — в [Discussions](https://github.com/perkthefox/mqb_contitool/discussions).
  В личные сообщения не пишите: ответ в issue или обсуждении пригодится и следующему.
- Перед публикацией просмотрите архив: в сырых журналах могут быть идентификаторы блока и автомобиля.

### Прислать изменения

1. Для заметных изменений сначала откройте issue или обсуждение — договоримся о подходе до того, как писать код.
2. Окружение (Python 3.12+):
   ```bash
   python -m venv .venv
   .venv/bin/pip install -e ".[dev]"          # Windows: .venv\Scripts\pip
   QT_QPA_PLATFORM=offscreen .venv/bin/pytest -q
   .venv/bin/python conti_cp_tool.py           # GUI; с аргументами — CLI
   ```
3. Откройте pull request в `main` и заполните шаблон.

### Правила кода

- **Проверенные на железе протоколы не трогаются без доказательства.** Полиномы CRC-16/CRC-32, криптография,
  смещения в образах, последовательности кадров CAN / ISO-TP в `src/contitool/core/` и `src/contitool/can/` меняются
  только вместе с журналом со стенда (`can.jsonl`, журнал драйвера), где новый вариант работает.
- **Долгие операции** принимают `OperationReporter` и в GUI выполняются в фоновом потоке — интерфейс не должен зависать.
- **Каждая строка для пользователя — на двух языках** через `tr(ru, en)`.
- **Никаких настоящих идентификаторов** в репозитории: VIN, FAZIT, серийные номера, дампы `*.bin`. В тестах —
  выдуманные значения; тест гигиены репозитория это проверяет.
- **Изменение поведения — вместе с тестом**, который без этого изменения падает.
- **Заметное для пользователя** — запись в `CHANGELOG.md` на двух языках.

### Лицензия вкладов

Присылая изменения, вы подтверждаете, что имеете на них право, и соглашаетесь, что они распространяются на условиях
[`LICENSE`](LICENSE) (PolyForm Noncommercial 1.0.0 с дополнительными условиями) и что PerkTheFox может также
лицензировать их на других условиях — например, выдать разрешение на коммерческое использование.

## 🇬🇧 English

### Reporting a problem

- **Easiest from the program.** After an error press "Create report…": ContiTool saves an archive with the logs
  (no memory dumps) and opens the issue form already filled in. Describe what you did and drag the archive in.
- Without the program — the ["Problem" form](https://github.com/perkthefox/mqb_contitool/issues/new/choose).
- **Questions** ("how to connect", "which driver") — in [Discussions](https://github.com/perkthefox/mqb_contitool/discussions).
  Please do not use direct messages: an answer in an issue or discussion helps the next person too.
- Review the archive before publishing it: raw logs may contain ECU and vehicle identifiers.

### Sending changes

1. For anything sizeable, open an issue or discussion first, so we agree on the approach before the code.
2. Environment (Python 3.12+):
   ```bash
   python -m venv .venv
   .venv/bin/pip install -e ".[dev]"          # Windows: .venv\Scripts\pip
   QT_QPA_PLATFORM=offscreen .venv/bin/pytest -q
   .venv/bin/python conti_cp_tool.py           # GUI; with arguments — CLI
   ```
3. Open a pull request against `main` and fill in the template.

### Code rules

- **Hardware-verified protocols are not changed without proof.** CRC-16/CRC-32 polynomials, cryptography, image
  offsets, and CAN / ISO-TP frame sequences in `src/contitool/core/` and `src/contitool/can/` change only together
  with a bench log (`can.jsonl`, driver log) showing the new version working.
- **Long operations** take an `OperationReporter` and run on a background thread in the GUI — the UI must never freeze.
- **Every user-facing string is bilingual** through `tr(ru, en)`.
- **No real identifiers** in the repository: VINs, FAZITs, serial numbers, `*.bin` dumps. Tests use made-up values;
  the repository hygiene test checks this.
- **A change in behaviour comes with a test** that fails without it.
- **Anything users notice** gets a bilingual entry in `CHANGELOG.md`.

### License of contributions

By sending changes you confirm you have the right to do so, and agree that they are distributed under
[`LICENSE`](LICENSE) (PolyForm Noncommercial 1.0.0 with Additional Terms) and that PerkTheFox may also license them
under other terms — for example, to grant permission for commercial use.
