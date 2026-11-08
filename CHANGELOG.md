# Changelog / История изменений

## 2.0.1a — 2026-11-08

Заменяет 2.0.1: те же исправления плюс отчёты о проблемах, предупреждение при запуске и FAQ.
Replaces 2.0.1: the same fixes plus problem reports, a startup warning and a FAQ.

### 🇷🇺 Исправлено
- **Запись CodeFlash по UDS.** Пока блок выполняет долгую операцию, он отвечает «ждите» (`7F xx 78`) примерно каждые 2,5 с. ContiTool ждал после такого ответа тоже 2,5 с, и на адаптере с задержкой стирание обрывалось на середине: приложение уже стёрто, а блок остаётся в загрузчике. Теперь после `78` программа ждёт до 6 с (по протоколу блоку положено до 5 с, P2*). CAN-терминал ждёт так же.
- **VAS 6154 / VNCI на драйверах D-PDU 30 и новее.** Каналы теперь закрываются так же, как это делают ODIS и сам драйвер: STOPCOMM на канале отправки, отмена монитора, только потом отключение. Раньше примерно каждая вторая операция падала с `PDU_ERR_COMM_PC_TO_VCI_FAILED` через 2 с после подключения.
- Если VCI всё же разорвал соединение при подключении, ContiTool ждёт 4 с и подключается заново (один раз).

### 🇷🇺 Добавлено
- **Проверка версии драйвера D-PDU до подключения.** При подключении драйвер перепрошивает VCI под свою версию, поэтому версия проверяется заранее. Версии **27.2** и **31.0 / 31.1** работают сразу. Для остальных нужна галочка в окне «Подключение» или флаг `--allow-dpdu-driver` в CLI.
- Версия драйвера D-PDU показывается в списке адаптеров и в `contitool can ports`.
- **Понятная ошибка при обрыве чтения памяти.** Программа пишет, сколько байт пришло до обрыва. Для SLCAN добавлена подсказка: адаптер теряет кадры. Клоны с последовательным портом (CH340 и т. п. на 115200 бод) справляются с UDS, но не с потоком памяти на полной скорости шины.
- **Отчёт о проблеме.** Если операция, проверка связи или CAN-терминал завершились ошибкой, ContiTool предлагает сообщить о проблеме (и в любой момент — «Справка → Сообщить о проблеме…»). Программа собирает архив: журнал программы, файлы операции (без дампов памяти `*.bin`; из `can.jsonl` — начало и конец), журналы драйвера D-PDU за время операции, описание системы и адаптера. Затем открывается страница нового issue на GitHub с уже заполненным текстом. VIN и FAZIT в тексте скрываются.
- **Предупреждение при запуске.** Кому программа не нужна, почему нельзя работать на рабочей машине, кто отвечает за испорченный блок. Без согласия работа не начнётся. Можно скрыть до следующей версии.
- **FAQ** — в README и в «Памятке по стенду»: VNCI не подключается на поддерживаемом драйвере, дешёвые адаптеры, шлюз не отвечает после обрыва чтения, как сообщить о проблеме.

### 🇷🇺 Изменено
- Галочка CAN-терминатора объясняет, что такое резистор 120 Ом и зачем он на столе, и предупреждает, что это только напоминание: программа сама ничего не проверяет. Для VAS 6154 / VNCI и J2534 галочки больше нет: терминатор в них встроен.
- Диалоги подгоняют высоту под текст с переносами: раньше последняя строка могла обрезаться.
- В консольном режиме при ошибке выводится ссылка на GitHub Issues; в заставке — короткое предупреждение.

### 🇬🇧 Fixed
- **CodeFlash write over UDS.** During a long operation the ECU answers "wait" (`7F xx 78`) about every 2.5 s. ContiTool also waited only 2.5 s after it, so on an adapter with some latency an erase could be cut off halfway: the application already erased, the ECU left in its bootloader. ContiTool now waits up to 6 s after a `78` (the ECU may take up to 5 s, P2*). The CAN terminal waits the same way.
- **VAS 6154 / VNCI on D-PDU drivers 30 and newer.** Links are now closed the way ODIS and the driver itself close them: STOPCOMM on the send link, then the monitor is cancelled, and only then the link is disconnected. Before, about every second operation failed with `PDU_ERR_COMM_PC_TO_VCI_FAILED` 2 s after connecting.
- If the VCI still drops the connection while connecting, ContiTool waits 4 s and connects again (once).

### 🇬🇧 Added
- **D-PDU driver version check before connecting.** The driver reflashes the VCI to its own version on connect, so the version is checked beforehand. **27.2** and **31.0 / 31.1** run right away. Other versions need a checkbox in the Connection dialog or `--allow-dpdu-driver` in the CLI.
- The D-PDU driver version is shown in the adapter list and in `contitool can ports`.
- **Clear error when a memory read stream breaks.** ContiTool reports how many bytes arrived before the break. For SLCAN it adds a hint that the adapter loses frames: serial clones (CH340 etc. at 115200 baud) handle UDS but not a memory stream at full bus speed.
- **Problem report.** When an operation, a link check or the CAN terminal fails, ContiTool offers to report it (and any time via Help → Report a problem…). It collects an archive — the program log, the operation's files (no `*.bin` memory dumps; the start and end of `can.jsonl`), the D-PDU driver logs written during the operation, a system and adapter summary — and opens a new GitHub issue with the text filled in. VINs and FAZIT IDs in the text are masked.
- **Startup warning.** Who should not use the program, why not on a working car, who answers for a bricked ECU. Nothing starts without consent; it can be hidden until the next version.
- **FAQ** in the README and in the bench guide: the VNCI does not connect on a supported driver, cheap adapters, the gateway does not answer after a broken read, how to report a problem.

### 🇬🇧 Changed
- The CAN terminator checkbox explains what the 120 Ω resistor is and why the bench needs it, and says it is only a reminder: the program checks nothing itself. For VAS 6154 / VNCI and J2534 it is gone: their terminator is built in.
- Dialogs fit their height to wrapped text: the last line could be cut off before.
- The CLI prints a GitHub Issues link on errors and a short warning in its banner.

## 2.0.0 — 2026-11-08

A complete rewrite: a desktop GUI and a CLI for Continental J533 (`3Q0 907 530`) gateways. See the [v2.0.0 release](https://github.com/perkthefox/mqb_contitool/releases/tag/v2.0.0).

Полностью новая версия: настольное приложение и CLI для шлюзов Continental J533 (`3Q0 907 530`). Подробности — в [релизе v2.0.0](https://github.com/perkthefox/mqb_contitool/releases/tag/v2.0.0).
