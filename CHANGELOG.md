# Changelog / История изменений

## 2.0.1b — 2026-11-08

Исправления по отчётам пользователей 2.0.1a: выбор модуля и драйвера D-PDU, удержание связи с VCI.
Fixes from the 2.0.1a user reports: D-PDU module and driver selection, and holding the VCI link open.

### 🇷🇺 Исправлено
- **`PDUModuleConnect: D-PDU error 0x01` на VAS 6154 / VNCI.** Драйвер перечисляет **все** установленные на компьютере модули D-PDU и J2534 — не только VCI — и порядок у него меняется от вызова к вызову. ContiTool брал первый в списке, попадал в чужой драйвер (Softing VAS5054A, XHorse MVCI, Scanmatik, DENSO), тот не находил свою службу на `127.0.0.1:4500` и отвечал `0x01`. Из-за меняющегося порядка это выглядело как случайные сбои: «работает после перезапуска», «работает, только пока открыт монитор CAN». Теперь модуль выбирается: сначала VCI Volkswagen, и если один не подключился — пробуется следующий, а в тексте ошибки перечислены все попытки.
- **Связь с VCI больше не разрывается между операциями.** Раньше канал открывался и закрывался на каждую операцию, то есть выбор модуля переигрывался каждый раз, а драйвер при каждом открытии заново перебирал свои журналы (на одном компьютере это стоило 4,4 с перед подключением). Теперь канал держится открытым, как его держит ODIS, и отдаётся следующей операции. Отдельный поток постоянно вычитывает кадры из драйвера, поэтому простой не оставляет очереди, которую следующая операция разгребала бы вместо своего ответа.
- **Модуль, ответивший неожиданной ошибкой, больше не прячет VCI за собой** — перебор продолжается, а разрыв со стороны VCI (`0x11`) по-прежнему получает повторную попытку через 4 с.
- **Ошибка одного кадра больше не убивает канал.** Результат длиннее одного кадра CAN — штатно повторяемая ошибка (чтение памяти её повторяет), и канал остаётся рабочим.
- **Выход из программы во время записи** больше не закрывает каналы драйвера из-под работающей операции. Запуск из CLI и аварийное завершение теперь тоже закрывают канал: иначе VCI оставался с живым монитором и следующая сессия падала через 2 с.
- **Правка DataFlash больше не откатывает записи, которые шлюз обновил сам.** Пишутся только изменённые вами блоки; блоки, изменившиеся в блоке после бэкапа, остаются как есть; если один и тот же блок изменили и вы, и шлюз — запись останавливается до первой команды стирания и просит снять свежий бэкап. На реальном отчёте пользователя так откатывались два служебных блока NvM (`0xF040`, `0xF080`).
- **Понятная ошибка, когда блок молчит на входе в заводской RAM-Loader.** Раньше показывалось `No CAN frame from 0x77A within 2.5s` — про транспорт, а не про шаг. Теперь прямо сказано: на предыдущие запросы блок ответил, значит связь есть, а чтение памяти по CAN на этом блоке не получилось.
- **В отчёт о проблеме попадает журнал драйвера с ошибкой.** Раньше брался самый старый журнал окна, и отчёт заполнялся трассой *удачного* чтения. Теперь берётся самый свежий, а журнал больше 8 МБ пакуется хвостом — ошибка как раз в конце.

### 🇷🇺 Добавлено
- **Выбор драйвера D-PDU.** Все установленные показываются отдельными строками в окне «Подключение» с вариантом и версией (`OE`, `OS`, `VCTOOL`…). По умолчанию ODIS-E, выбор запоминается. Раньше вариант ODIS-E брался всегда, и если именно он не дружил с адаптером, выхода не было.
- **Свой драйвер рядом с программой.** Папка `dpdu/` рядом с ContiTool сканируется на `PDUAPI*.dll`, найденное показывается первым в списке. Без установки, записи в реестр и прав администратора — для компьютера, где драйвер не установлен или установленный не подходит. 32-разрядные сборки отбрасываются. Сам драйвер ContiTool не распространяет.
- **Версия загрузчика (DID `F180`)** читается вместе с остальной идентификацией: вход в заводской RAM-Loader зависит именно от неё, а не от версии приложения.
- FAQ: нужен ли ODIS (нет, достаточно отдельного пакета VW D-PDU API), как выбрать другой драйвер, как положить свой в `dpdu/`.

### 🇬🇧 Fixed
- **`PDUModuleConnect: D-PDU error 0x01` on a VAS 6154 / VNCI.** The driver lists **every** D-PDU and J2534 module installed on the PC — not just the VCI — in an order that changes between calls. ContiTool took the first entry, reached someone else's driver (Softing VAS5054A, XHorse MVCI, Scanmatik, DENSO), which found no service of its own on `127.0.0.1:4500` and answered `0x01`. Because the order kept changing this looked random: "works after a restart", "works only while the CAN monitor is open". The module is now chosen — Volkswagen VCIs first — the next candidate is tried if one refuses, and the error names every module tried.
- **The VCI link is no longer dropped between operations.** It used to be opened and closed per operation, so the module choice was re-rolled every time and the driver re-scanned its own log files on each open (4.4 s before connecting on one user's PC). The link is now held open the way ODIS holds it and handed to the next operation. A dedicated thread keeps taking frames from the driver, so a quiet spell leaves no backlog for the next operation to chew through before its own answer.
- **A module that fails in an unexpected way no longer hides the VCI behind it** — the search continues, while a VCI-side drop (`0x11`) still gets its retry after 4 s.
- **A single bad frame no longer kills the link.** A result longer than one CAN frame is a normally retried error (memory reads retry it) and the link stays usable.
- **Quitting during a write** no longer closes the driver's links from under a running operation. A CLI run and a crash now close the link too: otherwise the VCI was left with a live monitor and the next session died 2 s in.
- **Editing DataFlash no longer rolls back records the gateway updated itself.** Only the blocks you changed are written; blocks the gateway changed since the backup stay as they are; if you and the gateway changed the same block, the write stops before any erase command and asks for a fresh backup. In a real user report this had rolled back two NvM records (`0xF040`, `0xF080`).
- **A clear error when the ECU stays silent on the factory RAM-Loader entry.** It used to read `No CAN frame from 0x77A within 2.5s`, which names the transport instead of the step. It now says plainly that the ECU answered the requests before it, so the link works, but reading memory over CAN did not succeed on this ECU.
- **A problem report now carries the driver log that holds the error.** The oldest log of the window was taken, filling the report with the trace of a *successful* read. The newest one is taken now, and a log over 8 MB goes in as its tail — the error is at the end.

### 🇬🇧 Added
- **D-PDU driver selection.** Every installed driver is its own row in the Connection window, with its variant and version (`OE`, `OS`, `VCTOOL`…). ODIS-E by default, and the choice is remembered. Before, the ODIS-E variant was always used, with no way out if that was the one your adapter disliked.
- **Your own driver next to the program.** A `dpdu/` folder beside ContiTool is scanned for `PDUAPI*.dll` and whatever is found is listed first — no installation, no registry entry, no administrator rights, for a PC where the driver is missing or the installed one does not fit. 32-bit builds are skipped. ContiTool ships no driver itself.
- **Boot software version (DID `F180`)** is read with the rest of the identification: the factory RAM-Loader entry depends on it, not on the application version.
- FAQ: whether ODIS is needed (no, the standalone VW D-PDU API package is enough), how to pick another driver, how to put your own into `dpdu/`.

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
