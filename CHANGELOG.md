# Changelog / История изменений

## 2.0.1e — 2026-11-09

По отчёту на 2.0.1d: после записи CodeFlash блок замолкал на входе в RAM-Loader.
From a 2.0.1d report: after a CodeFlash write the gateway went silent on the RAM-Loader entry.

### 🇷🇺 Исправлено
- **После записи CodeFlash через ContiTool блок переставал отвечать на входе в RAM-Loader** — и сверка записанного, чтение и следующая запись на нём не проходили. Причина — наш отпечаток программирования: в `2E F15A` ContiTool до 2.0.1d писал серийник тестера `01 02 03 04 05 06`. Загрузчик хранит отпечаток последней записью F15B, а ответ на подготовительное чтение входа выходит за его буфер и кладёт байты этой записи на служебные ячейки, в том числе на флаг «не отвечать». Отсюда и «перепрошивка через ODIS лечит»: ODIS перезаписывает отпечаток. Теперь серийник нулевой, как в заводской записи.
- **Блоки, уже прошитые старой версией, больше не останавливают вход.** Ответ на подготовительное чтение для входа не нужен: второй такой запрос загрузчик не подтверждает никогда, и вход при этом работает. Если первый промолчал, ContiTool продолжает вход и записывает F15B блока в отчёт. Следующая запись CodeFlash заменит отпечаток на правильный.
- **Объяснение молчания из 2.0.1d было неверным.** Байт, который мы считали проверочным, во всех рабочих журналах равен нулю. Пересборка запроса под блок удалена.
- **Видно, почему запись идёт без ISO-TP адаптера.** Если аппаратный ISO-TP не включился, причина (например, «3E 00: нет ответа») пишется в журнал и в результат записи.

### 🇬🇧 Fixed
- **After a CodeFlash write through ContiTool the gateway stopped answering on the RAM-Loader entry** — so verifying the write, reading and the next write on it all failed. The cause was our programming fingerprint: up to 2.0.1d ContiTool wrote the tester serial `01 02 03 04 05 06` in `2E F15A`. The bootloader keeps the fingerprint as the last F15B record, and the answer to the entry's staging read overruns its buffer and lands bytes of that record on its state cells, the suppress-response flag among them. That is also why "a reflash through ODIS cures it": ODIS rewrites the fingerprint. The serial is now zero, as in the factory record.
- **Gateways already flashed by an older version no longer stop the entry.** The entry does not need the answer to the staging read: the bootloader never confirms the second one either, and the entry works all the same. When the first goes unanswered, ContiTool carries on and puts the gateway's F15B into the report. The next CodeFlash write replaces the fingerprint with a correct one.
- **The 2.0.1d explanation of the silence was wrong.** The byte we took for a gate is zero on every working log. Rebuilding the request for the gateway is gone.
- **It shows why a write runs without the adapter's ISO-TP.** When the hardware ISO-TP does not come up, the reason (e.g. "3E 00: no answer") goes into the log and the write result.

## 2.0.1d — 2026-11-09

По отчётам на 2.0.1b и 2.0.1c: медленная запись через VNCI и обрыв на середине, блоки, оставшиеся в загрузчике, и молчание при входе в RAM-Loader.
From the 2.0.1b and 2.0.1c reports: slow VNCI writes that broke off halfway, gateways left in the bootloader, and silence on the RAM-Loader entry.

### 🇷🇺 Исправлено
- **Запись CodeFlash через VAS 6154 / VNCI шла 0,9 КБ/с и обрывалась ошибкой «очередь отправки VCI переполнена».** Каждый кадр CAN был отдельным обращением к VCI по сети (~7 мс), так что блок 514 байт уходил 74 обращениями и почти всё время уходило на дорогу до адаптера, а не на запись. Теперь вся сессия программирования идёт одним каналом через ISO-TP самого VCI, как у ODIS: блок — одно обращение, кадры нарезает и Flow Control обрабатывает сам адаптер. Так же загружаются наборы ZDC. Если ISO-TP адаптера откажет на каком-то запросе, этот запрос уходит повторно обычным путём, и запись продолжается — блок не остаётся стёртым.
- **«Очередь отправки VCI переполнена» говорилось не о том.** Очередь не переполнялась: после ~125 тысяч кадров на одном канале VCI переставал подтверждать отправку и перезапускал свою службу. Канал сырого CAN теперь переоткрывается между пакетами каждые 20 000 кадров (между операциями — от 5 000), а сообщение называет обе настоящие причины: кадр никто не подтверждает на шине (питание блока, провода, терминатор 120 Ом) или завис сам VCI.
- **Мёртвый канал больше не ждёт таймаут на каждом кадре.** Ожидание отправки кадра снова 1 с, а после отказа канала следующие кадры отклоняются сразу, без минут ожидания в повторах вокруг сброса.
- **Блок, оставшийся в загрузчике FBL после записи, больше не считается успехом.** `10 03 → 50 03` отвечает и загрузчик, поэтому работа приложения теперь подтверждается чтением `F197` или `0600` — этих идентификаторов в таблице загрузчика нет. Это касается и чтения/бэкапа: если исправный блок после операции остался в FBL, это ошибка, а не «готово».
- **Блок в загрузчике FBL распознаётся.** После оборванной записи (`10 03 → 7F 10 7E`) и после включения со стёртым приложением (загрузчик в Default Session) проверка связи, вход в RAM-Loader, сбросы и запись проходят штатно. Отказ предусловий программирования (`27 03`, `31 01 0203`) больше не останавливает вход — решает ответ на `10 02`, как в 2.0.1c.
- **Вход в RAM-Loader на блоках, где он молчал.** Ответ на подготовительное чтение не помещается в буфер загрузчика, и последние восемь байт ложатся на его служебные ячейки; одну из них загрузчик проверяет и, если она не подходит, не отвечает вовсе. Значение берётся из записи F15B, которую переписывает прошивка, — поэтому на одних блоках работало, на других нет, а перепрошивка «лечила». Если проверенная последовательность осталась без ответа, ContiTool читает идентификаторы этого блока и собирает запрос так, чтобы на служебные ячейки легли допустимые значения. Байт проверки и прочитанные длины сохраняются в отчёте.
- **В отчёт о проблеме попадают журналы драйвера, через который шла работа.** Раньше, если за время операции новых журналов не было, подкладывались два последних файла любого драйвера — например, VCTool часовой давности вместо ODIS-S.
- J2534: ответ сверяется с запросом, запоздавшие ответы отбрасываются, ожидание после `7F xx 78` — честные P2/P2*.

### 🇷🇺 Добавлено
- **Кнопка «Залить бэкап…»** на карточке блока на стартовом экране.
- **Блок в загрузчике виден сразу.** «Проверить связь» показывает «Блок отвечает (в режиме загрузчика FBL)», а «Считать блок» на таком блоке предупреждает, что основная прошивка не запущена, и предлагает залить бэкап.
- **Напоминание обновить прошивку VAS 6154 / VNCI** — в окне подключения при выборе адаптера и в FAQ.
- Аппаратный ISO15765 для прошивки через адаптеры J2534 и отправка Consecutive Frame пачкой.
- **«Создать отчёт…» открывает форму issue «Проблема» уже заполненной** — операция, ошибка, окружение и журнал разложены по полям; остаётся описать, что делали, и перетащить архив.

### 🇷🇺 Лицензия и репозиторий
- **У ContiTool появилась лицензия:** PolyForm Noncommercial 1.0.0 с дополнительными условиями. Код открыт; бесплатно для личного и некоммерческого использования и для платного ремонта и диагностики; продавать программу, копии и доступ к ней нельзя; доработанные версии — только с открытым исходником на тех же условиях и с указанием автора. Подробно — в `LICENSE` и README.
- Тексты лицензий ContiTool и сторонних компонентов (Qt / PySide6 и python-can под LGPL-3.0 и др., `THIRD_PARTY_NOTICES.md`) теперь лежат в каждой сборке.
- В репозитории: формы issue («Проблема», «Предложение»), Discussions для вопросов, `CONTRIBUTING.md`, `SECURITY.md` с приватной отправкой уязвимостей и правила поведения.

### 🇬🇧 Fixed
- **Writing CodeFlash through a VAS 6154 / VNCI ran at 0.9 KB/s and broke off with "the VCI send queue is full".** Every CAN frame was a separate round trip to the VCI over the network (~7 ms), so a 514-byte block took 74 of them and nearly all the time went on reaching the adapter rather than writing. The whole programming session now runs on one link through the VCI's own ISO-TP, as ODIS does: one request per block, with the adapter cutting the frames and handling Flow Control itself. ZDC datasets are uploaded the same way. Should the adapter's ISO-TP fail on a request, that request goes again on the regular path and the write carries on — the gateway is not left erased.
- **"The VCI send queue is full" was about something else.** No queue overflowed: after ~125,000 frames on one link the VCI stopped confirming sends and restarted its service. The raw CAN link is now reopened between packets every 20,000 frames (from 5,000 between operations), and the message names both real causes: nothing on the bus acknowledges the frame (ECU power, wiring, 120 Ω terminator), or the VCI itself hung.
- **A dead link no longer waits out a timeout on every frame.** A frame send waits 1 s again, and once the link has failed the next frames are refused at once instead of minutes of waiting in the retries around a reset.
- **A gateway left in its FBL bootloader after a write is no longer reported as success.** The bootloader answers `10 03 → 50 03` too, so a running application is now confirmed by reading `F197` or `0600`, which the bootloader's table does not have. The same goes for reads and backups: a healthy gateway left in FBL afterwards is an error, not "done".
- **A gateway in its FBL bootloader is recognised.** After an interrupted write (`10 03 → 7F 10 7E`) and after power-up with an erased application (bootloader in Default Session), the link check, RAM-Loader entry, resets and writes work as usual. A refused programming precondition (`27 03`, `31 01 0203`) no longer stops the entry — the answer to `10 02` decides, as in 2.0.1c.
- **RAM-Loader entry on gateways where it stayed silent.** The answer to the staging read does not fit the bootloader's buffer, and its last eight bytes land on the bootloader's own state cells; it checks one of them and, if the value is wrong, does not answer at all. That value comes from the F15B record, which a flash rewrites — which is why it worked on some gateways and not others, and why a reflash "cured" it. When the verified sequence goes unanswered, ContiTool reads this gateway's identifiers and lays the request out so the state cells receive acceptable values. The checked byte and the lengths read go into the report.
- **Problem reports carry the logs of the driver the operation ran on.** When no new log had been written during the operation, the last two files of any driver were taken instead — for example VCTool logs from an hour earlier in place of ODIS-S.
- J2534: answers are matched to their request, late answers are dropped, and the wait after `7F xx 78` uses proper P2/P2*.

### 🇬🇧 Added
- **A "Write backup…" button** on the bench ECU card of the start screen.
- **A gateway in the bootloader shows at once.** "Check link" reports "ECU answers (in FBL bootloader mode)", and "Read ECU" on such a gateway warns that the main firmware is not running and offers to write a backup.
- **A reminder to update the VAS 6154 / VNCI firmware** — in the connection dialog when that adapter is chosen, and in the FAQ.
- Hardware ISO15765 for flashing through J2534 adapters, and Consecutive Frames sent in batches.
- **"Create report…" opens the "Problem" issue form already filled in** — operation, error, environment and log each in their own field; describe what you did and drag the archive in.

### 🇬🇧 License & repository
- **ContiTool now has a license:** the PolyForm Noncommercial 1.0.0 with Additional Terms. The code is open; it is free for personal and noncommercial use and for paid repair and diagnostics; selling the program, copies of it or access to it is not allowed; changed versions only with their source open under the same terms and with the author credited. Details in `LICENSE` and the README.
- The license texts of ContiTool and of the bundled components (Qt / PySide6 and python-can under the LGPL-3.0, and others — `THIRD_PARTY_NOTICES.md`) now ship in every build.
- In the repository: issue forms ("Problem", "Feature request"), Discussions for questions, `CONTRIBUTING.md`, `SECURITY.md` with private vulnerability reporting, and a code of conduct.

## 2.0.1c — 2026-11-09

По отчётам на 2.0.1b: адаптеры, которые отказывают в сыром CAN.
From the 2.0.1b reports: adapters that refuse raw CAN.

### 🇷🇺 Исправлено
- **`PDUCreateComLogicalLink: D-PDU error 0x01` сразу после удачного подключения модуля.** ContiTool выбирал модуль по тому, что тот **принял подключение**, — а это ничего не доказывает: чужой драйвер J2534 подключается спокойно и отказывает уже на сыром канале CAN. Теперь канал открывается внутри перебора, и модуль считается нужным, только когда связь реально поднялась; не поднялась — берётся следующий кандидат.
- **Любой отказ в сыром канале объясняется словами**, с именем адаптера и кодом, вместо голого `0x01` или `0x50`. Раньше понятный текст показывался только для `0x50`.
- Если кандидат один, показывается его собственная причина, а не обобщённая сводка: при нескольких кандидатах сводка дополнена причиной последнего.

### 🇷🇺 Добавлено
- **Запасной режим для адаптеров без RawMode.** Часть VAS 6154 / VNCI (в том числе вполне настоящих) отказывает в сыром канале CAN — отказ приходит от самого адаптера, на всех драйверах. Для них ContiTool теперь пробует связь в стиле ODIS: по одному каналу на пару идентификаторов (`0x710/0x77A` и `0x6F0/0x6F1`), с адресацией через таблицу URID. Идентификаторы объектов не захардкожены — программа спрашивает их у драйвера по имени.
- **Запасной режим проверяет сам себя.** После открытия каналов отправляется один `10 03`, и без ответа адаптер честно объявляется неподдерживаемым. Открыться — ещё не значит работать: это защита от «наполовину работающей» сессии.

### 🇷🇺 Известно
- Запасной режим **не проверен на железе**: ни один адаптер без RawMode нам пока недоступен. На адаптерах, где сырой CAN работает, путь кода недостижим и ничего не меняет. Отчёты с результатом приветствуются.

### 🇬🇧 Fixed
- **`PDUCreateComLogicalLink: D-PDU error 0x01` right after the module connected.** ContiTool picked the module that **accepted a connection**, which proves nothing: another vendor's J2534 driver connects happily and only then refuses the raw CAN channel. The links are now opened inside the candidate loop, so a module counts as the right one only once communication is actually up; if it is not, the next candidate is tried.
- **Any refusal of the raw channel is now explained in words**, naming the adapter and the code, instead of a bare `0x01` or `0x50`. Before, only `0x50` produced a readable message.
- With a single candidate its own reason is shown instead of a summary; with several, the summary carries the last reason too.

### 🇬🇧 Added
- **A fallback for adapters without RawMode.** Some VAS 6154 / VNCI units — genuine ones included — refuse the raw CAN channel, and the refusal comes from the adapter itself on every driver. For those ContiTool now tries the ODIS-style link: one per identifier pair (`0x710/0x77A` and `0x6F0/0x6F1`), addressed through the URID table. Object ids are not hardcoded; they are asked from the driver by name.
- **The fallback verifies itself.** Once the links are up it sends one `10 03`, and without an answer the adapter is honestly reported as unsupported. Opening is not the same as working, and a half-working session helps nobody.

### 🇬🇧 Known
- The fallback is **not hardware-verified**: no adapter without RawMode is available to us yet. On adapters where raw CAN works the code path is unreachable and changes nothing. Reports welcome.

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
