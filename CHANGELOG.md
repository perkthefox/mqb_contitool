# Changelog / История изменений

## 2.1.0 — 2026-11-13

### 🇷🇺 Добавлено
- **Чтение и расшифровка внешней SPI EEPROM (`ST M95640`, 8 КБ) и опционных байтов `OPBT` (`OPBT0..OPBT8`, 36 Б):** выполняются в режиме «только чтение» через аппаратные апплеты RH850/F1L (`CSIH1` и окно `Extra Area`) без привязки к версии прошивки шлюза.
  - Полное чтение блока по CAN автоматически сохраняет `Eeprom.bin` и `Opbt.bin` вместе с основными дампами (`--no-extras` в CLI отключает это). Если `EEPROM` или `OPBT` прочитать не удалось, основной бэкап (`CodeFlash`, `Uflash`, `DataFlash`) не прерывается — ContiTool сохраняет его и выводит предупреждение (Warning).
  - На экране блока добавлен раздел **«EEPROM и OPBT»** с расшифровкой паспорта `NvM 0x00`, VIN, кодировки `0x0600`, списка оборудования `0x04A3`, АКБ `BEM`, блока безопасности `NvM 0x5E` (маска обученных слотов CP, `Master CP`, `Showroom`, инженерные флаги `0x80/0x81/0x83`), проверкой `CRC-16/CCITT-FALSE` по всем записям и битовой расшифровкой `OPBT0` / `OPBT8 (ICU-S)`.
  - В CLI добавлены команды `can read-eeprom`, `can read-opbt` и флаги `inspect --eeprom` / `--opbt`.
- **Редактор профилей движения (`FPA`):** добавлена поддержка целевых режимов `On` / `Off` (`0x0300`) и непрерывного 15-ступенчатого слайдера жёсткости подвески `DCC` (`Step 1..15`, атрибут `0xFFFE` в профиле `Individual`).

### 🇷🇺 Исправлено
- **Редактор профилей движения (`FPA`, #24):** исправлен каталог функциональных групп `CharismaFunctions` (`0x01..0x1C` — `Motor`, `Getriebe`, `Lenkung`, `DCC`, `ACC`, `Kurvenlicht`, `Klima`, `Bussound` и др.), порядок целевых режимов (`8: On`, `9: Off`, `10: Snow`), Big-Endian формула байта `PaCo` (`12 - (pbit - 1) // 8`) и список силовых групп `KL15` (`0x04 EDS` больше не помечается как требующая перезапуска двигателя).
- **Загрузка параметрии ZDC по CAN (#26):** по UDS теперь выгружаются только реально изменённые блоки датасета вместо перезаписи всех непустых блоков; адреса `RequestDownload (0x34)` определяются динамически из таблицы прошивки `CodeFlash` (если дамп открыт), а при отказе `7F 34 31` / `7F 34 70` выводится понятное объяснение с предложением записать `DataFlash` через RAM-Loader.
- **VAS 6154 / VNCI (D-PDU, #10, #23):** после автоматического обновления прошивки адаптера драйвером D-PDU добавлено повторное переподключение при перезагрузке USB-интерфейса VCI; ID ресурса `RawCAN` теперь определяется из `MDF`-файла драйвера с резервным перебором `0x10000`.
- **Неподдерживаемые шлюзы `5Q0` и `Lear` (#8, #13, #14, #15):** проверка аппаратной платформы добавлена непосредственно перед входом в RAM-Loader во всех CAN-операциях, чтобы исключить неинформативную ошибку `7F 22 31` на блоках MPC5607B / MPC5748G.

### 🇬🇧 Added
- **Read-only backup and decoding of external SPI EEPROM (`ST M95640`, 8 KB) and RH850 Option Bytes (`OPBT0..OPBT8`, 36 B):** read over Diagnosis CAN via firmware-independent RH850/F1L hardware applets (`CSIH1` SPI and `Extra Area` window) that restore all peripheral registers before returning.
  - Full CAN backups automatically include `Eeprom.bin` and `Opbt.bin` alongside the main flash areas (`--no-extras` in CLI skips them). If `EEPROM` or `OPBT` cannot be read, the main backup (`CodeFlash`, `Uflash`, `DataFlash`) does not abort — ContiTool saves it cleanly and shows a Warning.
  - Added the **“EEPROM & OPBT”** service page in the GUI with full decoding of `NvM 0x00` passport, VIN, coding `0x0600`, installation list `0x04A3`, `BEM` battery data, `NvM 0x5E` security state (learned CP slot mask, `Master CP`, `Showroom`, `0x80/0x81/0x83` engineering flags), per-record `CRC-16/CCITT-FALSE` verification, and `OPBT0` / `OPBT8 (ICU-S)` bitfields.
  - Added CLI subcommands `can read-eeprom`, `can read-opbt`, and `inspect --eeprom` / `--opbt`.
- **Driving-profile editor (`FPA`):** added support for `On` / `Off` (`0x0300`) target modes and the 15-step continuous `DCC` damping slider (`Step 1..15`, `0xFFFE` in `Individual`).

### 🇬🇧 Fixed
- **Driving-profile editor (`FPA`, #24):** fixed the `CharismaFunctions` group catalog (`0x01..0x1C` — `Engine`, `Gearbox`, `Steering`, `DCC`, `ACC`, `AFS`, `Climatronic`, `Interior sound`, etc.), target mode mapping (`8: On`, `9: Off`, `10: Snow`), Big-Endian `PaCo` byte indexing (`12 - (pbit - 1) // 8`), and `KL15` powertrain group tagging (`0x04 EDS` is no longer flagged as requiring an ignition cycle).
- **ZDC dataset upload over CAN (#26):** UDS upload now sends only the ZDC blocks actually modified since the base `DataFlash` read; `RequestDownload (0x34)` addresses are resolved dynamically from the open `CodeFlash` image when available, and `7F 34 31` / `7F 34 70` rejections report a clear explanation suggesting RAM-Loader `DataFlash` write.
- **VAS 6154 / VNCI (D-PDU, #10, #23):** added reconnect retries while the VCI reboots over USB right after a D-PDU firmware update, and dynamic `RawCAN` resource ID lookup from the driver's `MDF` file with fallback to `0x10000`.
- **Unsupported `5Q0` and `Lear` gateways (#8, #13, #14, #15):** added an upfront platform check inside `enter_ram_loader` across all CAN workflows so MPC5607B / MPC5748G units report a clear unsupported-hardware error instead of failing with `7F 22 31`.

## 2.0.4 — 2026-11-11

### 🇷🇺 Добавлено
- **Драйвер D-PDU 27.2 в комплекте (Windows):** лежит в `dpdu/VW_PDUAPI_27.2` рядом с программой и выбирается по умолчанию для VAS 6154 / VNCI. При подключении драйвер сам записывает в адаптер прошивку своей версии (около 30 секунд) — не отключайте адаптер до конца. Это безопасно: ODIS при следующем подключении так же запишет в адаптер свою версию. USB-драйвер адаптера (дополнение для VAS 6154) должен быть установлен в системе.
- **VAS 6154 / VNCI:** пока запущены ODIS или VCTool, ContiTool к адаптеру не подключается и пишет, что закрыть.

### 🇷🇺 Изменено
- **Драйверы D-PDU 30 и новее:** работа на них сейчас нестабильна — адаптер зависает посреди прошивки по UDS, примерно на 550-м блоке из 2975. Без вопросов работает только 27.2; для остальных версий в окне «Подключение» нужна отдельная галочка.
- **VAS 6154 / VNCI:** убрано переподключение к VCI во время длинной передачи, добавленное в 2.0.3b: зависание оно не предотвращало.

### 🇷🇺 Исправлено
- **CANable (SLCAN), запись приложения по UDS:** с версии 2.0.3 скорость упала примерно до 3,9 КБ/с — перед каждым запросом программа 0,1 с ждала пустой порт. Ожидание убрано.
- **VAS 6154 / VNCI:** если VCI отключился посреди прошивки на драйвере 30 и новее, сообщение советует перейти на драйвер 27.2, а не запускать ту же прошивку заново.
- **Отчёт о проблеме:** в архив попадают журналы и того драйвера D-PDU, что идёт вместе с программой.

### 🇬🇧 Added
- **D-PDU driver 27.2 included (Windows):** it sits in `dpdu/VW_PDUAPI_27.2` next to the program and is picked by default for a VAS 6154 / VNCI. On connect the driver itself writes firmware of its version into the adapter (about 30 seconds) — do not unplug the adapter until it finishes. This is safe: ODIS writes its own version back into the adapter the next time it connects. The adapter's USB driver (the VAS 6154 add-on) has to be installed on the PC.
- **VAS 6154 / VNCI:** while ODIS or VCTool is running, ContiTool does not connect to the adapter and says what to close.

### 🇬🇧 Changed
- **D-PDU drivers 30 and newer:** work on them is unstable at the moment — the adapter hangs partway through a UDS flash, around block 550 of 2975. Only 27.2 runs without asking; any other version needs a separate tick in the Connection dialog.
- **VAS 6154 / VNCI:** the reconnect to the VCI during a long transfer, added in 2.0.3b, is removed: it did not prevent the hang.

### 🇬🇧 Fixed
- **CANable (SLCAN), application write over UDS:** since 2.0.3 the speed had dropped to about 3.9 KB/s — before every request the program waited 0.1 s on an empty port. The wait is gone.
- **VAS 6154 / VNCI:** when the VCI drops off mid-flash on a driver 30 or newer, the message says to switch to driver 27.2 instead of running the same flash again.
- **Problem report:** the archive also takes the logs of the D-PDU driver that comes with the program.

## 2.0.3b — 2026-11-10

### 🇷🇺 Добавлено
- **Прошивка из ODX:** кроме `.frf` ContiTool принимает обычный файл ODIS `FL_…_S.odx` («Файл → Прошить FRF / ODX ODIS…»). Проверки те же: подпись, CRC и список блоков, для которых файл предназначен.

### 🇷🇺 Исправлено
- **VAS 6154 / VNCI, запись приложения по UDS:** VCI переставал отвечать примерно на 553-м блоке из 2975. Теперь во время длинной передачи ContiTool переподключается к VCI между блоками задолго до этой точки, блок этого не замечает.
- **VAS 6154 / VNCI:** если VCI всё же отключился посреди прошивки, ContiTool прямо пишет, что делать, вместо обещания «продолжить программным путём».
- **VAS 6154 / VNCI:** каналы драйвера закрываются в том же порядке, что у ODIS.

### 🇬🇧 Added
- **Flashing from ODX:** besides `.frf`, ContiTool takes a plain ODIS `FL_…_S.odx` file (“File → Flash an ODIS FRF / ODX…”). Same checks: signature, CRC and the list of ECUs the file is meant for.

### 🇬🇧 Fixed
- **VAS 6154 / VNCI, application write over UDS:** the VCI stopped answering around block 553 of 2975. During a long transfer ContiTool now reconnects to the VCI between blocks well before that point; the ECU does not notice.
- **VAS 6154 / VNCI:** if the VCI still drops off mid-flash, ContiTool says plainly what to do instead of promising to "continue on the software path".
- **VAS 6154 / VNCI:** driver links are closed in the same order as ODIS closes them.

## 2.0.3a — 2026-11-10

### 🇷🇺 Изменено
- **VAS 6154 / VNCI, запись приложения по UDS:** канал аппаратного ISO-TP открывается с теми же параметрами связи, что ставит ODIS-E для шлюза по своим ODX-данным: таймауты P2/P3, ожидание `7F xx 78`, повтор при `7F xx 21`, TesterPresent. Сам VCI запросы не повторяет — как у ODIS во время передачи блоков.
- **VAS 6154 / VNCI:** о новых данных драйвер сообщает сам, как в ODIS, вместо опроса каждые полмиллисекунды. Канал отправки RAW CAN работает как раньше.

### 🇬🇧 Changed
- **VAS 6154 / VNCI, application write over UDS:** the hardware ISO-TP link opens with the same communication parameters ODIS-E sets for the gateway from its ODX data: P2/P3 timeouts, waiting on `7F xx 78`, repeating on `7F xx 21`, TesterPresent. The VCI does not repeat requests on its own — as in ODIS while blocks are transferred.
- **VAS 6154 / VNCI:** the driver reports new data by itself, as for ODIS, instead of being polled every half millisecond. The RAW CAN send link works as before.

## 2.0.3 — 2026-11-10

### 🇷🇺 Исправлено
- **Отчёт о проблеме:** в архив больше не попадают файлы ключей (папка `ContiTool_keys`, `*.pem`, JSON с закрытым ключом). FAZIT и VIN скрываются и в имени папки блока, путь к домашней папке заменяется на `~`.
- **Изменённый DataFlash считался уже записанным** после записи параметрии по CAN: «Записать в блок» писал только CodeFlash.
- **Запись только загрузочных блоков CodeFlash** заканчивалась ошибкой сверки по адресу 0xC100 при верной записи, и блок оставался в RAM-Loader.
- **Закрытие программы во время операции** обрывало её на середине. Теперь программа ждёт, пока операция остановится (запись во Flash — пока закончится), и закрывается сама.
- **Остановка во время записи:** журнал записи теперь верно показывает, что запись выполнена; при восстановлении выводится предупреждение об оставленном инженерном загрузчике.
- **VAS 6154 / VNCI:** чтение и запись могли оборваться после пересоздания канала отправки и при повторной ошибке кадра во время чтения.
- **Блок в загрузчике (приложение стёрто):** чтение памяти завершалось ошибкой, а CodeFlash такого блока не опознавался как дамп шлюза.
- **Восстановление одного DataFlash:** владелец сверяется по VCRN, раньше сравнить было нечем.
- **Редактор профилей движения:** сохранение без изменений меняло кольцо кнопки руля; сохранение во время «Определить нажатие по CAN» теряло правки; нехватка свободного входа под кнопку приводила к сбою вместо сообщения.
- Кнопки экрана блока оставались активными во время операции; результаты операции (DTC, SWaP, считанный загрузчик) попадали в другой блок, открытый до её конца.
- **Windows:** пути со скобками, `#` и `~` портились в командной строке и при перетаскивании файла.
- Ключ RSA строкой из 256 hex-цифр не принимался в сборках для macOS и Linux.
- **Командная строка:** `set-rsa-key --target fbl` менял ключ SWaP в DataFlash; `sign-fsc` принимал FeC и время, не помещающиеся в 32 бита; в сборке без консоли команды не выполнялись.

### 🇷🇺 Изменено
- **Командная строка:** параметры, которые раньше молча игнорировались (`--mfl-key` без `--button-mode`, `--fpa-preset` без `--auto-parameterize` и подобные), теперь дают ошибку с названием нужного параметра.
- **CAN-терминал, режим UDS:** ID больше 7FF отклоняется с сообщением; раньше такой запрос уходил 11-битным кадром.
- При запуске через `python -m contitool` папка `contitool_runs` создаётся в текущей папке, а не внутри установленного пакета.

### 🇬🇧 Fixed
- **Problem report:** key files no longer go into the archive (the `ContiTool_keys` folder, `*.pem`, a JSON holding a private key). FAZIT and VIN are hidden in the gateway folder name too, and the home folder path becomes `~`.
- **An edited DataFlash counted as already written** after a dataset write over CAN: “Write to ECU” wrote CodeFlash only.
- **Writing only the boot blocks of CodeFlash** ended in a readback mismatch at 0xC100 after a correct write, leaving the ECU in the RAM-Loader.
- **Quitting during an operation** cut it off halfway. ContiTool now waits for the operation to stop (a flash write — to finish) and then quits by itself.
- **Stopping during a write:** the write log now correctly says the write was performed; a restore warns that the engineering bootloader stays in the ECU.
- **VAS 6154 / VNCI:** a read or write could break off after the send link was reopened, or on a second frame error during a read.
- **ECU in its bootloader (application erased):** the memory read ended in an error, and such a CodeFlash was not recognised as a gateway dump.
- **Restoring DataFlash alone:** the owner is checked by VCRN; there used to be nothing to compare.
- **Driving-profile editor:** saving with nothing changed altered the wheel-button ring; saving during “Detect press over CAN” lost the edits; no free input for a button caused a crash instead of a message.
- ECU-screen buttons stayed enabled during an operation; the results of an operation (DTCs, SWaP, the bootloader read back) went to another gateway opened before it ended.
- **Windows:** paths with brackets, `#` or `~` were corrupted on the command line and on file drop.
- An RSA key given as a 256-digit hex string was refused in the macOS and Linux builds.
- **Command line:** `set-rsa-key --target fbl` changed the SWaP key in DataFlash; `sign-fsc` took a FeC or time that does not fit in 32 bits; commands did not run in a build without a console.

### 🇬🇧 Changed
- **Command line:** options that used to be silently ignored (`--mfl-key` without `--button-mode`, `--fpa-preset` without `--auto-parameterize` and the like) are now an error naming the option they need.
- **CAN terminal, UDS mode:** an ID above 7FF is refused with a message; such a request used to go out as an 11-bit frame.
- Started with `python -m contitool`, the `contitool_runs` folder is created in the working folder, not inside the installed package.

## 2.0.2b — 2026-11-10

### 🇷🇺 Добавлено
- **Прошивка FRF ODIS по UDS** («Файл → Прошить FRF ODIS…»). Приложение из FRF идёт с его собственной подписью, поэтому его принимает и заводской загрузчик — без RAM-Loader и без инженерного загрузчика, как у ODIS. Подпись FRF ContiTool сначала проверяет сам ключом загрузчика этого блока (из его последнего чтения, без чтения — заводским; если ключ в блоке заменён своим, FRF ODIS он не примет): с неверной подписью FRF не прошивается и блок не стирается. Затем сверяет номер детали, версию ПО и оборудование блока со списками допуска FRF: на другое оборудование не прошивает, а то, на что ODIS не стал бы лить, — только после подтверждения. Серийник тестера в отпечатке пишется нулевым.
- **Лечение закрытого входа в RAM-Loader без бэкапа:** в окне лечения можно выбрать FRF вместо CodeFlash этого блока.
- FRF длиннее 727 369 Б (например, 3Q0907530BF 5585) ContiTool пока не расшифровывает и говорит об этом сразу.

### 🇷🇺 Изменено
- **Шайба 4MOTION Active Control.** В редакторе профилей шайбу можно добавить так, как она настроена в заводском датасете Tiguan 2019: положения Snow, On-road, Offroad и Offroad Individual. Шайба заменяет кнопку MODE на консоли. Нужны сама шайба и FEC 10001400, 10001800, 10001900.
- Слот 9 профилей теперь Offroad Individual (ID 0x0B), как в Tiguan; раньше там был неподтверждённый ID 0x09.
- **Меньше лишних чтений перед записью.** Перед записью читается только та область, которая пишется, после — проверка чтением. Полная копия памяти снимается, только если этот блок ещё ни разу не читался целиком: остальные области запись не меняет, а их копия уже лежит в папке блока. Запись DataFlash или загрузчика стала примерно на минуту короче.
- **Окно «Подключение к блоку»** больше не меняет размер и не прокручивается вбок: длинные строки переносятся, путь к папке сокращается.
- **Изменена только параметрия — пишется штатно.** Если в DataFlash правились только датасеты, панель изменённых дампов предлагает «Записать параметрию по CAN» (UDS, с проверкой SWaP и кодировки) вместо записи всего DataFlash через RAM-Loader.
- **Страница «Параметрирование»:** запись по CAN, экспорт, импорт ODIS и паспорт собраны в один блок наверху, проверка кнопки руля — в блоке профилей.

### 🇷🇺 Исправлено
- **Windows: 2.0.2 и 2.0.2a не запускались** с ошибкой «The procedure entry point CRYPTO_calloc could not be located … libssl-3-x64.dll», если другая программа оставила в System32 несовместимую копию OpenSSL. Её подхватывала проверка обновлений через Qt. Теперь ContiTool при запуске загружает свою копию OpenSSL, и чужая из System32 не используется.
- **Редактор профилей движения переделан по прошивке шлюза.** Магнитола получает профиль, если в слоте записан его ID и для слота активен FEC. Раньше выключение профиля в редакторе меняло только маску запоминаемых профилей (S030), и профиль в меню оставался; заодно редактор ставил биты в S070, которые на самом деле включают показ смены профиля на приборной панели. Теперь выключение убирает профиль из меню, повторное включение возвращает слот как был, S070 не трогается. Для профилей, выключенных намеренно, ContiTool больше не просит «настроить параметрию под включённые функции».
- Слот Individual определяется по ID профиля, а не по S015 (это число пользователей персонализации).
- Статус FEC в блоке (`22 3C 00`) считается по тому же правилу, что и в шлюзе.
- Загрузчик другой сборки (например, у блоков с оборудованием 518) принимался за обрезанный DataFlash, и блок показывался «Uflash — нет». Теперь он определяется как загрузчик со статусом «сборка не распознана»; менять его ContiTool по-прежнему не берётся.
- **VAS 6154 / VNCI: запись CodeFlash обрывалась на середине** (#18). Пока программа ждала, что питание блока выключат и включат (NRC 0x37), запросы без ответа переводили адаптер с аппаратного ISO-TP на передачу по одному кадру, а так VCI перестаёт отправлять примерно на 125-тысячном кадре. Теперь ожидание не трогает аппаратный ISO-TP. Если он всё же не работает, запись отказывается до стирания.
- **Адаптер J2534 под видом VAS 6154** (#17). Драйвер VW D-PDU подключает и чужие драйверы J2534 (например, OpenVCX32 у VCX). Через такой драйвер raw CAN нет, и из потока памяти доходит примерно каждый пятый кадр, поэтому чтение падало через 20 секунд с ошибкой «Stream … stopped». Теперь журнал и отчёт о проблеме называют модуль D-PDU, к которому подключились. Проверка связи предупреждает, что это не VAS 6154, а вход в RAM-Loader отказывается сразу, до каких-либо действий с блоком. Если тот же адаптер установлен и как J2534 с 64-разрядным драйвером, программа предлагает выбрать его напрямую; 32-разрядные драйверы J2534 ContiTool не загружает.

### 🇬🇧 Added
- **Flashing an ODIS FRF over UDS** ("File → Flash an ODIS FRF…"). The application from the FRF goes in with the FRF's own signature, so the factory bootloader takes it too — no RAM-Loader and no engineering bootloader, as with ODIS. ContiTool first verifies the FRF's signature itself with this ECU's bootloader key (from its latest read, the factory key without one; a bootloader whose key was replaced with your own will not take an ODIS FRF): an FRF with a bad signature is refused before anything is erased. Then it checks the ECU's part number, software version and hardware against the FRF's lists: it never flashes other hardware, and what ODIS would not flash only after a confirmation. The tester serial in the fingerprint is written as zero.
- **A closed RAM-Loader entry cured without a backup:** the cure dialog takes an FRF instead of this ECU's CodeFlash.
- FRFs longer than 727,369 B (3Q0907530BF 5585, for one) cannot be decrypted yet; ContiTool says so straight away.

### 🇬🇧 Changed
- **4MOTION Active Control knob.** The profile editor can add the knob as the factory dataset of a 2019 Tiguan has it: positions Snow, On-road, Offroad and Offroad Individual. The knob replaces the console MODE button. It needs the knob itself and FECs 10001400, 10001800, 10001900.
- Profile slot 9 is now Offroad Individual (ID 0x0B), as in the Tiguan; it used to be an unconfirmed ID 0x09.
- **Fewer redundant reads before a write.** A write reads only the area it writes, then reads it back to verify. A full memory copy is taken only for a gateway that was never read completely: the other areas do not change, and their copy is already in the gateway's folder. A DataFlash or bootloader write is about a minute shorter.
- **The ECU connection dialog** keeps its size and never scrolls sideways: long lines wrap, the folder path is shortened.
- **Only the datasets changed — written the standard way.** When only datasets were edited in DataFlash, the changed-dumps bar offers “Write datasets over CAN” (UDS, with the SWaP and coding check) instead of writing the whole DataFlash through the RAM-Loader.
- **Parameterization page:** write over CAN, export, ODIS import and passport sit together in one block at the top; the wheel-button test moved into the profiles block.

### 🇬🇧 Fixed
- **Windows: 2.0.2 and 2.0.2a did not start** with “The procedure entry point CRYPTO_calloc could not be located … libssl-3-x64.dll” when another program had left an incompatible OpenSSL copy in System32. The update check through Qt picked it up. ContiTool now loads its own OpenSSL at start, so the copy in System32 is never used.
- **The driving-profile editor now follows the gateway firmware.** The head unit is offered a profile when its slot holds the profile ID and the slot's FEC is active. Switching a profile off used to change only the remembered-profile mask (S030), so the profile stayed in the menu, and the editor also set S070 bits, which really turn on the cluster's profile-change pop-up. Now switching off takes the profile out of the menu, switching it on again restores the slot as it was, and S070 is left alone. ContiTool no longer asks to “configure the datasets for enabled features” for profiles switched off on purpose.
- The Individual slot is found by its profile ID, not by S015 (the number of personalisation users).
- The FEC status read from the ECU (`22 3C 00`) uses the gateway's own rule.
- A bootloader of another build (ECUs with hardware 518, for one) was taken for a cut DataFlash and the ECU showed “Uflash — missing”. It is now recognised as a bootloader of an unrecognised build; ContiTool still refuses to modify it.
- **VAS 6154 / VNCI: a CodeFlash write broke off halfway** (#18). While the program waited for the ECU to be switched off and on (NRC 0x37), the unanswered requests moved the adapter off its hardware ISO-TP to sending frame by frame, and that way the VCI stops sending at around the 125,000th frame. The wait now leaves the hardware ISO-TP alone. If it does not work anyway, the write is refused before the erase.
- **A J2534 adapter posing as a VAS 6154** (#17). The VW D-PDU driver also connects other vendors' J2534 drivers (OpenVCX32 of a VCX, for one). Through such a driver there is no raw CAN and only about every fifth frame of a memory stream gets through, so a read failed after 20 seconds with “Stream … stopped”. The log and the problem report now name the D-PDU module actually connected. The link check warns that it is not a VAS 6154, and the RAM-Loader entry is refused at once, before anything is done to the ECU. If the same adapter is installed as a J2534 device with a 64-bit driver, the program suggests picking it directly; ContiTool does not load 32-bit J2534 drivers.

## 2.0.2a — 2026-11-09

### 🇷🇺 Исправлено
- **Редактор FPA ломал кнопку MODE и режимы полного привода на машинах с 4Motion.** Заводскую кнопку MODE (вход типа `0x05` с кольцами «дорога» и «бездорожье») он не узнавал и при любом сохранении заменял своей. Теперь кнопки и кольца машины не трогаются никогда — меняются только кнопки, которые добавил сам ContiTool (консоль, руль); режим всплывающего окна (S056) сохраняется как в стоке.

### 🇬🇧 Fixed
- **The FPA editor broke the MODE button and the 4Motion modes on 4Motion cars.** It did not know the car's own MODE button (input type `0x05` with on-road and off-road rings) and replaced it with its own on every save. The car's buttons and rings are now never touched — only the buttons ContiTool adds itself (console, wheel) change; the pop-up mode (S056) stays as in stock.

## 2.0.2 — 2026-11-09

### 🇷🇺 Исправлено
- **Заливка бэкапа на блок, застрявший в загрузчике.** Приложение пишется сразу по UDS — без RAM-Loader и без бэкапа нерабочего блока; владелец сверяется по FAZIT; сброс один, в конце. На `7F 27 37` — сброс, затем просьба передёрнуть питание, дальше без участия.
- **Сверка после заливки** сравнивает с бэкапом всё записанное, включая запись программирования загрузчика (блок 4).
- **Отмена** больше не запускает повтор, не прерывает запись на середине и после отменённого чтения возвращает блок в приложение.
- **000401 после записи DataFlash:** блоки ZDC программируются целиком.
- **000601 после пресета FPA:** пресет больше не меняет метку и год датасета.
- **Запись параметрии по CAN:** вход `27 03/04` вместо несуществующего `27 01`, блоки передачи полного размера.
- **Кодировка 0x0600** согласуется с записанными датасетами, в том числе когда CodeFlash и DataFlash пишутся вместе.
- **Аппаратный ISO-TP VAS 6154 / VNCI** настроен как у ODIS: ответ принимается только с эхом запроса (`76 <блок>`, `71 01 FF00`…), `7F xx 78` и `7F xx 21` обрабатывает адаптер. J2534 тоже сверяет эхо.
- **«Сообщить о проблеме»:** ссылка на заполненное issue укладывается в лимит GitHub; отчёт о внутренней ошибке берёт файлы только последней операции.
- Диалоги прокручиваются на небольших экранах; журнал не пишет «прошит», если записывать было нечего.

### 🇷🇺 Добавлено
- **Лечение молчащего этапа 1 входа в RAM-Loader.** Причина — ненулевой серийник тестера в отпечатке программирования (его пишут ContiTool до 2.0.1e и ODIS). ContiTool предлагает одну перепрошивку приложения по UDS с нулевым серийником из CodeFlash этого блока.
- **«Записать параметрию по CAN» готовит блок:** показывает недостающие функции SWaP и изменения кодировки, активирует SWaP, загружает датасет по UDS, согласует кодировку, предлагает стереть ошибки.
- **Папки по шлюзам:** `contitool_runs` рядом с программой, в нём `<деталь>_<FAZIT>/dumps` (`base_read`, повторные чтения, `…_flashed` с манифестом изменений) и `writes`.
- **После «Записать в блок»** открыты дампы в том виде, в каком они теперь в блоке.
- **Экспорт и импорт параметрии:** каждый заполненный блок ZDC — файлом параметрии ODIS (`.xml`, байт в байт как его пишет ODIS) и `.bin`, плюс вся область параметрии; импорт файла ODIS в DataFlash вместе с номером и версией датасета.
- **Проверка обновлений** — раз в сутки и из меню «Справка».
- **Дампы в отчёте о проблеме** — по галочке; архив выделяется в папке, чтобы перетащить его в issue.

### 🇬🇧 Fixed
- **Writing a backup to a gateway stuck in its bootloader.** The application goes in over UDS at once — no RAM-Loader, no backup of a dead unit; the owner is checked by FAZIT; one reset, at the end. On `7F 27 37`: a reset, then a request to power-cycle, after which it carries on by itself.
- **The check after a restore** compares everything written with the backup, the bootloader's programming record (block 4) included.
- **Cancel** no longer starts a retry, never stops a write halfway, and after a cancelled read hands the gateway back to its application.
- **000401 after a DataFlash write:** ZDC blocks are programmed in full.
- **000601 after an FPA preset:** the preset no longer changes the dataset's tag and year.
- **Writing datasets over CAN:** login `27 03/04` instead of the non-existent `27 01`, full-size transfer blocks.
- **Coding 0x0600** is aligned with the written datasets, also when CodeFlash and DataFlash are written together.
- **VAS 6154 / VNCI hardware ISO-TP** is set up as ODIS sets it: an answer counts only when it echoes the request (`76 <block>`, `71 01 FF00`…); `7F xx 78` and `7F xx 21` are handled by the adapter. J2534 checks the echo too.
- **"Report a problem":** the prefilled issue link stays within GitHub's limit; an internal-error report takes only the last operation's files.
- Dialogs scroll on small screens; the log no longer says "programmed" when nothing was written.

### 🇬🇧 Added
- **Cure for a silent stage 1 of the RAM-Loader entry.** The cause is a non-zero tester serial in the programming fingerprint (written by ContiTool before 2.0.1e and by ODIS). ContiTool offers one reflash of the application over UDS with a zero serial, from this ECU's CodeFlash.
- **"Write datasets over CAN" prepares the ECU:** shows the missing SWaP features and the coding changes, activates the SWaP, uploads the datasets over UDS, aligns the coding, offers to clear the trouble codes.
- **Per-gateway folders:** `contitool_runs` next to the program, holding `<part>_<FAZIT>/dumps` (`base_read`, later reads, `…_flashed` with a manifest of changes) and `writes`.
- **After "Write to ECU"** the loaded dumps are what the ECU now holds.
- **Dataset export and import:** every populated ZDC block as an ODIS parameterization file (`.xml`, byte for byte as ODIS writes it) and as `.bin`, plus the whole dataset area; an ODIS file imports into DataFlash with its dataset number and version.
- **Update check** — once a day and from the Help menu.
- **Dumps in a problem report** — when ticked; the archive is selected in its folder, ready to drag into the issue.

## 2.0.1e — 2026-11-09

По отчётам на 2.0.1d: после записи CodeFlash блок замолкал на входе в RAM-Loader, а запись через VAS 6154 / VNCI обрывалась на середине.
From the 2.0.1d reports: after a CodeFlash write the gateway went silent on the RAM-Loader entry, and writing through a VAS 6154 / VNCI broke off halfway.

### 🇷🇺 Исправлено
- **После записи CodeFlash через ContiTool блок переставал отвечать на входе в RAM-Loader** — и сверка записанного, чтение и следующая запись на нём не проходили. Причина — наш отпечаток программирования: в `2E F15A` ContiTool до 2.0.1d писал серийник тестера `01 02 03 04 05 06`. Загрузчик хранит отпечаток последней записью F15B, а ответ на подготовительное чтение входа выходит за его буфер и кладёт байты этой записи на служебные ячейки, в том числе на флаг «не отвечать». Теперь серийник нулевой, как в заводской записи. *(Поправка: «перепрошивка через ODIS лечит» неверно — ODIS пишет свой серийник и с ненулевым тоже закрывает вход; см. 2.0.2.)*
- **Блоки, уже прошитые старой версией, вход по-прежнему не пускают.** Без ответа на первое подготовительное чтение вход не срабатывает, поэтому ContiTool останавливается до отправки ключа и записывает F15B блока в отчёт. *(Поправка: ODIS такой блок не лечит; лечение — одна перепрошивка приложения по UDS с нулевым серийником, см. 2.0.2.)*
- **Объяснение молчания из 2.0.1d было неверным.** Байт, который мы считали проверочным, во всех рабочих журналах равен нулю. Пересборка запроса под блок удалена.
- **Аппаратный ISO-TP адаптера не включался вообще никогда — из-за нашей ошибки.** Номер объекта, равный нулю, проверялся как «драйвер не знает такого имени», а в MDF Volkswagen нулями пронумерованы как раз шина `ISO_11898_2_DWCAN` и контакт `HI`. Поэтому ContiTool каждый раз решал, что драйвер не поддерживает ISO-TP, и писал старым путём: по одному обращению к адаптеру на каждый кадр CAN. Отсюда и 0,9 КБ/с, и обрыв записи на середине — VAS 6154 / VNCI перестаёт подтверждать отправку примерно на 125-тысячном кадре и перезапускает свою службу, а записи приложения нужно около 220 тысяч. Переоткрытие канала это не лечило: адаптер считает обращения на модуль, а не на канал.
- **Настройки UDS-канала выровнены по ODIS.** Флаг создания канала `0x40` и `CP_ModifyTiming=1` — как в журнале драйвера собственной сессии ODIS-E на этом же адаптере.
- **Видно, почему запись идёт без ISO-TP адаптера.** Если аппаратный ISO-TP не включился, причина (например, «3E 00: нет ответа» или какого объекта не хватает) пишется в журнал и в результат записи. Перед записью большого объёма без ISO-TP ContiTool предупреждает, что такая запись у этого адаптера обычно обрывается на середине.

### 🇬🇧 Fixed
- **After a CodeFlash write through ContiTool the gateway stopped answering on the RAM-Loader entry** — so verifying the write, reading and the next write on it all failed. The cause was our programming fingerprint: up to 2.0.1d ContiTool wrote the tester serial `01 02 03 04 05 06` in `2E F15A`. The bootloader keeps the fingerprint as the last F15B record, and the answer to the entry's staging read overruns its buffer and lands bytes of that record on its state cells, the suppress-response flag among them. The serial is now zero, as in the factory record. *(Correction: "a reflash through ODIS cures it" is wrong — ODIS writes a serial of its own, and a non-zero one closes the entry too; see 2.0.2.)*
- **Gateways already flashed by an older version still refuse the entry.** Without the answer to the first staging read the entry does not work, so ContiTool stops before sending the key and puts the gateway's F15B into the report. *(Correction: ODIS does not cure such a gateway; the cure is one reflash of the application over UDS with a zero serial, see 2.0.2.)*
- **The 2.0.1d explanation of the silence was wrong.** The byte we took for a gate is zero on every working log. Rebuilding the request for the gateway is gone.
- **The adapter's hardware ISO-TP never came up at all — because of a bug of ours.** An object id of zero was tested as "this driver does not know the name", and the Volkswagen MDF numbers exactly the `ISO_11898_2_DWCAN` bus and the `HI` pin zero. So ContiTool decided every time that the driver had no ISO-TP and wrote the old way: one request to the adapter per CAN frame. That is where the 0.9 KB/s and the write breaking off halfway came from — a VAS 6154 / VNCI stops confirming sends at around the 125,000th frame and restarts its service, while an application write needs some 220,000. Reopening the link did not help: the adapter counts requests per module, not per link.
- **The UDS link settings now match ODIS.** Link-create flag `0x40` and `CP_ModifyTiming=1`, as in the driver log of ODIS-E's own session on this very adapter.
- **It shows why a write runs without the adapter's ISO-TP.** When the hardware ISO-TP does not come up, the reason (e.g. "3E 00: no answer", or which object is missing) goes into the log and the write result. Before a large write without ISO-TP, ContiTool warns that such a write usually breaks off partway on this adapter.

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
