# Changelog / История изменений

## 2.0.1 — 2026-11-08

### 🇷🇺 Исправлено
- **Запись CodeFlash по UDS.** Пока блок выполняет долгую операцию, он отвечает «ждите» (`7F xx 78`) примерно каждые 2,5 с. ContiTool ждал после такого ответа тоже 2,5 с, и на адаптере с задержкой стирание обрывалось на середине: приложение уже стёрто, а блок остаётся в загрузчике. Теперь после `78` программа ждёт до 6 с (по протоколу блоку положено до 5 с, P2*). CAN-терминал ждёт так же.
- **VAS 6154 / VNCI на драйверах D-PDU 30 и новее.** Каналы теперь закрываются так же, как это делают ODIS и сам драйвер: STOPCOMM на канале отправки, отмена монитора, только потом отключение. Раньше примерно каждая вторая операция падала с `PDU_ERR_COMM_PC_TO_VCI_FAILED` через 2 с после подключения.
- Если VCI всё же разорвал соединение при подключении, ContiTool ждёт 4 с и подключается заново (один раз).

### 🇷🇺 Добавлено
- **Проверка версии драйвера D-PDU до подключения.** При подключении драйвер перепрошивает VCI под свою версию, поэтому версия проверяется заранее. Версии **27.2** и **31.0 / 31.1** работают сразу. Для остальных нужна галочка в окне «Подключение» или флаг `--allow-dpdu-driver` в CLI.
- Версия драйвера D-PDU показывается в списке адаптеров и в `contitool can ports`.
- **Понятная ошибка при обрыве чтения памяти.** Программа пишет, сколько байт пришло до обрыва. Для SLCAN добавлена подсказка: адаптер теряет кадры. Клоны с последовательным портом (CH340 и т. п. на 115200 бод) справляются с UDS, но не с потоком памяти на полной скорости шины.

### 🇬🇧 Fixed
- **CodeFlash write over UDS.** During a long operation the ECU answers "wait" (`7F xx 78`) about every 2.5 s. ContiTool also waited only 2.5 s after it, so on an adapter with some latency an erase could be cut off halfway: the application already erased, the ECU left in its bootloader. ContiTool now waits up to 6 s after a `78` (the ECU may take up to 5 s, P2*). The CAN terminal waits the same way.
- **VAS 6154 / VNCI on D-PDU drivers 30 and newer.** Links are now closed the way ODIS and the driver itself close them: STOPCOMM on the send link, then the monitor is cancelled, and only then the link is disconnected. Before, about every second operation failed with `PDU_ERR_COMM_PC_TO_VCI_FAILED` 2 s after connecting.
- If the VCI still drops the connection while connecting, ContiTool waits 4 s and connects again (once).

### 🇬🇧 Added
- **D-PDU driver version check before connecting.** The driver reflashes the VCI to its own version on connect, so the version is checked beforehand. **27.2** and **31.0 / 31.1** run right away. Other versions need a checkbox in the Connection dialog or `--allow-dpdu-driver` in the CLI.
- The D-PDU driver version is shown in the adapter list and in `contitool can ports`.
- **Clear error when a memory read stream breaks.** ContiTool reports how many bytes arrived before the break. For SLCAN it adds a hint that the adapter loses frames: serial clones (CH340 etc. at 115200 baud) handle UDS but not a memory stream at full bus speed.

## 2.0.0 — 2026-11-08

A complete rewrite: a desktop GUI and a CLI for Continental J533 (`3Q0 907 530`) gateways. See the [v2.0.0 release](https://github.com/perkthefox/mqb_contitool/releases/tag/v2.0.0).

Полностью новая версия: настольное приложение и CLI для шлюзов Continental J533 (`3Q0 907 530`). Подробности — в [релизе v2.0.0](https://github.com/perkthefox/mqb_contitool/releases/tag/v2.0.0).
