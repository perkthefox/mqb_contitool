# Техническая документация ContiTool / Technical Reference (`docs/`)

В этом каталоге собрано подробное инженерное описание устройства памяти, алгоритмов и протоколов шлюза **Continental VAG MQB Gateway J533** (`3Q0 907 530 xx`, микроконтроллер **Renesas RH850/F1L**), на которых построена работа всех функций **ContiTool**.

This directory contains concrete, byte-accurate engineering documentation for the memory layout, hardware controllers, cryptographic formats, and CAN/UDS protocols of the **Continental VAG MQB Gateway J533** (`3Q0 907 530 xx`, **Renesas RH850/F1L**) implemented in **ContiTool**.

> [!WARNING]
> **Примечание при работе с ИИ-ассистентами (Claude Code и др.) / Note on AI Coding Agents:**
> Документы в папке `docs/` содержат низкоуровневое описание работы загрузчика `RH850`, контроллера флеш-памяти `FACI`, криптомодуля `ICUS0` и диагностических кадров `UDS / CAN`. Автоматические фильтры безопасности ИИ-агентов могут ошибочно сработать при попытке прочитать всю папку целиком. Не просите ИИ-агентов читать `docs/` полностью — при необходимости указывайте только конкретный раздел нужного файла.
>
> Because `docs/` describes low-level `RH850` bootloader internals, `FACI` flash registers, `ICUS0` key loading, and raw `UDS / CAN` frames, asking AI coding assistants to read `docs/` in full may trigger false-positive automated safety filters. Avoid asking AI agents to read the entire `docs/` folder; point them only to a specific section when needed.

---

## Разделы на русском языке (RU)

1. **[Чтение и запись шлюза J533 по шине Diagnosis CAN (`can-read-write.md`)](can-read-write.md)**
   - Физическое подключение к разъёму `T20` (`Pin 19 = Diag CAN-H`, `Pin 9 = Diag CAN-L`, `120 Ом`, `500 кбит/с`), идентификаторы `0x710/0x77A` и `0x6F0/0x6F1`, полная карта памяти `RH850/F1L`.
   - Механизм входа в заводской потоковый загрузчик `CAN RAM-Loader` (`0x0100120E`) на полностью штатном блоке: переход в `10 02`, двухэтапная подготовка выровненного дескриптора `Renesas FCL` (`0xFEDE0548`) через сервис `0x22` и передача управления по ветке `27 12`.
   - Формат потоковых пакетов `0x6F0 / 0x6F1` (лимит `0x7DB8`), проверка готовности и нативное чтение `Cflash` (`1.5 МБ`), `Uflash` (`32 КБ`), `Dflash` (`64 КБ`) и произвольных адресов (`can read-mem`) без входа в режим программирования флеш-памяти.
   - Нативная запись всех областей флеш-памяти через аппаратный контроллер `FACI` из ОЗУ (автозагрузка `SELFID` из `Cflash + 0xAB00` и обслуживание `WDTA0 / WDTA1`): однопакетная/двухпакетная запись `Uflash` (`32 КБ`), дифференциальная запись `DataFlash` (`64 КБ`, `FENTRYR = 0xAA80`, блоки `64` Б, пословная запись `4` Б с сохранением `ECC`) и прямая запись бут-секторов `CodeFlash` (`0x00000000..0x0000BFFF` и режим `--raw-faci`).
   - Штатная перепрошивка прикладной области `CodeFlash` (`FD_0DATA`) по `ISO 14229 UDS` с алгоритмом `VAG SA2`, контролем `App CRC-16/MODBUS` и сквозной побайтовой верификацией.
2. **[Защита компонентов `KSCHUTZ` (`#MoLaLi`) и протоколы CAN/UDS (`component-protection.md`)](component-protection.md)**
   - Архитектура `KSCHUTZ` на гейтвее `19` и аппаратного модуля `ICUS0`, устройство 12 ведомых банков и мастер-ключа `GFA` (`0xDA00`), откуда берётся 16-байтный ключ `K3` (`IKA`).
   - Побайтовое устройство 38-байтного гибридного трамплина `CodeFlash` (`0x0016FF80`: разделение `CMD_LOAD_KEY 0x40` и `CMD_LOAD_PLAIN_KEY 0x10`) и обход маски внешней `ST M95640` SPI EEPROM.
   - Справочник всех 12 банков `CP`, полная карта памяти `DataFlash.bin` (`64 КБ`) и правило выбора профиля `R7F7010543` (`64 КБ`) в программаторе.
   - Четырёхкадровое рукопожатие `80 01 → C0 01 → 80 02 → C0 02` (`AES-128-ECB`), мультиплексор `VIN` в `0x6B4` и двухшаговая запись ключей в ведомый ЭБУ по UDS (`2E 00 BE → 2E 00 BD`).
3. **[Инженерный режим, сервисные протоколы и криптография `RSA-1024` / `SWaP` / `ODX` (`engineering-and-swap.md`)](engineering-and-swap.md)**
   - Точки бинарного патчинга `Feature 0x80/0x81/0x83`, снятие фильтра адресов `ASAM CCP` и разблокировка `0x0000A167`.
   - Сессии `10 40` / `10 4F`, формулы `SecurityAccess` уровней 1 и 2, живой калибровочный протокол `ASAM CCP v2.1` (`0x1BFC8600 / 0x1BFC8601`), заливка параметрии `ZDC` по `CRC-32` без `RSA` и сервисные `DID` / `RoutineControl`.
   - Генерация ключей `RSA-1024 (e = 3)`, синхронная замена публичного модуля в `CodeFlash` и кэше `DataFlash NvM 0x7C`, выпуск 171-байтных сертификатов `VAG SWaP FSC v2` (`RIPEMD-160`) и подпись прошивок `ODX` (`SHA-1`).

---

## English Documentation (EN)

1. **[Live Diagnosis CAN Read & Write Mechanism on J533 (`can-read-write.en.md`)](can-read-write.en.md)**
   - Bench wiring on `J533 T20` (`Pin 19 = Diag CAN-H`, `Pin 9 = Diag CAN-L`, `120 Ω`, `500 kbit/s`), CAN IDs `0x710/0x77A` & `0x6F0/0x6F1`, and complete `RH850/F1L` memory map.
   - Exact mechanism for entering the factory Stage-2 `CAN RAM-Loader` (`0x0100120E`) on unmodified stock units: `10 02` transition, two-stage aligned `Renesas FCL` descriptor staging (`0xFEDE0548`) via multi-DID `0x22`, and `27 12` mismatch dispatch.
   - `0x6F0 / 0x6F1` stream framing (`0x7DB8` cap), readiness beacon, and read-only dumping of `Cflash` (`1.5 MB`), `Uflash` (`32 KB`), `Dflash` (`64 KB`), and custom physical memory ranges (`can read-mem`).
   - Native RAM `FACI` drivers (`SELFID` auto-loading from `Cflash + 0xAB00` + `WDTA0 / WDTA1` servicing) for all flash regions: `Uflash` (`32 KB`), differential `DataFlash` (`64 KB`, `FENTRYR = 0xAA80`, 64B erase + 4B ECC-valid word writes), and `CodeFlash` boot blocks (`0x00000000..0x0000BFFF` & `--raw-faci`).
   - Standard `ISO 14229 UDS` programming of `CodeFlash` (`FD_0DATA`) with `VAG SA2`, `512`-byte `TransferData` framing, `App CRC-16/MODBUS`, and full 1.5 MB readback verification.
2. **[Component Protection (`KSCHUTZ` `#MoLaLi`) & CAN/UDS Protocols (`component-protection.en.md`)](component-protection.en.md)**
   - `KSCHUTZ` & hardware `ICUS0` architecture, 12 slave banks vs Master Key `GFA` (`0xDA00`), and Slave `K3` (`IKA`) provenance.
   - Byte-level breakdown of the 38-byte `CodeFlash` hybrid trampoline (`0x0016FF80`: `CMD_LOAD_KEY 0x40` vs `CMD_LOAD_PLAIN_KEY 0x10`) and external `ST M95640` SPI EEPROM bitmask bypass.
   - Complete 12-bank CP reference table, 64 KB `DataFlash.bin` memory map, and the `R7F7010543` (`64 KB`) bench programmer rule.
   - Runtime 4-message `80 01 → C0 01 → 80 02 → C0 02` `AES-128-ECB` handshake, `0x6B4` `VIN_01` mux frames, and two-step Slave ECU UDS key adaptation (`2E 00 BE → 2E 00 BD`).
3. **[Engineering Mode, Service Protocols & `RSA-1024` / `SWaP` / `ODX` Cryptography (`engineering-and-swap.en.md`)](engineering-and-swap.en.md)**
   - Exact `Feature 0x80/0x81/0x83`, `ASAM CCP` blacklist, and `0x0000A167` patch sites.
   - `10 40` / `10 4F` UDS sessions, `SecurityAccess` Level 1 & Level 2 formulas, `ASAM CCP v2.1` (`0x1BFC8600 / 0x1BFC8601`), stock CRC-32-only `ZDC` dataset upload, and service `DID` / `RoutineControl` catalog.
   - `RSA-1024 (e = 3)` key generation, synchronized `CodeFlash` + `DataFlash NvM 0x7C` modulus replacement, 171-byte `VAG SWaP FSC v2` (`RIPEMD-160`) signing & OBD activation, and `ODX` `<FW-SIGNATURE>` (`SHA-1`) signing.
