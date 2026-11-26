"""MQB 2B ELV / ESCL / J764 (Marquardt 3Q0 905 861, EV_ELVMarquMQBB) trouble codes.

All 71 24-bit UDS DTC entries extracted directly from 3Q0 905 861 SW 0032 PFLASH
(`0x000103EC..0x0001085B`, 71 x 16 B records).
"""

from __future__ import annotations

ELV_DTCS: dict[int, tuple[str, str, str]] = {
    # Internal MCU / ROM / RAM / EEPROM / H-bridge hardware self-test faults (priority 1)
    0x000006: ("B200000", "Неисправен блок управления (внутренняя ошибка ОЗУ / процессора)", "Control module faulty (internal RAM / CPU error)"),
    0x000007: ("B200000", "Неисправен блок управления (контрольная сумма ПЗУ / PFLASH)", "Control module faulty (ROM / PFLASH checksum)"),
    0x000008: ("B200000", "Неисправен блок управления (ошибка EEPROM / Data Flash)", "Control module faulty (EEPROM / Data Flash error)"),
    0x00000A: ("B200000", "Неисправен блок управления (сбой сторожевого таймера / сброс)", "Control module faulty (watchdog / unexpected reset)"),
    0x00000C: ("B200000", "Неисправен блок управления (драйвер H-моста / выходной каскад)", "Control module faulty (H-bridge driver / output stage)"),
    0x00000D: ("B200000", "Неисправен блок управления (ASIL-D контроль состояния)", "Control module faulty (ASIL-D safety monitor)"),
    0x00000E: ("B200000", "Неисправен блок управления (внутренний аппаратный сбой)", "Control module faulty (internal hardware failure)"),
    # Steering column lock actuator, motor, end-position Hall sensors, and power stages
    0x100000: ("B11F700", "Блокиратор рулевой колонки: механическая неисправность привода", "Steering column lock actuator: mechanical malfunction"),
    0x100001: ("B11F701", "Блокиратор рулевой колонки: электрическая неисправность привода", "Steering column lock actuator: electrical malfunction"),
    0x100100: ("B11F713", "Блокиратор рулевой колонки: обрыв / неисправность цепи мотора", "Steering column lock actuator: motor circuit malfunction / open"),
    0x100110: ("B11F711", "Датчик положения ригеля (P50/P51): замыкание на массу", "Lock bolt position sensor (P50/P51): short to ground"),
    0x100111: ("B11F712", "Датчик положения ригеля (P50/P51): замыкание на плюс", "Lock bolt position sensor (P50/P51): short to plus"),
    0x100112: ("B11F729", "Датчики положения ригеля: недостоверная комбинация сигналов (0/0 или 1/1)", "Lock bolt position sensors: implausible signal combination (0/0 or 1/1)"),
    0x100113: ("B11F771", "Блокиратор рулевой колонки: заклинивание ригеля при отпирании", "Steering column lock: bolt jammed during unlock"),
    0x100114: ("B11F772", "Блокиратор рулевой колонки: заклинивание ригеля при запирании", "Steering column lock: bolt jammed during lock"),
    0x100115: ("B11F773", "Блокиратор рулевой колонки: превышено время хода ригеля", "Steering column lock: bolt travel timeout exceeded"),
    0x100119: ("B11F719", "Привод блокиратора рулевой колонки: превышение тока мотора", "Steering column lock actuator: motor overcurrent"),
    0x100200: ("B11F800", "Неисправность силовой цепи питания привода ELV", "ELV actuator power stage malfunction"),
    0x100202: ("B11F802", "Неисправность обратной связи драйвера H-моста (P02/P913)", "H-bridge driver feedback malfunction (P02/P913)"),
    0x100203: ("B11F803", "Блокиратор рулевой колонки: несанкционированное изменение положения ригеля", "Steering column lock: unexpected bolt position change"),
    0x100300: ("B11F900", "Концевой выключатель / датчик Холла ригеля: недостоверный сигнал", "Bolt end-switch / Hall sensor: implausible signal"),
    0x100400: ("B11FA00", "Блокиратор рулевой колонки: ошибка защитного интерлока запирания", "Steering column lock: safety lock interlock fault"),
    0x100401: ("B11FA01", "Блокиратор рулевой колонки: отказ запирания (условия движения/ДВС)", "Steering column lock: locking inhibited (speed/engine condition)"),
    0x100402: ("B11FA02", "Блокиратор рулевой колонки: сбой контроля клемм (KL15 / KL_S)", "Steering column lock: terminal state plausibility fault (KL15 / KL_S)"),
    0x100403: ("B11FA03", "Блокиратор рулевой колонки: сбой ASIL-D таймера безопасности", "Steering column lock: ASIL-D safety timer fault"),
    # CAN bus communication, timeout, E2E CRC-8 and alive-counter (BZ) faults
    0xC14000: ("U014000", "Блок управления бортовой сети (BCM / J519): нет связи", "Body Control Module (BCM / J519): no communication"),
    0xC14100: ("U014100", "Шина данных комфорта (CAN Komfort): нет связи с Kessy / BCM", "Komfort CAN databus: no communication with Kessy / BCM"),
    0xC14101: ("U014101", "Блок санкционирования доступа и пуска (Kessy): нет связи / таймаут 0x58C", "Access/Start Authorization (Kessy): no communication / 0x58C timeout"),
    0xC14601: ("U014601", "Диагностический интерфейс шин данных (J533): нет связи / таймаут 0x3DC", "Data Bus Diagnostic Interface (J533): no communication / 0x3DC timeout"),
    0xC14602: ("U014602", "Шина данных: таймаут сообщения Klemmen_Status_01 (0x3C0)", "Databus: Klemmen_Status_01 (0x3C0) message timeout"),
    0xC14604: ("U014604", "Шина данных: таймаут сообщения ESP_21 (0x0FD)", "Databus: ESP_21 (0x0FD) message timeout"),
    0xC14605: ("U014605", "Шина данных: таймаут сообщения Motor_04 (0x0A8)", "Databus: Motor_04 (0x0A8) message timeout"),
    0xC1460A: ("U01460A", "Шина данных: таймаут сообщения Getriebe_11 (0x0AD)", "Databus: Getriebe_11 (0x0AD) message timeout"),
    0xC1460B: ("U01460B", "Шина данных: таймаут сообщения Motor_14 / Motor_20 (0x3BE)", "Databus: Motor_14 / Motor_20 (0x3BE) message timeout"),
    0xC1460C: ("U01460C", "Шина данных: таймаут сообщения ZV_01 / ZV_02 (0x3D4 / 0x583)", "Databus: ZV_01 / ZV_02 (0x3D4 / 0x583) message timeout"),
    0xC1460E: ("U01460E", "Шина данных: таймаут сообщения TSG_FT_01 (0x3D0)", "Databus: TSG_FT_01 (0x3D0) message timeout"),
    0xC1460F: ("U01460F", "Шина данных: таймаут сообщения Diagnose_01 (0x6B2)", "Databus: Diagnose_01 (0x6B2) message timeout"),
    0xC14610: ("U014610", "Шина данных: таймаут сообщения Systeminfo_01 (0x585)", "Databus: Systeminfo_01 (0x585) message timeout"),
    0xC14611: ("U014611", "Шина данных: таймаут сообщения BCM / Kessy (0x2A0)", "Databus: BCM / Kessy (0x2A0) message timeout"),
    0xC14612: ("U014612", "Шина данных: CAN Bus-Off / потеря сетевого управления OSEK-NM", "Databus: CAN Bus-Off / OSEK-NM network management fault"),
    0xC40100: ("U040100", "Блок управления двигателя (ECM): недостоверный сигнал / ошибка E2E Motor_04", "Engine Control Module (ECM): implausible signal / Motor_04 E2E error"),
    0xC43101: ("U043101", "Шина данных: ошибка CRC-8 / счётчика BZ сообщения ESP_21 (0x0FD)", "Databus: ESP_21 (0x0FD) CRC-8 / alive counter BZ error"),
    0xC43102: ("U043102", "Шина данных: ошибка CRC-8 / счётчика BZ сообщения Klemmen_Status_01 (0x3C0)", "Databus: Klemmen_Status_01 (0x3C0) CRC-8 / alive counter BZ error"),
    0xC43103: ("U043103", "Шина данных: ошибка CRC-8 / счётчика BZ сообщения Getriebe_11 (0x0AD)", "Databus: Getriebe_11 (0x0AD) CRC-8 / alive counter BZ error"),
    # Security, power supply voltage, coding, and WFS5 immobilizer faults
    0xD00901: ("B200901", "Иммобилайзер WFS5: блок не адаптирован / режим Virgin (Mode 1)", "WFS5 Immobilizer: unit not adapted / Virgin mode (Mode 1)"),
    0xD00904: ("B200904", "Иммобилайзер WFS5: ошибка авторизации CAN (0x01A / 0x01B)", "WFS5 Immobilizer: CAN authentication failed (0x01A / 0x01B)"),
    0xD00905: ("B200905", "Иммобилайзер WFS5: неверный ключ K_5 (Slot A) или PowerClass", "WFS5 Immobilizer: wrong K_5 (Slot A) key or PowerClass"),
    0xD00907: ("B200907", "Иммобилайзер WFS5: несовпадение IDac приборной панели", "WFS5 Immobilizer: instrument cluster IDac mismatch"),
    0xD00908: ("B200908", "Иммобилайзер WFS5: исчерпан счётчик Virgin-открытий", "WFS5 Immobilizer: Virgin unlock counter exhausted"),
    0xD0090D: ("B20090D", "Иммобилайзер WFS5: таймаут ответа приборной панели (0x01B)", "WFS5 Immobilizer: instrument cluster response timeout (0x01B)"),
    0xD0090E: ("B20090E", "Иммобилайзер WFS5: активен таймер блокировки адаптации (02ED)", "WFS5 Immobilizer: adaptation lockout timer active (02ED)"),
    0xD0090F: ("B20090F", "Иммобилайзер WFS5: ошибка контрольной суммы блока данных WFS (Блок 34)", "WFS5 Immobilizer: WFS data block checksum error (Block 34)"),
    0xD00910: ("B200910", "Иммобилайзер WFS5: несогласованность копий EEPROM (Block 2/4/34)", "WFS5 Immobilizer: EEPROM triple-copy inconsistency (Block 2/4/34)"),
    0xD00A00: ("B200A00", "Кодирование блока управления (DID 0x0600): недействительно / отсутствует", "Control module coding (DID 0x0600): invalid / missing"),
    0xD00B00: ("B200B00", "Заводской режим (Plant Mode 0xFF) или невалидный набор параметров", "Plant mode (0xFF) active or invalid parameter set"),
    0xD01100: ("B201100", "Напряжение питания (KL30): слишком низкое", "Supply voltage (KL30): too low"),
    0xD01200: ("B201200", "Напряжение питания (KL30): слишком высокое", "Supply voltage (KL30): too high"),
    0xD01700: ("B201700", "Контроль безопасности ELV: сбой проверки состояния (0x00)", "ELV safety monitor: state verification fault (0x00)"),
    0xD01701: ("B201701", "Контроль безопасности ELV: ошибка сигнала скорости (ESP_21)", "ELV safety monitor: vehicle speed signal fault (ESP_21)"),
    0xD01702: ("B201702", "Контроль безопасности ELV: ошибка сигнала оборотов ДВС (Motor_04)", "ELV safety monitor: engine RPM signal fault (Motor_04)"),
    0xD01703: ("B201703", "Контроль безопасности ELV: ошибка сигнала клемм (Klemmen_Status_01)", "ELV safety monitor: terminal status signal fault (Klemmen_Status_01)"),
    0xD01704: ("B201704", "Контроль безопасности ELV: ошибка сигнала селектора АКПП (Getriebe_11)", "ELV safety monitor: gear selector signal fault (Getriebe_11)"),
    0xD01705: ("B201705", "Контроль безопасности ELV: рассогласование резервного контейнера", "ELV safety monitor: redundant container mismatch"),
    0xD01706: ("B201706", "Контроль безопасности ELV: сбой входного контроля ПЗУ/ОЗУ", "ELV safety monitor: memory integrity monitor fault"),
    0xD01707: ("B201707", "Контроль безопасности ELV: сбой теста АЦП / опорного напряжения", "ELV safety monitor: ADC / reference voltage self-test fault"),
    0xD01709: ("B201709", "Контроль безопасности ELV: некорректная команда управления от Kessy", "ELV safety monitor: implausible lock/unlock request from Kessy"),
    0xD0170A: ("B20170A", "Контроль безопасности ELV: ошибка статуса двери водителя (TSG_FT_01)", "ELV safety monitor: driver door status fault (TSG_FT_01)"),
    0xD0170B: ("B20170B", "Контроль безопасности ELV: ошибка статуса центрального замка (ZV_01/02)", "ELV safety monitor: central locking status fault (ZV_01/02)"),
    0xD0170D: ("B20170D", "Контроль безопасности ELV: ошибка шины данных / таймаут шлюза", "ELV safety monitor: databus / gateway timeout"),
    0xD0170E: ("B20170E", "Контроль безопасности ELV: ошибка последовательности переходов КА", "ELV safety monitor: state-machine transition sequence fault"),
    0xD0170F: ("B20170F", "Контроль безопасности ELV: критический отказ интерлока запирания", "ELV safety monitor: critical locking interlock failure"),
}

# Exact firmware DTC index order (0..70) at 0x000103EC in 3Q0 905 861 SW 0032 PFLASH
ELV_DTC_ORDER: tuple[int, ...] = tuple(ELV_DTCS.keys())
