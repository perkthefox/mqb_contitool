# Third-party components / Сторонние компоненты

ContiTool's own code is licensed under the PolyForm Noncommercial License 1.0.0 with Additional Terms
(see `LICENSE`). The release builds (`ContiTool-v*-windows/macos/linux`) also contain the components
below, each under its own license; ContiTool's terms do not restrict what those licenses allow.

Собственный код ContiTool распространяется под PolyForm Noncommercial 1.0.0 с дополнительными условиями
(см. `LICENSE`). Готовые сборки дополнительно содержат перечисленные ниже компоненты — каждый под своей
лицензией; условия ContiTool не ограничивают того, что разрешают эти лицензии.

| Component | License | Source |
|---|---|---|
| Python runtime | PSF-2.0 | https://www.python.org/downloads/source/ |
| Qt 6 libraries | LGPL-3.0-only | https://download.qt.io/official_releases/qt/ |
| PySide6 (Qt for Python), shiboken6 | LGPL-3.0-only | https://code.qt.io/cgit/pyside/pyside-setup.git/ |
| python-can | LGPL-3.0-only | https://github.com/hardbyte/python-can |
| pyserial | BSD-3-Clause | https://github.com/pyserial/pyserial |
| wrapt | BSD-2-Clause | https://github.com/GrahamDumpleton/wrapt |
| packaging | Apache-2.0 OR BSD-2-Clause | https://github.com/pypa/packaging |
| typing_extensions | PSF-2.0 | https://github.com/python/typing_extensions |
| PyInstaller bootloader | GPL-2.0-or-later with the bootloader exception | https://github.com/pyinstaller/pyinstaller |

## LGPL components / Компоненты под LGPL

Qt, PySide6, shiboken6 and python-can are used unmodified and ship as separate files inside the
application folder (`_internal/` on Windows and Linux, `Contents/Frameworks/` on macOS), so you can
replace them with your own builds of the same versions, and reverse-engineer ContiTool as far as
needed to debug such replacements. The full text of the LGPL-3.0 is in `LICENSES/LGPL-3.0.txt`; it
adds permissions to the GPL-3.0 in `LICENSES/GPL-3.0.txt`.

Qt, PySide6, shiboken6 и python-can используются без изменений и лежат отдельными файлами в папке
программы (`_internal/` в Windows и Linux, `Contents/Frameworks/` в macOS) — их можно заменить своими
сборками тех же версий и исследовать ContiTool настолько, насколько это нужно для отладки такой замены.
Полный текст LGPL-3.0 — в `LICENSES/LGPL-3.0.txt`; он дополняет GPL-3.0 из `LICENSES/GPL-3.0.txt`.

## VW D-PDU API driver 27.2 / Драйвер VW D-PDU API 27.2

The Windows build carries the VW D-PDU API driver 27.2.0 in `dpdu/VW_PDUAPI_27.2/`, unmodified: `PDUAPI_VW.dll`,
its description files, the protocol-layer programs and the VAS 6154 firmware image the driver writes into the
adapter. These files are Volkswagen AG's and remain under their owner's terms; ContiTool's license does not
cover them. ODIS and the adapter's USB driver are not included.

Сборка для Windows содержит драйвер VW D-PDU API 27.2.0 в `dpdu/VW_PDUAPI_27.2/`, без изменений: `PDUAPI_VW.dll`,
его файлы описаний, программы протокольного слоя и образ прошивки VAS 6154, который драйвер записывает в
адаптер. Это файлы Volkswagen AG, на них распространяются условия правообладателя; лицензия ContiTool на них
не действует. ODIS и USB-драйвер адаптера в состав не входят.
