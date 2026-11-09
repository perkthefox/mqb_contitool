## Что изменено / What changed

<!-- Что и зачем. Ссылка на issue: Fixes #… / What and why. Link the issue: Fixes #… -->

## Как проверено / How it was verified

<!-- Тесты; если менялась работа с блоком — адаптер, блок, версия ПО и журнал со стенда.
     Tests; if ECU communication changed — adapter, ECU, software version and the bench log. -->

## Чек-лист / Checklist

- [ ] `QT_QPA_PLATFORM=offscreen pytest -q` проходит / passes
- [ ] Изменение поведения покрыто тестом / A behaviour change comes with a test
- [ ] Строки для пользователя на двух языках через `tr(ru, en)` / User-facing strings bilingual via `tr(ru, en)`
- [ ] Запись в `CHANGELOG.md`, если это заметно пользователю / `CHANGELOG.md` entry if users notice it
- [ ] Нет настоящих VIN, FAZIT, серийников и дампов / No real VINs, FAZITs, serial numbers or dumps
- [ ] Проверенные протоколы и контрольные суммы не менялись — или приложен журнал со стенда / Verified protocols and checksums unchanged — or a bench log is attached
- [ ] Я согласен с лицензией вкладов из `CONTRIBUTING.md` / I agree to the contribution terms in `CONTRIBUTING.md`
