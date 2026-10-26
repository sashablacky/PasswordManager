## Какой файл скачать

Ниже, в разделе **Assets**, файлы для Windows 10 и 11. Нужен один.

| Файл | Когда брать |
|---|---|
| `PasswordManager-{VERSION}-Windows-Setup.exe` | обычно: установщик с ярлыком в меню «Пуск» |
| `PasswordManager-{VERSION}-Windows-Portable.zip` | без установки: распаковать в папку и запускать `Password Manager.exe` |

Программа не подписана платным сертификатом, поэтому Windows может показать **«Система Windows защитила ваш компьютер»**: нажмите **«Подробнее»** → **«Выполнить в любом случае»**. Пароли хранятся в `%APPDATA%\SecureVault`; удаление программы их не удаляет. Подробно: [docs/windows-install.md](https://github.com/sashablacky/PasswordManager/blob/main/docs/windows-install.md).

**Расширение для Firefox** (если есть в списке): `PasswordManager-{VERSION}-Firefox.xpi`. Нажмите на файл в Firefox и подтвердите установку. Программа из `Setup.exe` уже связана с Firefox, дальше нажмите значок SecureVault → «Подключить».

Версия для Mac выпускается отдельно: [Password Manager 1.5.5 для Mac](https://github.com/sashablacky/PasswordManager/releases/tag/v1.5.5).

Обновление: установите новую версию поверх старой, пароли сохранятся.
