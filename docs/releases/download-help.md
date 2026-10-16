## Какой файл скачать

Ниже, в разделе **Assets**, файлы для Windows и для Mac. Нужен один.

### Windows 10 и 11

| Файл | Когда брать |
|---|---|
| `PasswordManager-{VERSION}-Windows-Setup.exe` | обычно: установщик с ярлыком в меню «Пуск» |
| `PasswordManager-{VERSION}-Windows-Portable.zip` | без установки: распаковать в папку и запускать `Password Manager.exe` |

Программа не подписана платным сертификатом, поэтому Windows может показать **«Система Windows защитила ваш компьютер»**: нажмите **«Подробнее»** → **«Выполнить в любом случае»**. Пароли хранятся в `%APPDATA%\SecureVault`; удаление программы их не удаляет. Подробно: [docs/windows-install.md](https://github.com/sashablacky/PasswordManager/blob/main/docs/windows-install.md).

### Mac

Какой у вас Mac: меню  (яблоко в левом верхнем углу) → **Об этом Mac**, строка «Чип» или «Процессор».

| Там написано | Скачайте |
|---|---|
| **Apple M1, M2, M3, M4…** | `PasswordManager-{VERSION}-macOS-AppleSilicon.dmg` |
| **Intel** | `PasswordManager-{VERSION}-macOS-Intel.dmg` |

Как установить и в первый раз открыть программу (она не подписана сертификатом Apple, поэтому macOS один раз спросит разрешения), где хранятся пароли и как сделать резервную копию — в инструкции: [docs/macos-install.md](https://github.com/sashablacky/PasswordManager/blob/main/docs/macos-install.md).

Обновление: установите новую версию поверх старой, пароли сохранятся.
