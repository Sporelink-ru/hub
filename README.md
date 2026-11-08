[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

# Sporelink Hub (C#)

Центральный сервер авторизации, реализующий протокол Yggdrasil (совместим с `authlib-injector`).

## Особенности
* Выдача JWT (Ed25519) с репутацией и ролями.
* Поддержка скинов и плащей (RSA подпись).
* Мульти-Hub федерация (синхронизация манифестов).
* База данных PostgreSQL + Entity Framework.

## Запуск
Требуется PostgreSQL. Установите строку подключения в переменной `DB_CONNECTION_STRING`.
```bash
dotnet run