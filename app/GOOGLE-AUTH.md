# Вход через Google

Поддерживается сервер PostgreSQL (`node start.js postgres`). В SQLite демо эта функция недоступна.

1. В Google Cloud Console / Google Auth Platform создайте проект и настройте Branding, Audience и доступ к `openid`, `email`, `profile`. Если приложение в режиме Testing, добавьте тестовых пользователей.
2. Создайте OAuth client типа Web application.
3. В Authorized redirect URIs добавьте точно `http://127.0.0.1:8000/api/auth/google/callback`.
4. В локальном `.env` задайте:

```dotenv
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
GOOGLE_REDIRECT_URI=http://127.0.0.1:8000/api/auth/google/callback
```

5. Перезапустите сервер. Открывайте приложение по адресу `http://127.0.0.1:8000`, а не `localhost`, чтобы совпадал хост cookie. Для рабочего сервера зарегистрируйте точный HTTPS callback, измените GOOGLE_REDIRECT_URI и включите NODE_ENV=production.

Секрет хранится только на сервере. Не публикуйте `.env`. Авторизация Google должна открываться в обычном браузере; встроенные браузеры могут быть отклонены Google.

Новый пользователь создаётся студентом без группы. Администратор назначает группу и при необходимости меняет роль. Роли из запроса браузера не принимаются.

Существующая активная подтверждённая учётная запись связывается по email только для Gmail или подтверждённого Google Workspace домена. Для Google-аккаунта со сторонней почтой автоматическая привязка к существующему пользователю запрещена: используйте вход по паролю. Ручная привязка в этом выпуске не предусмотрена. Последующие входы используют уникальный Google sub. Заблокированные и неактивные пользователи не входят через Google. Существующий пароль сохраняется; новый пользователь может установить пароль через восстановление доступа.

Проверяются одноразовый state, привязка к браузеру, срок запроса, PKCE, подпись ID token по ключам Google, issuer, audience, expiration, nonce и подтверждение email. Токены Google и Client Secret не возвращаются браузеру и не сохраняются в базе. OAuth запросы и обычные сессии хранятся в памяти одного процесса; при перезапуске вход нужно повторить.

Проверка без Google credentials: `node --test test/google-auth.test.js`. Для полной проверки после настройки: новый студент, существующий подтверждённый Gmail/Workspace пользователь, отказ Google, блокированный пользователь и выход из системы.

Документация Google: https://developers.google.com/identity/protocols/oauth2/web-server
