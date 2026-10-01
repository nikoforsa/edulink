# Проверка комплекта

Дата: 2026-09-30T12:59:49.975Z

Полный SQL-дамп успешно восстановлен в отдельную временную базу PostgreSQL 17 с ON_ERROR_STOP и одной транзакцией. Исходная база не изменялась. Временная база удалена после проверки.

- accounts: 6
- courses: 3
- study_groups: 5
- lessons: 95
- lesson_plans: 93
- lesson_tests: 1
- test_attempts: 0
- lesson_journals: 1
- lesson_marks: 1

18 тестов Google-авторизации прошли. Docker отсутствует, поэтому сборка образа, доступность тегов образов и запуск Docker Compose не проверялись.
