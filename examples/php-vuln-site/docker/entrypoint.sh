#!/usr/bin/env sh
# First-run setup for the local demo, then start the server. Idempotent.
set -e
cd /app
[ -d vendor ] || composer install --no-interaction --prefer-dist
[ -f .env ] || cp .env.example .env
grep -q '^APP_KEY=.\+' .env || php artisan key:generate
[ -f database/database.sqlite ] || touch database/database.sqlite
php artisan migrate --force --seed
exec php artisan serve --host=0.0.0.0 --port=8000
