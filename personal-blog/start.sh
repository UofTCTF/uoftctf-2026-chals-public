#!/bin/bash
set -euo pipefail

if [ -z "${ADMIN_PASSWORD:-}" ]; then
  set +o pipefail
  ADMIN_PASSWORD="$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | head -c 16)"
  set -o pipefail
  export ADMIN_PASSWORD
  export ADMIN_PASS="$ADMIN_PASSWORD"
  echo "Generated ADMIN_PASSWORD=$ADMIN_PASSWORD"
else
  export ADMIN_PASS="$ADMIN_PASSWORD"
fi

node /app/web/server.js &
web_pid=$!

node /app/bot/index.js &
bot_pid=$!

trap 'kill $web_pid $bot_pid' TERM INT
wait -n "$web_pid" "$bot_pid"
exit_code=$?

kill "$web_pid" "$bot_pid" >/dev/null 2>&1 || true
wait || true

exit "$exit_code"
