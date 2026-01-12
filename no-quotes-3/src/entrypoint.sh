#!/usr/bin/env sh
set -eu

mkdir -p /run/mysqld
chown -R mysql:mysql /run/mysqld

mariadbd --user=mysql --datadir=/var/lib/mysql --bind-address=127.0.0.1 --port=3306 &

i=0
until mariadb-admin --protocol=socket --socket=/run/mysqld/mysqld.sock ping --silent; do
  i=$((i+1))
  if [ "$i" -gt 60 ]; then
    echo "MariaDB failed to start" >&2
    exit 1
  fi
  sleep 0.2
done

mariadb --protocol=socket --socket=/run/mysqld/mysqld.sock -uroot <<'SQL'
CREATE DATABASE IF NOT EXISTS `ctf`;
CREATE USER IF NOT EXISTS 'ctf'@'%' IDENTIFIED BY 'ctf';
GRANT ALL PRIVILEGES ON `ctf`.* TO 'ctf'@'%';
FLUSH PRIVILEGES;
SQL

exec su -s /bin/sh www-data -c 'exec python app.py'
