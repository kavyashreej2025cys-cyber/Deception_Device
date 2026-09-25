#!/bin/bash
set -e

echo "=== Cyber Deception System — Full Data Reset ==="
echo "This will clear all events, logs, and cursors, then restart honeypots."
read -p "Are you sure? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

cd "$(dirname "$0")/.."

echo "--> Stopping honeypots..."
(cd honeypots/ssh && docker compose down)
(cd honeypots/web && docker compose down)
(cd honeypots/database && docker compose down)
(cd honeypots/iot && docker compose down)
echo "--> Clearing log files..."
sudo rm -f honeypots/ssh/logs/*.json honeypots/ssh/logs/*.json.*
sudo rm -f honeypots/web/logs/*.json
sudo rm -f honeypots/database/logs/*.json
sudo rm -f honeypots/iot/logs/*.json

echo "--> Clearing cursor files..."
rm -f logger/cursors/*.cursor

echo "--> Removing database..."
rm -f data/events.db

echo "--> Reinitializing database..."
(cd logger && python3 -c "from database import init_db; init_db()")

echo "--> Restarting honeypots..."
(cd honeypots/ssh && docker compose up -d)
(cd honeypots/web && docker compose up -d)
(cd honeypots/database && docker compose up -d)
(cd honeypots/iot && docker compose up -d)

echo "=== Reset complete. All honeypots restarted with fresh state. ==="
echo "Note: Cowrie's SSH host key changed — run this on Kali if needed:"
echo "  ssh-keygen -f '/home/kali/.ssh/known_hosts' -R '[192.168.56.101]:2222'"
