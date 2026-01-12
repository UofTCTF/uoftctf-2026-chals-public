#!/bin/sh

OUTFILE="/tmp/input.txt"

head -c 16 /dev/urandom | od -An -tx1 | tr -d ' ' > "$OUTFILE"

echo "Welcome to the encryption service"
echo "Please put in all your plaintexts"
echo "End with EOF"

while true; do
    read -r line

    if [ "$line" = "EOF" ]; then
        break
    fi

    echo "$line" >> "$OUTFILE"
done

echo "As a bonus we will also encrypt the flag for you"

cat /flag.txt >> "$OUTFILE"

echo "Here is the encryption."
echo "$(cat "$OUTFILE" | xargs /app/enc.py)"