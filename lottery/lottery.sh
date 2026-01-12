#!/bin/bash

echo "Today's lottery!"
echo "Guess the winning ticket (hex):"
read guess

if [[ "$guess" =~ ^[0-9a-fA-F]+ ]]; then
    let "g = 0x$guess" 2>/dev/null
else
    echo "Invalid guess."
    exit 1
fi

ticket=$(head -c 16 /dev/urandom | md5sum | cut -c1-16)
let "t = 0x$ticket" 2>/dev/null

if [[ $g -eq $t ]]; then
    cat /flag.txt
else
    echo "Not a winner. Better luck next time!"
fi

