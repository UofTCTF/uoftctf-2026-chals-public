#!/bin/bash

cd /app
# run PoW
python3 pow.py ask 31337 || exit 0
exec python3 ./chall.py
