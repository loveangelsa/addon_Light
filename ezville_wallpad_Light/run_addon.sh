#!/bin/sh

ADDON_FILE1=ezville_wallpad.py
ADDON_FILE2=ezville_wallpad2.py

# Execute the first Python script
echo "[Info] Running $ADDON_FILE1 ..."
python3 $ADDON_FILE1
echo "[Info] $ADDON_FILE1 exited unexpectedly!"

echo "[Info] Running $ADDON_FILE2 ..."
python3 $ADDON_FILE2
echo "[Info] $ADDON_FILE2 exited unexpectedly!"
