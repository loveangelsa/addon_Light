#!/bin/sh

ADDON_FILE1=ezville_wallpad.py
ADDON_FILE2=ezville_wallpad2.py

echo "[Info] run $ADDON_FILE1 ..."
echo "[Info] run $ADDON_FILE2 ..."
python3 /srv/$ADDON_FILE "/data/options.json"
echo "[Info] unexpected exit!"
