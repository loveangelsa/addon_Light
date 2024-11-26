#!/bin/sh

ADDON_FILE1=ezville_wallpad.py


echo "[Info] run $ADDON_FILE1 ..."

python3 /srv/$ADDON_FILE1 "/data/options.json"

echo "[Info] unexpected exit!"
