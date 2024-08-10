#!/bin/sh

ADDON_FILE1=ezville_wallpad.py
ADDON_FILE2=ezville_wallpad2.py
#ADDON_FILE3=ezville_wallpad3.py

echo "[Info] run $ADDON_FILE1 ..."
echo "[Info] run $ADDON_FILE2 ..."
python3 /srv/$ADDON_FILE1 "/data/options.json"
python3 /srv/$ADDON_FILE2 "/data/options.json"
#echo "[Info] run $ADDON_FILE3 ..."
#python3 /srv/$ADDON_FILE3 "/data/options.json"
echo "[Info] unexpected exit!"
