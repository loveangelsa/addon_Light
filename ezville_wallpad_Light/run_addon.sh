#!/bin/sh

ADDON_FILE1=ezville_wallpad.py
ADDON_FILE2=ezville_wallpad2.py

# Execute the first Python script
echo "[Info] Running $ADDON_FILE1 ..."
python3 $ADDON_FILE1

# Check if the first script exited unexpectedly
if [ $? -ne 0 ]; then
    echo "[Info] $ADDON_FILE1 exited unexpectedly!"
fi

# Execute the second Python script
echo "[Info] Running $ADDON_FILE2 ..."
python3 $ADDON_FILE2

# Check if the second script exited unexpectedly
if [ $? -ne 0 ]; then
    echo "[Info] $ADDON_FILE2 exited unexpectedly!"
fi
