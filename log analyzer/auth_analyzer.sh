#!/bin/bash

PY_SCRIPT="auth_analyzer.py"
LOG_PATH="/var/log/auth.log"

echo " LOG ANALYZER "

if [[ ! -f "$PY_SCRIPT" ]]; then
	echo "ERROR: $PY_SCRIPT WASN'T FOUND."
	exit 1
fi

if [[ ! -r "$LOG_PATH" ]]; then
	echo "WARNING: PERMISSION DENIED, USE SUDO"
	exit 1
fi

python3 "$PY_SCRIPT" "$LOG_PATH"

if [[ $? -eq 0 ]]; then
	echo "ANALYSIS FINISHED SUCCESSFULLY"
	echo "RESULT STORED IN 'log_results.txt'"
else
	echo "ERROR: SOMETHING WENT WRONG IN "$PY_SCRIPT""
fi

exit 0
