#!/bin/sh

chown "${LGUID}:${LGGID}" /dev/stdout

exec gunicorn -u "${LGUID}" -g "${LGGID}" -b 0.0.0.0:8000 $@