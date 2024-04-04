#!/bin/sh

# https://vinniefalco.github.io/BeastAssets/reports/autobahn/index.html
# https://github.com/python-trio/trio-websocket/blob/master/autobahn/client.py

docker run -it --rm \
    -v "./config:/config" \
    -v "./reports:/reports" \
    -p 9001:9001 \
    --name autobahn_ws_client \
    crossbario/autobahn-testsuite \
    wstest -m fuzzingserver -s '/config/fuzzingserver.json'
