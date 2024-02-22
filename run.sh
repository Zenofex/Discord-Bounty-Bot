#!/bin/bash

docker build -t bug-bounty-bot .

docker run -e TOKEN=INSERT_DISCORD_TOKEN_HERE --cap-add NET_ADMIN -it bug-bounty-bot
