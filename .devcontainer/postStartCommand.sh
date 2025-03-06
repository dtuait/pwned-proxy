#!/bin/bash
echo "Running postStartCommand.sh..."


# if /usr/src/project/app-main/.env.local and NGROK_AUTHTOKEN from /usr/src/project/app-main/.env.local exists then run
if [ -f "/usr/src/project/.devcontainer/.env" ]; then
  NGROK_AUTHTOKEN=$(grep -oP '^DEVCONTAINER_NGROK_AUTHTOKEN=\K.*' /usr/src/project/app-main/.env.local)
  if [ -n "$NGROK_AUTHTOKEN" ]; then
    ngrok config add-authtoken "$NGROK_AUTHTOKEN"
  else
    echo "NGROK_AUTHTOKEN not found in .env"
  fi
else
  echo ".env.local file not found"
fi