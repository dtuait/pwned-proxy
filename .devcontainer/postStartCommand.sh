#!/bin/bash
echo "Running postStartCommand.sh..."

curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
	| sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
	&& echo "deb https://ngrok-agent.s3.amazonaws.com buster main" \
	| sudo tee /etc/apt/sources.list.d/ngrok.list \
	&& sudo apt update \
	&& sudo apt install ngrok

# if /usr/src/project/app-main/.env.local and NGROK_AUTHTOKEN from /usr/src/project/app-main/.env.local exists then run
if [ -f "/usr/src/project/.devcontainer/.env" ]; then
  DEVCONTAINER_NGROK_AUTHTOKEN=$(grep -oP '^DEVCONTAINER_NGROK_AUTHTOKEN=\K.*' /usr/src/project/.devcontainer/.env)
  if [ -n "$DEVCONTAINER_NGROK_AUTHTOKEN" ]; then
    ngrok config add-authtoken "$DEVCONTAINER_NGROK_AUTHTOKEN"
  else
    echo "DEVCONTAINER_NGROK_AUTHTOKEN not found in .env"
  fi
else
  echo ".env.local file not found"
fi

ngrok http --url=api.dtuaitsoc.ngrok.dev 3000