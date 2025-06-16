# Pwned Proxy Quickstart

This project ships with a Docker Compose setup that handles running the
Django application and a PostgreSQL database. On startup it will apply
all migrations and create a superuser automatically so you can log in
immediately.

## Prerequisites

- [Docker](https://www.docker.com/) and Docker Compose installed
- A `.env` file based on `.devcontainer/.env.example`

Copy the example environment file and fill in the required variables:

```bash
cp .devcontainer/.env.example .env
# Edit .env to set POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB,
# DJANGO_SUPERUSER_USERNAME and DJANGO_SUPERUSER_PASSWORD.
```

## Running the stack

Build and start the containers:

```bash
docker compose up --build
```

The Django application will be available on port **8000**. It accepts
requests for both `localhost` and `api.dtuaitsoc.ngrok.dev` thanks to the
`ALLOWED_HOSTS` configuration. On first start, migrations are applied and
a superuser is created using the credentials from your `.env` file.
The admin username and password will be echoed in the terminal when the
containers start so you can copy them for login.

You can then log into the admin interface at
`http://localhost:8000/admin/` (or via your ngrok domain) using the
superuser credentials you provided.

### First-time setup

1. After logging into the Django admin, add your [Have I Been Pwned](https://haveibeenpwned.com/api) API key:
   - Navigate to **HIBP Keys** and create a new key with the value you received from HIBP.
2. Go to **Domains** and click **Import from HIBP**. This populates the database with the latest domain data.
3. Open **Groups** and use the **Seed Groups** action to generate API keys for each predefined group. The keys are downloaded as a JSON file.
4. Finally, visit `http://localhost:8000/` to open the Swagger start page and try out the API using the generated keys.

## Deploying on Debian\u00a012

Make sure Docker and Docker Compose are installed:

```bash
sudo apt update
sudo apt install docker.io docker-compose -y
```

Clone this repository and prepare your environment file as described above.
You can then test the stack with:

```bash
docker compose up --build --abort-on-container-exit --remove-orphans && \
docker compose down --volumes --remove-orphans
```

If everything starts correctly the application will exit once the containers
are stopped.

## Putting it behind Nginx for HTTPS

Install Nginx on the host and configure it as a reverse proxy:

```nginx
server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

Use a tool like `certbot` to obtain TLS certificates and update the
server block to listen on port `443` with SSL enabled. Once configured,
requests to `https://example.com` will be forwarded to the Dockerized
Django application.
