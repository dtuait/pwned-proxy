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

You can then log into the admin interface at
`http://localhost:8000/admin/` (or via your ngrok domain) using the
superuser credentials you provided.
