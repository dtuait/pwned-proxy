#!/usr/bin/env python3
"""Validate environment setup before starting the container."""
from pathlib import Path
import os
import sys
import yaml

BASE_DIR = Path(__file__).resolve().parent
EXAMPLE = BASE_DIR / '.env.example'
COMPOSE = BASE_DIR / 'docker-compose-coolify.yaml'


def parse_compose(path: Path) -> set[str]:
    data = yaml.safe_load(path.read_text())
    envs = set()
    for svc in data.get('services', {}).values():
        env = svc.get('environment', {})
        envs.update(env.keys())
    return envs


def parse_env_example(path: Path) -> dict[str, str]:
    envs = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, _, value = line.partition('=')
        envs[key] = value
    return envs


def main() -> None:
    compose_vars = parse_compose(COMPOSE)
    example_envs = parse_env_example(EXAMPLE)

    missing = compose_vars - example_envs.keys()
    extra = example_envs.keys() - compose_vars
    if missing or extra:
        print('Environment variable mismatch between docker-compose-coolify.yaml and .env.example', file=sys.stderr)
        if missing:
            print('Missing in .env.example:', ', '.join(sorted(missing)), file=sys.stderr)
        if extra:
            print('Extra in .env.example:', ', '.join(sorted(extra)), file=sys.stderr)
        sys.exit(1)

    placeholders = {
        'DJANGO_SECRET_KEY': '<django_secret_key>',
        'POSTGRES_PASSWORD': '<postgres_password>',
    }

    for key, placeholder in placeholders.items():
        value = os.getenv(key)
        if not value or value == placeholder or (key == 'DJANGO_SECRET_KEY' and value == 'change-this-to-a-random-secret-key'):
            print(f'{key} must be set. Generate a secure value at https://www.random.org/passwords/?num=5&len=32&format=html&rnd=new', file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
