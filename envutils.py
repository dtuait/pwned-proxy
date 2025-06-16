from pathlib import Path
import os
import secrets
from dotenv import load_dotenv


def ensure_env(base_dir: Path) -> None:
    """Load environment variables from existing .env or create one with defaults."""
    env_paths = [
        base_dir.parent / '.devcontainer' / '.env',
        base_dir.parent / '.env'
    ]
    for path in env_paths:
        if path.exists():
            load_dotenv(path)
            return

    env_path = base_dir.parent / '.env'
    env_vars = {
        'DJANGO_SECRET_KEY': secrets.token_urlsafe(50),
        'POSTGRES_DB': 'db',
        'POSTGRES_USER': 'postgres',
        'POSTGRES_PASSWORD': secrets.token_urlsafe(16),
        'DJANGO_SUPERUSER_USERNAME': 'admin',
        'DJANGO_SUPERUSER_PASSWORD': secrets.token_urlsafe(16),
        'DJANGO_SUPERUSER_EMAIL': '',
        'PUBLIC_AZURE_AD_TENANT_ID': '',
        'AZURE_APP_AIT_SOC_GRAPH_VICRE_REGISTRATION_CLIENT_ID': '',
        'AZURE_APP_AIT_SOC_GRAPH_VICRE_REGISTRATION_CLIENT_SECRET': '',
        'AZURE_APP_AIT_SOC_GRAPH_VICRE_REGISTRATION_RESOURCE': '',
        'AZURE_APP_AIT_SOC_GRAPH_VICRE_REGISTRATION_GRANT_TYPE': '',
        'DEVCONTAINER_NGROK_AUTHTOKEN': '',
    }

    with open(env_path, 'w') as fh:
        for key, value in env_vars.items():
            fh.write(f"{key}={value}\n")
            os.environ.setdefault(key, value)

