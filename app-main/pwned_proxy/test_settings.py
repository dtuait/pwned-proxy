from .settings import *  # noqa

# Use in-memory sqlite database for tests
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}
SECRET_KEY = 'test-secret-key'
