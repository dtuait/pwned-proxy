import os
import django
import random
import string

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pwned_proxy.settings')

# Setup Django
django.setup()

from django.contrib.auth import get_user_model

User = get_user_model()

username = os.getenv('DJANGO_SUPERUSER_USERNAME', 'admin')
email = os.getenv('DJANGO_SUPERUSER_EMAIL', '')

if not User.objects.filter(username=username).exists():
    password = ''.join(random.SystemRandom().choices(string.ascii_letters + string.digits, k=32))
    User.objects.create_superuser(username=username, email=email, password=password)
    print('Created default admin user:', username)
    print('Password:', password)
else:
    print('Default admin already exists: %s' % username)
