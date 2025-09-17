import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = os.getenv('ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', 30)
REFRESH_TOKEN_EXPIRE_MINUTES = os.getenv('REFRESH_TOKEN_EXPIRE_MINUTES', 10080)
EMAIL_TOKEN_EXPIRE_MINUTES = os.getenv('EMAIL_TOKEN_EXPIRE_MINUTES', 1440)

DEBUG = False
ADD_MONEY = 1000.00

DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASS = os.getenv('DB_PASS')
DB_HOST = os.getenv('DB_HOST')
DB_PORT = os.getenv('DB_PORT')

DATABASE_URL = f'postgresql+asyncpg://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
DB_ALEMBIC_URL = f'postgresql+psycopg://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
TEST_DATABASE_URL = 'sqlite+aiosqlite:///:memory:'

REDIS_URL = os.getenv('REDIS_URL')

EMAIL_HOST = os.getenv('EMAIL_HOST')
EMAIL_PORT = os.getenv('EMAIL_PORT')
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS')
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')

# local | dev | prod
LOGGING_MODE = 'prod'
