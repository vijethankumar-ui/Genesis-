
import os
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "genesis_consent")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD")


JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY") or os.getenv("JWT_SECRET")
JWT_SECRET = JWT_SECRET_KEY
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

AUTH_DEMO_USERNAME = os.getenv("AUTH_DEMO_USERNAME")
AUTH_DEMO_PASSWORD = os.getenv("AUTH_DEMO_PASSWORD")
AUTH_DEMO_SUBJECT_ID = os.getenv("AUTH_DEMO_SUBJECT_ID")
AUTH_DEMO_ROLE = os.getenv("AUTH_DEMO_ROLE")

ACCESS_TOKEN_MINUTES = int(
    os.getenv("ACCESS_TOKEN_MINUTES", "10")
)
