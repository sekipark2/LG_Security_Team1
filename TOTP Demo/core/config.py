
import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseSettings

env_path = Path(".") / ".env"
load_dotenv(dotenv_path=env_path)


class Settings(BaseSettings):
    PROJECT_NAME: str = "LG Secu Team 1 - Login Server"
    PROJECT_VERSION: str = "1.0.0"
    email_sender: str = 'lgesecuteam1@gmail.com'
    email_password: str = 'imfzqouxcvsdujru'
    server_address: str = 'https://192.168.0.136:8000'


settings = Settings()