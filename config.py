from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    google_application_credentials: Optional[str] = None
    hibp_api_key: Optional[str] = None
    etsy_client_id: Optional[str] = None
    etsy_client_secret: Optional[str] = None
    ebay_app_id: Optional[str] = None
    ebay_oauth_token: Optional[str] = None

    class Config:
        env_file = "../.env"
        env_file_encoding = 'utf-8'

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not self.google_application_credentials or not os.path.exists(self.google_application_credentials):
            print("Warning: GOOGLE_APPLICATION_CREDENTIALS is missing or invalid. Google Cloud APIs may fail.")

settings = Settings()