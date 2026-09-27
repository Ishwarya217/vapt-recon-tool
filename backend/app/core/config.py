import os
from typing import List, Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # App
    APP_NAME: str = "VAPT Recon Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./vapt_recon.db"

    # Scanner
    SCANNER_MODE: str = "real"  # "real" or "mock"

    # theHarvester
    THEHARVESTER_SOURCES: str = "hackertarget,rapiddns,crtsh,certspotter,otx"
    THEHARVESTER_LIMIT: int = 500
    THEHARVESTER_TIMEOUT: int = 300

    # testssl.sh
    TESTSSL_GIT_BASH: str = r"C:\Program Files\Git\bin\bash.exe"
    TESTSSL_TIMEOUT: int = 600

    # API Keys (optional)
    SHODAN_API_KEY: Optional[str] = None
    CENSYS_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://localhost:3000", "http://127.0.0.1:5173"]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "allow"


settings = Settings()
