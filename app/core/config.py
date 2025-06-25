"""
Advanced configuration management for fraud detection system
Handles environment variables, security settings, and application configuration
"""

import os
from pathlib import Path
from typing import Optional, List
from pydantic import BaseSettings, validator
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    """Application settings with validation and defaults"""
    
    # Application Info
    app_name: str = "Fraud Detection & Tracking System"
    app_version: str = "1.0.0"
    app_description: str = "Advanced fraud detection and case management system"
    
    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8080
    debug: bool = False
    
    # Security Configuration
    secret_key: str = "fraud_detection_secret_key_change_in_production"
    access_token_expire_minutes: int = 60 * 24  # 24 hours
    algorithm: str = "HS256"
    
    # Database Configuration
    database_url: str = "sqlite:///./data/fraud_detection.db"
    database_echo: bool = False
    
    # Fraud Detection Configuration
    default_risk_threshold: float = 70.0
    max_transaction_amount: float = 50000.0
    velocity_check_window_minutes: int = 60
    geographic_risk_countries: List[str] = ["XX", "YY"]  # ISO country codes
    
    # Alert Configuration
    alert_retention_days: int = 90
    max_alerts_per_page: int = 50
    
    # Case Management Configuration
    case_retention_days: int = 365
    max_cases_per_page: int = 25
    
    # External API Configuration
    enable_external_apis: bool = False
    external_api_timeout: int = 30
    
    # Logging Configuration
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # Asset Configuration
    static_files_path: str = "app/static"
    upload_path: str = "app/static/uploads"
    max_upload_size: int = 10 * 1024 * 1024  # 10MB
    
    @validator('secret_key')
    def validate_secret_key(cls, v):
        if v == "fraud_detection_secret_key_change_in_production" and not os.getenv('DEBUG'):
            raise ValueError("Please change the default secret key in production")
        return v
    
    @validator('database_url')
    def validate_database_url(cls, v):
        # Ensure database directory exists for SQLite
        if v.startswith('sqlite:'):
            db_path = Path(v.replace('sqlite:///', ''))
            db_path.parent.mkdir(parents=True, exist_ok=True)
        return v
    
    @validator('default_risk_threshold')
    def validate_risk_threshold(cls, v):
        if not 0 <= v <= 100:
            raise ValueError("Risk threshold must be between 0 and 100")
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Global settings instance
settings = Settings()

# Ensure required directories exist
Path(settings.static_files_path).mkdir(parents=True, exist_ok=True)
Path(settings.upload_path).mkdir(parents=True, exist_ok=True)
Path("data").mkdir(parents=True, exist_ok=True)
Path("logs").mkdir(parents=True, exist_ok=True)