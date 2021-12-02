import os
from dotenv import load_dotenv
from pathlib import Path  # python3 only

# load enviorment variables
env_path = 'src/.env'
load_dotenv(dotenv_path=env_path)


class Config:
    """
    Set capi configuration vars from .env file
    """

    # Load in environment variables
    LOG_DIR = os.getenv('LOG_DIR')
    LOG_FILE_PREFIX = os.getenv('LOG_FILE_PREFIX')
    LOG_FORMAT = os.getenv('LOG_FORMAT')
    NVD_CVE_FILE_PREFIX = os.getenv('NVD_CVE_FILE_PREFIX')
    NVD_CVE_FILE_POSTFIX = os.getenv('NVD_CVE_FILE_POSTFIX')
    NVD_CVE_FILE_EXTENSION = os.getenv('NVD_CVE_FILE_EXTENSION')
    DOWNLOADED_DIR = os.getenv('DOWNLOADED_DIR')
    EXECUTE_DATES = os.getenv('EXECUTE_DATES')


