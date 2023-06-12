import csv
import hashlib
import logging
import os
from typing import List

import requests

from utils.crypt import encrypt_data

# Set up these environment files in the actual app
CSV_PATH = os.getenv("CSV_PATH")
APP_KEY = os.getenv("APP_KEY")
APP_SECRET = hashlib.sha256(os.getenv("APP_SECRET").encode("utf-8")).digest()
BLOCK_SIZE = int(os.getenv("BLOCK_SIZE", 16))
API_ENDPOINT = os.getenv("API_ENDPOINT")
DELETE_CSV = True if int(os.getenv("DELETE_FILE", "0")) == 1 else 0

# Setup Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def read_file() -> list:
    with open(CSV_PATH, "r") as f:
        data = list(csv.DictReader(f))
        return data


def forward_data(data: str) -> dict:
    return requests.post(
        API_ENDPOINT, json={"jdt": data}, headers={"htt": APP_KEY}
    ).json()


def forward_data_unencrypted(data: List[dict]) -> dict:
    """Use for testing purposes"""
    return requests.post(
        API_ENDPOINT, json=data, headers={"htt": APP_KEY}
    ).json()


def delete_file() -> None:
    os.remove(CSV_PATH)


def main():
    """
    1. Retrieve csv file generated by another PL process.
    2. Read the content and encrypt it using a combination of API key and secret.
    3. Forward the encrypted data to a centralized server of database (REST API)
    4. Delete the csv file.
    """
    raw_data = read_file()
    logger.info({"msg": "Got raw data", "raw_data": raw_data})

    # TODO: Let's not complicate ourselves with encryption for now
    # encrypted_data = encrypt_data(
    #     data=raw_data, app_secret=APP_SECRET, block_size=BLOCK_SIZE
    # )
    # logger.info({"msg": "Encrypted data", "encrypted_data": encrypted_data})
    #
    # response = forward_data(data=encrypted_data)

    response = forward_data_unencrypted(data=raw_data)
    logger.info({"msg": "Response from server", "response": response})

    if DELETE_CSV:
        delete_file()
        logger.info({"msg": "Done deleting the file", "file": CSV_PATH})


if __name__ == "__main__":
    main()
