import json
import logging
import os

def load_json_config(file_path):
    try:
        with open(file_path) as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error loading config file {file_path}: {e}")
        return None

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)