import requests

API_KEY = "sk-ant-api03-real-key-here-1234567890"
DATABASE_PASSWORD = "supersecret123"

def connect():
    return requests.get("https://api.example.com", headers={"Authorization": f"Bearer {API_KEY}"})
