import os

USED_AUTH_IDS = set()

def getID():
    return int.from_bytes(os.urandom(16), byteorder="big")

def getChallenge() -> dict:
    pass

def checkResponse(response: dict):
    pass