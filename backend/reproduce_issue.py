import jwt
import os

SECRET_KEY = "test"
ALGORITHM = "HS256"
to_encode = {"sub": "123"}

try:
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    print(f"Successfully encoded token: {token}")
except AttributeError as e:
    print(f"Failed with AttributeError: {e}")
except Exception as e:
    print(f"Failed with Exception: {e}")
