from passlib.context import CryptContext
from jose import JWTError, jwt 
from datetime import datetime, timedelta

SECRET_KEY = "supersecret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Use bcrypt_sha256 to avoid bcrypt's 72-byte input limitation by pre-hashing
# long passwords with SHA-256. Keep plain "bcrypt" as a fallback in the list
# so existing hashes are still supported.
pwd_context = CryptContext(schemes=["bcrypt_sha256", "bcrypt"], deprecated="auto")


def hash_password(password: str):
    if password is None:
        raise ValueError("password must be provided")
    # passlib handlers expect a str; bcrypt_sha256 will internally pre-hash
    # long inputs so callers don't need to truncate manually.
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)