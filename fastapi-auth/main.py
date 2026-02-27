from fastapi import FastAPI,HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from jose import jwt, JWTError
from fastapi.middleware.cors import CORSMiddleware
from utils import hash_password, verify_password, create_access_token

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials = True,
    allow_methods=["*"],
    allow_headers=["*"]

)

user_db={}

class User(BaseModel):
    username: str
    password: str


security = HTTPBearer()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        payload = jwt.decode(token, "supersecret", algorithms=["HS256"])
        username = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid Token")
        return username
    except JWTError:
            raise HTTPException(status_code=401, detail="Invalid Token")


@app.get("/")
def home():
    return {'message': 'Api is running'}

@app.post("/register")
def create_user(user: User):
    if user.username in user_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User alredy exists"
        )
    
    user_db[user.username] = hash_password(user.password)
    return {'message': 'User is created'}

@app.get("/users")
def get_users():
    return {'users': list(user_db.keys())} 


@app.post("/login")
def login(user: User):
    if user.username not in user_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    if not verify_password(user.password, user_db[user.username]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access_token = create_access_token({"sub": user.username})

    return {
        "access_token" : access_token,
        "token_type" : "bearer"
    }

@app.get("/protected")
def protected_route(current_user: str = Depends(get_current_user)):
    return {"message": f"Welcome {current_user}"}