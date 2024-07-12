from fastapi import APIRouter,Depends,HTTPException,status
from datetime import timedelta,datetime
from typing import Annotated
from pydantic import BaseModel
from pymongo import MongoClient
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm,OAuth2PasswordBearer
from jose import jwt,JWTError
import logging

logging.getLogger('passlib').setLevel(logging.ERROR)
router = APIRouter(
    prefix="/auth",
    tags=['auth']
)
client = MongoClient(host='mongodb://localhost:27017')  
SECRET_KEY = '084DDE2BFB8FF500005E345C0CFF3E1A'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'],deprecated='auto')
outh2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

class CreateUserRequest(BaseModel):
    username:str
    password:str

class Token(BaseModel):
    access_token:str
    token_type:str

def gett_db():
    db = client['auth_header']
    return db['jwt']

db_dependency = Annotated[None,Depends(gett_db)]

@router.post('/',status_code=status.HTTP_201_CREATED)
async def create_user(db:db_dependency,create_user:CreateUserRequest):
    create_user_values = {
    "username": create_user.username,
    "hashed_password":bcrypt_context.hash(create_user.password)
    }
    a = db.insert_one(create_user_values)
    return {"message": "User created successfully"}
    
@router.post("/token",response_model=Token)
async def access_token(form_data:Annotated[OAuth2PasswordRequestForm,Depends()],db:db_dependency):
    users = authenticate_users(form_data.username,form_data.password,db)
    if not users:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='could not validate user')
    token = create_access_token(users['username'],timedelta(minutes=20))

    return {'access_token':token,'token_type':'bearer'}

def create_access_token(username:str,expires_delta:timedelta):
    encode = {'sub':username}
    expires = datetime.now()+expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode,SECRET_KEY,algorithm=ALGORITHM)



def authenticate_users(username: str, password: str, db):
    user = db.find_one({'username': username})
    if not user:
        return False
    try:
        bcrypt_context.verify(password, user['hashed_password'])
    except:
        return False
    return user

async def get_current_user(token:Annotated[str,Depends(outh2_bearer)]):
    try:
        payload = jwt.decode(token,SECRET_KEY,ALGORITHM)
        username:str = payload.get('sub')
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='could not validate user')
        return {'username':username}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail='could not validate user')