from fastapi import FastAPI,status,Depends,HTTPException
from pymongo import MongoClient
from typing import Annotated
import auth
from auth import get_current_user

app = FastAPI()
app.include_router(router=auth.router)
client = MongoClient(host=r'mongodb://localhost:27017')

def db_connect():
    db = client['auth_header']
    collection = db['jwt']

db_dependency = Annotated[None,Depends(db_connect)]
user_dependency = Annotated[dict,Depends(get_current_user)]

@app.get("/",status_code=status.HTTP_200_OK)
async def user(user:user_dependency,db:db_dependency): 
    if user is None:
        raise HTTPException(status_code=401,detail='AUthentication failed')
    return {"user":user}
