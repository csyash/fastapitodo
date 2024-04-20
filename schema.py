from pydantic import BaseModel
from datetime import datetime

class TodoCreate(BaseModel):
    task : str
    createdAt : datetime = datetime.now()
    completed : bool = False

class Todo(TodoCreate):
    id:int

    class Config:
        from_attributes =True

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    firstname: str | None = None
    lastname: str | None = None
    todos : list[Todo] = []

    class Config:
        from_attributes = True


class UserInDB(User):
    hashed_password: str