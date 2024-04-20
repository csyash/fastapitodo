from fastapi import FastAPI, Depends,HTTPException,status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import timedelta,datetime,timezone
import schema,models
from database import Base,engine,SessionLocal
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError,jwt
from typing import Annotated
from dotenv import load_dotenv
import os


Base.metadata.create_all(engine)

load_dotenv()
app = FastAPI()

def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto ")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_db(username:str, session :Session) -> schema.UserInDB | None:
    user = session.query(models.User).filter(models.User.username==username).first()

    if user is not None:
        return user
    
    return None

def authenticate_user_db(session:Session, username:str, password:str):
    user =get_user_db(username,session)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user_db(token : Annotated[str, Depends(oauth2_scheme)], session:Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username : str = payload.get("sub")
        
        if username is None:
            raise credentials_exception
        token_data = schema.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user_db(token_data.username, session)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: Annotated[schema.User, Depends(get_current_user_db)],):
    return current_user

@app.post("/login")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], session : Session = Depends(get_session)
) -> schema.Token:
    user = authenticate_user_db(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return schema.Token(access_token=access_token, token_type="bearer")


@app.post("/register")
async def register_user(newUser:schema.UserInDB, session : Session = Depends(get_session)):
    user = get_user_db(newUser.username, session)
    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username not available"
        )
    
    new_user = models.User(username=newUser.username, firstName=newUser.firstname, lastName=newUser.lastname, password=newUser.hashed_password)
    new_user.password = get_password_hash(newUser.hashed_password)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return {"message" : "account created"}



@app.get("/todos")
async def get_todos( current_user:schema.User = Depends(get_current_user_db)):
    return current_user.todos

@app.post("/todos")
def post_todos(todo:schema.TodoCreate , session: Session = Depends(get_session) , current_user:schema.User = Depends(get_current_user_db)):
    new_todo = models.Todo(task = todo.task, completed=todo.completed,user_id=current_user.id)
    session.add(new_todo)
    session.commit()
    session.refresh(new_todo)
    return new_todo

@app.put("/todos/{todo_id}")
def set_completed_task(todo_id:int, session:Session = Depends(get_session), current_user:schema.User = Depends(get_current_user_db)):

    updated_todo = session.query(models.Todo).get(todo_id)
    if updated_todo and updated_todo.user_id == current_user.id:    
        updated_todo.completed = not updated_todo.completed
        session.commit()
        session.refresh(updated_todo)
        return updated_todo
    
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND)

@app.delete("/todos/{todo_id}")
def delete_todo(todo_id:int, session:Session = Depends(get_session), current_user:schema.User = Depends(get_current_user_db)):
    deleted_todo = session.query(models.Todo).get(todo_id)

    if deleted_todo and deleted_todo.user_id == current_user.id:
        session.delete(deleted_todo)
        session.commit()
        session.close()
        return {"message" : "Todo deleted"}
    
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND)
