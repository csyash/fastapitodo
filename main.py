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

# Dependency to create a database session
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


# Function to verify plain password with hased password using pwd_context
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Function to get hashed password from plain password using pwd_context
def get_password_hash(password):
    return pwd_context.hash(password)


# Function to retrive User object from database using username. 
# Returns:schema.UserInDB | None: User object if found, None otherwise.

def get_user_db(username:str, session :Session) -> schema.UserInDB | None:
    user = session.query(models.User).filter(models.User.username==username).first()

    if user is not None:
        return user
    
    return None

#  Authenticate a user against the database.
# Returns: schema.UserInDB | bool: User object if authentication succeeds, False otherwise
def authenticate_user_db(session:Session, username:str, password:str):
    user =get_user_db(username,session)
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user

# Create new access token using jwt
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#   Dependency to get authenticated user from database
#   Returns authenticated user or Raises Exception otherwise
async def get_current_user_db(token : Annotated[str, Depends(oauth2_scheme)], session:Session = Depends(get_session)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Extracting the username from the token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username : str = payload.get("sub")
        
        if username is None:
            return credentials_exception
        token_data = schema.TokenData(username=username)
    except JWTError:
        return credentials_exception
    
    # Extracting the user from the database using get_user_db
    user = get_user_db(token_data.username, session)
    if user is None:
        return credentials_exception
    return user

async def get_current_active_user(current_user: Annotated[schema.User, Depends(get_current_user_db)],):
    return current_user


# Endpoint for user login to obtain an access token.
# Accepts only form data with fields 'username' and 'password' and content-type : 'application/x-www-form-urlencoded'
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


# Endpoint for New user registeration in database.
# Accepts data in application/json format
@app.post("/register")
async def register_user(newUser:schema.UserInDB, session : Session = Depends(get_session)):
    # Check if there exists a user with provided username.
    user = get_user_db(newUser.username, session)

    # Raise exception if Username not available
    if user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username not available"
        )
    
    # Creating new user in database
    new_user = models.User(username=newUser.username, firstName=newUser.firstname, lastName=newUser.lastname, password=newUser.hashed_password)
    new_user.password = get_password_hash(newUser.hashed_password)
    session.add(new_user)
    session.commit()
    session.refresh(new_user)
    return {"message" : "account created"}


# Endpoing to get all the todos of authorised user
@app.get("/todos")
async def get_todos( current_user:schema.User = Depends(get_current_user_db)):
    return current_user.todos

# Endpoint to create a new todo by authorised user.Accepts data in application/json format
@app.post("/todos")
def post_todos(todo:schema.TodoCreate , session: Session = Depends(get_session) , current_user:schema.User = Depends(get_current_user_db)):
    new_todo = models.Todo(task = todo.task, completed=todo.completed,user_id=current_user.id)
    session.add(new_todo)
    session.commit()
    session.refresh(new_todo)
    return new_todo

# Endpoint to update if  Todo is completed or not using todo_id
# No body required, It does Not of isCompleted in todo
@app.put("/todos/{todo_id}")
def set_completed_task(todo_id:int, session:Session = Depends(get_session), current_user:schema.User = Depends(get_current_user_db)):

    updated_todo = session.query(models.Todo).get(todo_id)
    if updated_todo and updated_todo.user_id == current_user.id:    
        updated_todo.completed = not updated_todo.completed
        session.commit()
        session.refresh(updated_todo)
        return updated_todo
    
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)

# Endpoint to delete a todo using todo_id
@app.delete("/todos/{todo_id}")
def delete_todo(todo_id:int, session:Session = Depends(get_session), current_user:schema.User = Depends(get_current_user_db)):
    deleted_todo = session.query(models.Todo).get(todo_id)

    if deleted_todo and deleted_todo.user_id == current_user.id:
        session.delete(deleted_todo)
        session.commit()
        session.close()
        return {"message" : "Todo deleted"}
    
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
