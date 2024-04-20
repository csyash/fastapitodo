from database import Base
from sqlalchemy import Column, Integer, String, Boolean, DateTime,ForeignKey
from datetime import datetime
from sqlalchemy.orm import validates,relationship
import re

# Validate email address using regular expression.
def validate_email(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email))

# Represents user table in database
class User(Base):
    __tablename__ = "user"

    id = Column(Integer, primary_key=True, index=True)
    username= Column(String, unique=True, index=True)
    firstName = Column(String)
    lastName = Column(String)
    email = Column(String, unique=True)
    password = Column(String)
    todos = relationship("Todo",back_populates="user")

    @validates("email")
    def validate_email_in_db(self, key, email):
        if not validate_email(email):
            raise ValueError("Invalid Email format")
        
        return email

# Represents todo table in database
class Todo(Base):
    __tablename__= "todo"

    id = Column(Integer,primary_key=True)
    task = Column(String(256))
    completed = Column(Boolean, default=False)
    createdAt = Column(DateTime, default=datetime.now())

    #  Foreign Key referencing to user table
    user_id = Column(Integer, ForeignKey("user.id"))
    user= relationship("User", back_populates="todos")



