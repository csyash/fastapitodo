# FastAPI Todo App

This is a simple Todo application built with FastAPI, SQLAlchemy, and JWT for authentication.

## Setup

1. Clone the repository:
   git clone https://github.com/yourusername/fastapi-todo-app.git

2. Install dependencies:
    pip install -r requirements.txt

3. Set up the database:
    Make sure you have PostgreSQL installed and running.
    Update the database connection details in database.py.

4. Run:
    uvicorn main:app --reload

## Endpoints

### Authentication

#### POST /login
- **Description**: Endpoint to obtain an access token for authentication.
- **Body**: Form data with fields 'username' and 'password'.
- **Content-Type**: application/x-www-form-urlencoded
- **Response**: Returns a JWT access token.<br>
  {
    "access_token": "your_access_token",
    "token_type": "bearer"
  }

#### POST /register
- **Description**: Endpoint to register a new user.
- **Body**: User details in JSON format.
- **Response**: Returns a message indicating successful registration.
- **Fields**: 'username', 'email', 'firstname', 'lastname', 'hashed_password' (dont use 'password', use 'password' will fix it ). <br>
{
  "username": "string",
  "email": "string",
  "firstname": "string",
  "lastname": "string",
  "todos": [],
  "hashed_password": "string"
}

## Todos
#### GET /todos
- **Description**: Get all todos for the authenticated user.<br>
- **Authorization**: Bearer Token (Include access token in headers).<br>
- **Response**: Returns a list of todo items.<br>

#### POST /todos
- **Description**: create new todo for the authenticated user.<br>
- **Authorization**: Bearer Token (Include access token in headers)<br>
{
  "task": "string",
}

#### PUT /todos/{todo_id}
- **Description**: Update isCompleted in todo. Updates Todo isCompleted as Not of isCompleted in database. <br>
- **Authorization**: Bearer Token (Include access token in headers)<br>

#### DELETE /todos/{todo_id}
- **Description**: Deletes todo with corresponding id.<br>
- **Authorization**: Bearer Token (Include access token in headers)<br>
