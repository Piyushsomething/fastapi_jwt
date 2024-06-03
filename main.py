from typing import List, Union
from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
import sqlite3

# Constants and secret key
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# OAuth2 bearer token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

# Pydantic models
class UserRegistration(BaseModel):
    name: str
    password: str

class UserUpdate(BaseModel):
    name: Union[str, None] = None
    password: Union[str, None] = None
    session: Union[str, None] = None
    plant_id: Union[int, None] = None

class PlantDetails(BaseModel):
    area_name: str
    variety: List[str]
    no_of_plants: int
    latitude: List[float]
    longitude: List[float]
    user_id: int

class TicketDetails(BaseModel):
    user_id: int
    payment_status: bool
    admin_approval: bool

# Database setup
conn = sqlite3.connect("app.db")
c = conn.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY, name TEXT, password TEXT, session TEXT, plant_id INTEGER)""")
c.execute("""CREATE TABLE IF NOT EXISTS plant_details
             (id INTEGER PRIMARY KEY, area_name TEXT, variety TEXT, no_of_plants INTEGER, latitude REAL, longitude REAL, user_id INTEGER)""")
c.execute("""CREATE TABLE IF NOT EXISTS tickets
             (id INTEGER PRIMARY KEY, user_id INTEGER, payment_status BOOLEAN, admin_approval BOOLEAN)""")
conn.commit()

# Helper functions
def get_user(user_id: int):
    c.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    if user:
        return {"id": user[0], "name": user[1], "password": user[2], "session": user[3], "plant_id": user[4]}

def authenticate_user(name: str, password: str):
    c.execute("SELECT * FROM users WHERE name=? AND password=?", (name, password))
    user = c.fetchone()
    if user:
        return {"id": user[0], "name": user[1], "password": user[2], "session": user[3], "plant_id": user[4]}

def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Routes
@app.post("/register")
async def register(user: UserRegistration):
    c.execute("SELECT * FROM users WHERE name=?", (user.name,))
    existing_user = c.fetchone()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already taken")
    c.execute("INSERT INTO users (name, password, session, plant_id) VALUES (?, ?, ?, ?)",
              (user.name, user.password, "", None))
    conn.commit()
    return {"message": "User registered successfully"}

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["id"])}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserUpdate)
async def read_users_me(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(user_id)
    if user is None:
        raise credentials_exception
    return user

@app.put("/users/me", response_model=UserUpdate)
async def update_user(user: UserUpdate, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    existing_user = get_user(user_id)
    if existing_user is None:
        raise credentials_exception
    update_data = []
    if user.name:
        update_data.append(f"name = '{user.name}'")
    if user.password:
        update_data.append(f"password = '{user.password}'")
    if user.session:
        update_data.append(f"session = '{user.session}'")
    if user.plant_id:
        update_data.append(f"plant_id = {user.plant_id}")
    update_query = "UPDATE users SET " + ", ".join(update_data) + f" WHERE id = {user_id}"
    c.execute(update_query)
    conn.commit()
    updated_user = get_user(user_id)
    return updated_user

@app.post("/plant_details", response_model=PlantDetails)
async def create_plant_details(plant_details: PlantDetails, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(user_id)
    if user is None:
        raise credentials_exception
    c.execute("INSERT INTO plant_details (area_name, variety, no_of_plants, latitude, longitude, user_id) VALUES (?, ?, ?, ?, ?, ?)",
              (plant_details.area_name, ",".join(plant_details.variety), plant_details.no_of_plants, ",".join(map(str, plant_details.latitude)), ",".join(map(str, plant_details.longitude)), user_id))
    conn.commit()
    plant_id = c.lastrowid
    c.execute("UPDATE users SET plant_id=? WHERE id=?", (plant_id, user_id))
    conn.commit()
    return plant_details

...

@app.post("/tickets", response_model=TicketDetails)
async def create_ticket(ticket_details: TicketDetails, token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user(user_id)
    if user is None:
        raise credentials_exception
    c.execute("INSERT INTO tickets (user_id, payment_status, admin_approval) VALUES (?, ?, ?)",
              (ticket_details.user_id, ticket_details.payment_status, ticket_details.admin_approval))
    conn.commit()
    ticket_id = c.lastrowid
    return TicketDetails(id=ticket_id, **ticket_details.dict())

# Run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)