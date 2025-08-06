# backend/models.py
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime

# Model for the data a user sends to the signup endpoint
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    idToken: str

# Model representing a user document in Firestore
class UserInDB(BaseModel):
    username: str
    email: EmailStr
    role: str = "student"
    created_at: datetime
    submissions: Optional[List[str]] = []