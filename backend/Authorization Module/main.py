# backend/main.py
import os
from typing import Annotated

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from firebase_admin import credentials, auth, firestore, initialize_app
from google.cloud.firestore_v1.document import DocumentSnapshot
from datetime import datetime

# Import the models you just created
from models import UserCreate, UserInDB

# Initialize the Firebase Admin SDK
cred = credentials.Certificate(os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))
initialize_app(cred)
db = firestore.client()

# Initialize FastAPI application
app = FastAPI()

# --- MOVE THIS FUNCTION HERE ---
# This is the dependency function we'll use to protect endpoints
bearer_scheme = HTTPBearer()
async def get_current_user_from_token(token: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)]):
    # This is a dependency that verifies a Firebase ID token.
    # We will expand on this logic in a later step. For now, we'll
    # just return the decoded token.
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No authorization token provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        decoded_token = auth.verify_id_token(token.credentials)
        user_uid = decoded_token['uid']
        user_doc: DocumentSnapshot = db.collection('users').document(user_uid).get()
        
        if not user_doc.exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found in Firestore.",
            )
            
        return user_doc.to_dict()

    except auth.InvalidIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        # Catch other potential errors, e.g., network issues, etc.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {e}",
        )
# --- END OF MOVED FUNCTION ---

@app.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(user_data: UserCreate):
    """
    Registers a new user by creating a document in the Firestore `users` collection.
    """
    try:
        # Verify the Firebase ID token
        decoded_token = auth.verify_id_token(user_data.idToken)
        user_uid = decoded_token['uid']
        email = decoded_token['email']
        
        # Create a new user document in Firestore
        user_ref = db.collection('users').document(user_uid)
        
        # Check if user document already exists
        if user_ref.get().exists:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User already exists")

        new_user = UserInDB(
            username=user_data.username,
            email=email,
            created_at=datetime.now(),
            role="student",
            submissions=[]
        )
        user_ref.set(new_user.model_dump())
        
        return {"message": "User successfully registered.", "user_id": user_uid}

    except auth.InvalidIdTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Firebase ID token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

@app.get("/protected-endpoint")
async def read_protected_data(current_user: Annotated[dict, Depends(get_current_user_from_token)]):
    """
    An endpoint that can only be accessed with a valid Firebase ID token.
    """
    return {"message": "Hello, you are authorized!", "user_data": current_user}

@app.get("/admin-only")
async def admin_only_data(current_user: Annotated[dict, Depends(get_current_user_from_token)]):
    """
    An endpoint only accessible to users with the 'admin' role.
    """
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this resource."
        )
    return {"message": "Welcome, Admin!", "user_data": current_user}