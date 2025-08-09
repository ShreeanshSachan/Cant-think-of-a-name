import os
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from firebase_admin import credentials, auth, firestore, initialize_app
from google.cloud.firestore_v1.document import DocumentSnapshot
from datetime import datetime
from models import UserCreate, UserInDB
from dotenv import load_dotenv


load_dotenv()

cred = credentials.Certificate(os.getenv("GOOGLE_APPLICATION_CREDENTIALS"))
initialize_app(cred)
db = firestore.client()



app = FastAPI()

# CORS for frontend 
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer()

async def get_current_user_from_token(token: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)]):

    if not token:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "No authorization token provided.",
            headers = {"WWW-Authenticate": "Bearer"},
        )
    try:
        decoded_token = auth.verify_id_token(token.credentials)
        user_uid = decoded_token['uid']
        user_doc:DocumentSnapshot = db.collection('users').document(user_uid).get()
        
        if not user_doc.exists:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail = "User not found in Firestore.",
            )
        return user_doc.to_dict()

    except auth.InvalidIdTokenError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid authentication credentials.",
            headers = {"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        raise HTTPException(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail = f"An error occurred: {e}",
        )

@app.post("/signup", status_code=status.HTTP_201_CREATED)
async def signup(user_data:UserCreate):

    try:
        decoded_token = auth.verify_id_token(user_data.idToken)
        user_uid = decoded_token['uid']
        email = decoded_token['email']

        user_ref = db.collection('users').document(user_uid)

        if user_ref.get().exists:
            raise HTTPException(
                status_code = status.HTTP_409_CONFLICT,
                detail = "User already exists"
            )

        new_user = UserInDB(
            username = user_data.username,
            email = email,
            created_at = datetime.now(),
            role = "student",
            submissions = []
        )
        user_ref.set(new_user.model_dump())

        return {"message":"User successfully registered.","user_id":user_uid}

    except auth.InvalidIdTokenError:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Invalid Firebase ID token.",
            headers = {"WWW-Authenticate": "Bearer"},
        )

@app.get("/protected-endpoint")
async def read_protected_data(current_user:Annotated[dict, Depends(get_current_user_from_token)]):
    return {"message":"Hello, you are authorized!","user_data":current_user}

@app.get("/admin-only")
async def admin_only_data(current_user:Annotated[dict, Depends(get_current_user_from_token)]):
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code = status.HTTP_403_FORBIDDEN,
            detail = "You do not have permission to access this resource."
        )
    return {"message":"Welcome, Admin!","user_data":current_user}

@app.get("/me")
async def get_current_user_profile(current_user: Annotated[dict, Depends(get_current_user_from_token)]):
    return {"user": current_user}
