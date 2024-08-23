from fastapi import FastAPI, Request, Depends, HTTPException
from pydantic import BaseModel
from supabase import Client, create_client
from typing import Dict
from gradio_client import Client as GradioClient
import bcrypt
import jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordBearer
import io
import base64
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os


# Load environment variables from Keys.env
load_dotenv("Keys.env")

# Initialize FastAPI
app = FastAPI()

# Initialize Supabase client using environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["GET", "POST"],  # Allow only GET and POST methods
    allow_headers=["*"],  # Allow all headers
)

@app.get("/")
def read_root():
    return {"GreenFinTech": "RBiH+IITj"}

class UserData(BaseModel):
    name: str
    email: str
    new_password: str
    electricity_bill_number: str
    lpg_service_number: str
    water_bill_number: str
    city: str
    state: str

class SignInData(BaseModel):
    email: str
    password: str

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Could not validate credentials")
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


#Account Creation
@app.post("/api/create_account/")
async def submit_data(user_data: UserData):
    last_user = supabase.table("Users").select("User_ID").order("User_ID", desc=True).limit(1).execute()
    
    if last_user.data:
        new_user_id = int(last_user.data[0]['User_ID']) + 1
    else:
        new_user_id = 1

    hashed_password = bcrypt.hashpw(user_data.new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    data = {
        "User_ID": new_user_id,
        "Name": user_data.name,
        "Email": user_data.email,
        "Password": hashed_password,
        "State": user_data.state,
        "City": user_data.city,
        "Electricity": user_data.electricity_bill_number,
        "Water": user_data.water_bill_number,
        "LPG": user_data.lpg_service_number
    }
    
    try:
        response = supabase.table("Users").insert(data).execute()
        return {"status": "success", "UserID": new_user_id, "data": response.data}
    except Exception as e:
        return {"status": "error", "message": str(e)}


#Sign_in
@app.post("/api/sign_in/")
async def sign_in(sign_in_data: SignInData):
    response = supabase.table("Users").select("Email", "Password", "User_ID").eq("Email", sign_in_data.email).execute()
    
    if not response.data:
        return {"status": "failure", "message": "User not found"}
    stored_password = response.data[0]['Password']
    
    if bcrypt.checkpw(sign_in_data.password.encode('utf-8'), stored_password.encode('utf-8')):
        user_id = response.data[0]['User_ID']
        access_token = create_access_token(data={"sub": user_id})
        return {"status": "success", "message": "User signed in successfully", "access_token": access_token, "token_type": "bearer"}
    else:
        return {"status": "failure", "message": "Incorrect password"}

#Home
@app.get("/api/home/")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    # Verify and decode the token
    payload = verify_access_token(token)
    user_id = payload.get("sub")
    
    # Retrieve user information
    user_response = supabase.table("Users").select("User_ID", "Name", "Email", "Electricity", "Water", "LPG").eq("User_ID", user_id).execute()
    
    if not user_response.data:
        return {"status": "failure", "message": "User not found"}
    
    # Check if "Electricity", "Water", and "LPG" fields are not null
    user_data = user_response.data[0]
    is_electricity_available = user_data.get("Electricity") is not None
    is_water_available = user_data.get("Water") is not None
    is_lpg_available = user_data.get("LPG") is not None
    
    # Retrieve and calculate the average green score
    green_score_response = supabase.table("GreenScore").select("Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec").eq("User_ID", user_id).execute()
    
    if not green_score_response.data:
        return {"status": "failure", "message": "No green score data found"}
    
    # Calculate average green score
    green_scores = [float(green_score_response.data[0][month]) for month in ["Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec"]]
    average_green_score = sum(green_scores) / len(green_scores) if green_scores else 0
    
    # Retrieve and calculate the average recycle score
    recycle_score_response = supabase.table("RecycleScore").select("Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec").eq("User_ID", user_id).execute()
    
    if not recycle_score_response.data:
        return {"status": "failure", "message": "No recycle score data found"}
    
    # Calculate average recycle score
    recycle_scores = [float(recycle_score_response.data[0][month]) for month in ["Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec"]]
    average_recycle_score = sum(recycle_scores) / len(recycle_scores) if recycle_scores else 0
    
    # Prepare and return the response
    return {
        "status": "success",
        "user_data": user_data,
        "average_green_score": round(average_green_score, 3),
        "average_recycle_score": round(average_recycle_score, 3),
        "electricity_available": is_electricity_available,
        "water_available": is_water_available,
        "lpg_available": is_lpg_available
    }

      
      
# Chatbot
client = GradioClient("huggingface-projects/gemma-2-9b-it")
session_state = {"initialized": False}

class Query(BaseModel):
    message: str

@app.post("/api/chat/")
async def analyze_and_respond(query: Query):
    if not session_state["initialized"]:
        initial_message = "Just analyze this: My green score is based on my electricity, water, and LPG consumption. Don't respond now. But I will be talking about it from now"
        
        client.predict(
            message=initial_message,
            max_new_tokens=1024,
            temperature=0.6,
            top_p=0.9,
            top_k=50,
            repetition_penalty=1.2,
            api_name="/chat"
        )
        session_state["initialized"] = True

    result = client.predict(
        message=query.message,
        max_new_tokens=1024,
        temperature=0.6,
        top_p=0.9,
        top_k=50,
        repetition_penalty=1.2,
        api_name="/chat"
    )
    
    return {"response": result}

@app.get("/api/graph_analytics/", response_class=JSONResponse)
async def graph_analytics(token: str = Depends(oauth2_scheme)):
    # Verify and decode the token
    payload = verify_access_token(token)
    user_id = payload.get("sub")

    # Retrieve green score data
    green_score_response = supabase.table("GreenScore").select("Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec").eq("User_ID", user_id).execute()
    if not green_score_response.data:
        return {"status": "failure", "message": "No green score data found"}

    # Retrieve electricity consumption data
    electricity_response = supabase.table("Electricity").select("Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec").eq("User_ID", user_id).execute()
    if not electricity_response.data:
        return {"status": "failure", "message": "No electricity data found"}

    # Retrieve water consumption data
    water_response = supabase.table("Water").select("Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec").eq("User_ID", user_id).execute()
    if not water_response.data:
        return {"status": "failure", "message": "No water data found"}

    # Retrieve LPG consumption data
    lpg_response = supabase.table("LPG").select("Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec").eq("User_ID", user_id).execute()
    if not lpg_response.data:
        return {"status": "failure", "message": "No LPG data found"}

    # Retrieve recycle points data
    recycle_score_response = supabase.table("RecycleScore").select("Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec").eq("User_ID", user_id).execute()
    if not recycle_score_response.data:
        return {"status": "failure", "message": "No recycle score data found"}

    # Extract scores and corresponding months
    months = ["Jan-Feb", "Mar-Apr", "May-Jun", "Jul-Aug", "Sep-Oct", "Nov-Dec"]

    green_scores = {month: float(green_score_response.data[0][month]) for month in months}
    electricity = {month: float(electricity_response.data[0][month]) for month in months}
    water = {month: float(water_response.data[0][month]) for month in months}
    lpg = {month: float(lpg_response.data[0][month]) for month in months}
    recycle_points = {month: float(recycle_score_response.data[0][month]) for month in months}

    # Construct the response data
    response_data = {
        "status": "success",
        "data": {
            "months": months,
            "green_scores": green_scores,
            "electricity": electricity,
            "water": water,
            "lpg": lpg,
            "recycle_points": recycle_points
        }
    }

    # Return the data as JSON
    return JSONResponse(content=response_data)
