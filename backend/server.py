from fastapi import FastAPI, HTTPException, Depends, Request, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
import os
import uuid
import bcrypt
import jwt
from datetime import datetime, timedelta
import base64
import secrets
import asyncio
from urllib.parse import urlparse
import json
import httpx # Added for making HTTP requests to M-Pesa API
from bson import ObjectId # Import ObjectId for handling MongoDB ObjectIds

# Environment variables
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-here')

# M-Pesa environment variables (Crucial for real integration)
MPESA_CONSUMER_KEY = os.environ.get('MPESA_CONSUMER_KEY', '')
MPESA_CONSUMER_SECRET = os.environ.get('MPESA_CONSUMER_SECRET', '')
MPESA_BUSINESS_SHORTCODE = os.environ.get('MPESA_BUSINESS_SHORTCODE', '')
MPESA_PASSKEY = os.environ.get('MPESA_PASSKEY', '')
MPESA_LIPA_NA_MPESA_SHORTCODE = os.environ.get('MPESA_LIPA_NA_MPESA_SHORTCODE', '') # For STK Push
MPESA_B2C_SHORTCODE = os.environ.get('MPESA_B2C_SHORTCODE', '') # For B2C withdrawals
MPESA_INITIATOR_NAME = os.environ.get('MPESA_INITIATOR_NAME', '') # For B2C
MPESA_SECURITY_CREDENTIAL = os.environ.get('MPESA_SECURITY_CREDENTIAL', '') # Encrypted password for B2C initiator

# M-Pesa API URLs (Sandbox/Production - adjust as needed)
MPESA_AUTH_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
MPESA_STKPUSH_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
MPESA_B2C_URL = "https://sandbox.safaricom.co.ke/mpesa/b2c/v1/paymentrequest"
# NOTE: For production, change 'sandbox.safaricom.co.ke' to 'api.safaricom.co.ke'

app = FastAPI(title="EarnPlatform API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
client = AsyncIOMotorClient(MONGO_URL)
db = client.earnplatform

# Pydantic models
class UserRegister(BaseModel):
    email: str
    password: str
    full_name: str
    phone: str
    referral_code: Optional[str] = None
    role: Optional[str] = "user" # Added role with default "user"

class UserLogin(BaseModel):
    email: str
    password: str

class DepositRequest(BaseModel):
    amount: float
    phone: str

class WithdrawalRequest(BaseModel):
    amount: float
    phone: str
    reason: Optional[str] = "Withdrawal request"

class Task(BaseModel):
    title: str
    description: str
    reward: float
    type: str  # survey, ad, writing, referral, social
    requirements: Dict[str, Any]
    is_active: Optional[bool] = True # Added for admin task management

class TaskCompletion(BaseModel):
    task_id: str
    completion_data: Dict[str, Any]

class NotificationCreate(BaseModel):
    title: str
    message: str
    user_id: Optional[str] = None  # None means broadcast to all users

class UpdateWithdrawalStatus(BaseModel):
    status: str # "approved", "rejected", "completed", "failed"
    reason: Optional[str] = None

class UpdateTaskStatus(BaseModel):
    is_active: bool

# Utility functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str, role: str) -> str: # Added role to JWT payload
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role, # Include role in token
        'exp': datetime.utcnow() + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_jwt_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def generate_referral_code() -> str:
    return secrets.token_urlsafe(8).upper()

def json_serializable_doc(doc):
    """
    Recursively converts MongoDB ObjectId and datetime objects within a document
    or list of documents to strings for JSON serialization.
    Also renames '_id' to 'id'.
    """
    if isinstance(doc, list):
        return [json_serializable_doc(item) for item in doc]
    if isinstance(doc, dict):
        for key, value in doc.items():
            if isinstance(value, ObjectId):
                doc[key] = str(value)
            elif isinstance(value, datetime):
                doc[key] = value.isoformat()
            elif isinstance(value, dict):
                doc[key] = json_serializable_doc(value)
            elif isinstance(value, list):
                doc[key] = [json_serializable_doc(item) for item in value]
        if '_id' in doc:
            doc['id'] = str(doc.pop('_id')) # Rename _id to id and convert to string
        return doc
    return doc

# M-Pesa Utility Functions
async def get_mpesa_access_token():
    """Fetches M-Pesa API access token."""
    try:
        consumer_key_secret = f"{MPESA_CONSUMER_KEY}:{MPESA_CONSUMER_SECRET}"
        encoded_auth = base64.b64encode(consumer_key_secret.encode('utf-8')).decode('utf-8')
        
        async with httpx.AsyncClient() as client:
            response = await client.get(
                MPESA_AUTH_URL,
                headers={"Authorization": f"Basic {encoded_auth}"}
            )
            response.raise_for_status() # Raise an exception for HTTP errors
            return response.json()["access_token"]
    except httpx.HTTPStatusError as e:
        print(f"M-Pesa Auth HTTP error: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=500, detail=f"M-Pesa authentication failed: {e.response.text}")
    except Exception as e:
        print(f"M-Pesa Auth error: {e}")
        raise HTTPException(status_code=500, detail="Could not get M-Pesa access token")

async def generate_mpesa_password(timestamp: str):
    """Generates password for M-Pesa STK Push."""
    data_to_encode = f"{MPESA_LIPA_NA_MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}"
    encoded_password = base64.b64encode(data_to_encode.encode('utf-8')).decode('utf-8')
    return encoded_password

# Dependency to get current user
async def get_current_user(request: Request):
    token = request.headers.get('Authorization')
    if not token:
        raise HTTPException(status_code=401, detail="No token provided")
    
    if token.startswith('Bearer '):
        token = token[7:]
    
    payload = verify_jwt_token(token)
    user = await db.users.find_one({"user_id": payload['user_id']})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    
    return user

# Dependency to get current admin user
async def get_current_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Not authorized. Admin access required.")
    return current_user

# Auth routes
@app.post("/api/auth/register")
async def register(user_data: UserRegister):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Check phone number
    existing_phone = await db.users.find_one({"phone": user_data.phone})
    if existing_phone:
        raise HTTPException(status_code=400, detail="Phone number already registered")
    
    user_id = str(uuid.uuid4())
    referral_code = generate_referral_code()
    
    # Handle referral if provided
    referred_by = None
    if user_data.referral_code:
        referrer = await db.users.find_one({"referral_code": user_data.referral_code})
        if referrer:
            referred_by = referrer['user_id']
    
    # Create user
    user_doc = {
        "user_id": user_id,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "full_name": user_data.full_name,
        "phone": user_data.phone,
        "referral_code": referral_code,
        "referred_by": referred_by,
        "wallet_balance": 0.0,
        "is_activated": False,
        "activation_amount": 500.0,  # KSH 500 activation fee
        "total_earned": 0.0,
        "total_withdrawn": 0.0,
        "referral_earnings": 0.0,
        "task_earnings": 0.0,
        "referral_count": 0,
        "created_at": datetime.utcnow(),
        "last_login": datetime.utcnow(),
        "notifications_enabled": True,
        "theme": "light",
        "role": user_data.role # Set user role
    }
    
    await db.users.insert_one(user_doc)
    
    # Create referral tracking if referred
    if referred_by:
        await db.referrals.insert_one({
            "referral_id": str(uuid.uuid4()),
            "referrer_id": referred_by,
            "referred_id": user_id,
            "status": "pending",  # pending -> activated -> rewarded
            "created_at": datetime.utcnow(),
            "activation_date": None,
            "reward_amount": 50.0  # KSH 50 referral bonus
        })
    
    token = create_jwt_token(user_id, user_data.email, user_data.role) # Pass role to token creation
    
    # Return serializable user data
    return {
        "success": True,
        "message": "Registration successful! Please deposit KSH 500 to activate your account.",
        "token": token,
        "user": json_serializable_doc({
            "user_id": user_id,
            "email": user_data.email,
            "full_name": user_data.full_name,
            "referral_code": referral_code,
            "is_activated": False,
            "wallet_balance": 0.0,
            "role": user_data.role # Return role in user object
        })
    }

@app.post("/api/auth/login")
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user['password']):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Update last login
    await db.users.update_one(
        {"user_id": user['user_id']},
        {"$set": {"last_login": datetime.utcnow()}}
    )
    
    token = create_jwt_token(user['user_id'], user['email'], user.get('role', 'user')) # Pass role to token creation
    
    # Return serializable user data
    return {
        "success": True,
        "message": "Login successful!",
        "token": token,
        "user": json_serializable_doc({
            "user_id": user['user_id'],
            "email": user['email'],
            "full_name": user['full_name'],
            "referral_code": user['referral_code'],
            "is_activated": user['is_activated'],
            "wallet_balance": user['wallet_balance'],
            "theme": user.get('theme', 'light'),
            "role": user.get('role', 'user') # Return role in user object
        })
    }

# Dashboard routes
@app.get("/api/dashboard/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    user_id = current_user['user_id']
    
    # Get recent transactions
    transactions = await db.transactions.find(
        {"user_id": user_id}
    ).sort("created_at", -1).limit(10).to_list(10)
    
    # Get referral stats
    referral_stats = await db.referrals.aggregate([
        {"$match": {"referrer_id": user_id}},
        {"$group": {
            "_id": "$status",
            "count": {"$sum": 1},
            "total_reward": {"$sum": "$reward_amount"}
        }}
    ]).to_list(10)
    
    # Get notifications
    notifications = await db.notifications.find(
        {"$or": [{"user_id": user_id}, {"user_id": None}]}
    ).sort("created_at", -1).limit(5).to_list(5)
    
    # Apply serialization helper to all fetched data
    serialized_transactions = json_serializable_doc(transactions)
    serialized_referral_stats = json_serializable_doc(referral_stats)
    serialized_notifications = json_serializable_doc(notifications)
    
    # The current_user object also needs to be serialized before returning
    # Pass a copy to avoid modifying the original dictionary that might be used elsewhere
    serialized_current_user = json_serializable_doc(current_user.copy()) 
    
    return {
        "success": True,
        "user": {
            "full_name": serialized_current_user['full_name'],
            "wallet_balance": serialized_current_user['wallet_balance'],
            "is_activated": serialized_current_user['is_activated'],
            "activation_amount": serialized_current_user.get('activation_amount', 500.0),
            "total_earned": serialized_current_user.get('total_earned', 0.0),
            "total_withdrawn": serialized_current_user.get('total_withdrawn', 0.0),
            "referral_earnings": serialized_current_user.get('referral_earnings', 0.0),
            "task_earnings": serialized_current_user.get('task_earnings', 0.0),
            "referral_count": serialized_current_user.get('referral_count', 0),
            "referral_code": serialized_current_user['referral_code'],
            "role": serialized_current_user.get('role', 'user')
        },
        "recent_transactions": serialized_transactions,
        "referral_stats": serialized_referral_stats,
        "notifications": serialized_notifications
    }

# Payment routes
@app.post("/api/payments/deposit")
async def initiate_deposit(deposit_data: DepositRequest, current_user: dict = Depends(get_current_user)):
    transaction_id = str(uuid.uuid4())
    
    # M-Pesa STK Push Integration
    # This is where the real M-Pesa STK Push API call would happen
    # Replace the simulated logic with actual M-Pesa API integration
    
    # Get M-Pesa access token
    access_token = await get_mpesa_access_token()
    
    # Generate timestamp and password
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    password = await generate_mpesa_password(timestamp)
    
    # Format phone number for M-Pesa (e.g., 2547XXXXXXXX)
    phone_number = deposit_data.phone
    if not phone_number.startswith('254'):
        raise HTTPException(status_code=400, detail="Phone number must start with 254 (Kenya format)")

    # M-Pesa STK Push Payload
    stk_payload = {
        "BusinessShortCode": MPESA_LIPA_NA_MPESA_SHORTCODE,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline", # Or "CustomerBuyGoodsOnline"
        "Amount": int(deposit_data.amount), # Amount must be an integer
        "PartyA": phone_number,
        "PartyB": MPESA_LIPA_NA_MPESA_SHORTCODE,
        "PhoneNumber": phone_number,
        "CallBackURL": "YOUR_MPESA_CALLBACK_URL_HERE", # IMPORTANT: Replace with your actual callback URL
        "AccountReference": f"EarnPlatform-{current_user['user_id']}",
        "TransactionDesc": f"Deposit for user {current_user['email']}"
    }

    try:
        async with httpx.AsyncClient() as client:
            mpesa_response = await client.post(
                MPESA_STKPUSH_URL,
                json=stk_payload,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                },
                timeout=30.0
            )
            mpesa_response.raise_for_status()
            mpesa_data = mpesa_response.json()
            
            if mpesa_data.get("ResponseCode") == "0":
                # STK Push initiated successfully
                transaction_doc = {
                    "transaction_id": transaction_id,
                    "user_id": current_user['user_id'],
                    "type": "deposit",
                    "amount": deposit_data.amount,
                    "phone": deposit_data.phone,
                    "status": "pending", # Status will be updated by M-Pesa callback
                    "method": "mpesa",
                    "created_at": datetime.utcnow(),
                    "completed_at": None,
                    "mpesa_receipt": None,
                    "CheckoutRequestID": mpesa_data.get("CheckoutRequestID"),
                    "CustomerMessage": mpesa_data.get("CustomerMessage")
                }
                await db.transactions.insert_one(transaction_doc)
                
                return {
                    "success": True,
                    "message": f"Deposit of KSH {deposit_data.amount} initiated. Please complete payment on your phone.",
                    "transaction_id": transaction_id,
                    "amount": deposit_data.amount,
                    "phone": deposit_data.phone,
                    "mpesa_response": mpesa_data # For debugging, remove in production
                }
            else:
                # STK Push initiation failed
                print(f"M-Pesa STK Push failed: {mpesa_data}")
                raise HTTPException(status_code=400, detail=mpesa_data.get("CustomerMessage", "M-Pesa STK Push initiation failed"))

    except httpx.HTTPStatusError as e:
        print(f"M-Pesa STK Push HTTP error: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=500, detail=f"M-Pesa STK Push failed: {e.response.text}")
    except Exception as e:
        print(f"Error initiating M-Pesa STK Push: {e}")
        raise HTTPException(status_code=500, detail="Error initiating M-Pesa deposit. Please try again.")

# NOTE: This endpoint is crucial for real M-Pesa integration.
# M-Pesa will send a callback to this URL to confirm payment status.
@app.post("/api/payments/mpesa-callback")
async def mpesa_callback(request: Request):
    """
    M-Pesa C2B/STK Push Callback URL.
    This endpoint receives confirmation from Safaricom about a transaction.
    """
    try:
        data = await request.json()
        print(f"M-Pesa Callback Received: {json.dumps(data, indent=2)}")

        # Process the callback data
        # Example for STK Push Callback:
        if data.get("Body") and data["Body"].get("stkCallback"):
            stk_callback = data["Body"]["stkCallback"]
            checkout_request_id = stk_callback["CheckoutRequestID"]
            result_code = stk_callback["ResultCode"]
            result_desc = stk_callback["ResultDesc"]
            
            transaction_status = "failed"
            mpesa_receipt = None
            amount = 0.0
            phone_number = None

            if result_code == 0:
                # Successful transaction
                transaction_status = "completed"
                callback_metadata = stk_callback.get("CallbackMetadata", {}).get("Item", [])
                
                for item in callback_metadata:
                    if item["Name"] == "MpesaReceiptNumber":
                        mpesa_receipt = item["Value"]
                    elif item["Name"] == "Amount":
                        amount = float(item["Value"])
                    elif item["Name"] == "PhoneNumber":
                        phone_number = str(item["Value"]) # Safaricom sends 254 format

                # Find the pending transaction in your DB
                transaction = await db.transactions.find_one({"CheckoutRequestID": checkout_request_id, "status": "pending"})
                if transaction:
                    # Update transaction status
                    await db.transactions.update_one(
                        {"_id": transaction["_id"]},
                        {
                            "$set": {
                                "status": transaction_status,
                                "completed_at": datetime.utcnow(),
                                "mpesa_receipt": mpesa_receipt,
                                "amount": amount, # Update amount from callback for accuracy
                                "phone": phone_number # Update phone from callback for accuracy
                            }
                        }
                    )

                    # Update user wallet and activation status
                    user = await db.users.find_one({"user_id": transaction['user_id']})
                    if user:
                        new_balance = user['wallet_balance'] + amount
                        update_data = {"wallet_balance": new_balance}
                        
                        if not user['is_activated'] and amount >= user.get('activation_amount', 500.0):
                            update_data['is_activated'] = True
                            # Process referral reward if user was referred
                            if user.get('referred_by'):
                                await process_referral_reward(user['user_id'], user['referred_by'])
                        
                        await db.users.update_one(
                            {"user_id": user['user_id']},
                            {"$set": update_data}
                        )
                        
                        await create_notification({
                            "title": "Deposit Successful!",
                            "message": f"Your deposit of KSH {amount} has been processed successfully. Receipt: {mpesa_receipt}",
                            "user_id": user['user_id']
                        })
                else:
                    print(f"Transaction with CheckoutRequestID {checkout_request_id} not found or already processed.")
            else:
                # Failed transaction
                transaction = await db.transactions.find_one({"CheckoutRequestID": checkout_request_id, "status": "pending"})
                if transaction:
                    await db.transactions.update_one(
                        {"_id": transaction["_id"]},
                        {
                            "$set": {
                                "status": "failed",
                                "completed_at": datetime.utcnow(),
                                "mpesa_receipt": None,
                                "error_message": result_desc
                            }
                        }
                    )
                    await create_notification({
                        "title": "Deposit Failed",
                        "message": f"Your deposit of KSH {transaction['amount']} failed. Reason: {result_desc}",
                        "user_id": transaction['user_id']
                    })

        return JSONResponse({"ResultCode": 0, "ResultDesc": "C2B/STK Push Callback Received Successfully"})

    except Exception as e:
        print(f"Error processing M-Pesa callback: {e}")
        return JSONResponse({"ResultCode": 1, "ResultDesc": "Error processing callback"}, status_code=500)


@app.post("/api/payments/withdraw")
async def request_withdrawal(withdrawal_data: WithdrawalRequest, current_user: dict = Depends(get_current_user)):
    if not current_user['is_activated']:
        raise HTTPException(status_code=400, detail="Account must be activated before withdrawal")
    
    if withdrawal_data.amount > current_user['wallet_balance']:
        raise HTTPException(status_code=400, detail="Insufficient balance")
    
    if withdrawal_data.amount < 100:
        raise HTTPException(status_code=400, detail="Minimum withdrawal amount is KSH 100")
    
    transaction_id = str(uuid.uuid4())
    
    # Create withdrawal request
    withdrawal_doc = {
        "transaction_id": transaction_id,
        "user_id": current_user['user_id'],
        "type": "withdrawal",
        "amount": withdrawal_data.amount,
        "phone": withdrawal_data.phone,
        "reason": withdrawal_data.reason,
        "status": "pending", # Status will be updated by admin or auto B2C
        "method": "mpesa",
        "created_at": datetime.utcnow(),
        "processed_at": None,
        "approved_by": None,
        "mpesa_conversation_id": None, # To store M-Pesa B2C ConversationID
        "mpesa_originator_conv_id": None # To store M-Pesa B2C OriginatorConversationID
    }
    
    await db.transactions.insert_one(withdrawal_doc)
    
    # Deduct from wallet (held in pending)
    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {"$inc": {"wallet_balance": -withdrawal_data.amount}}
    )
    
    return {
        "success": True,
        "message": f"Withdrawal request of KSH {withdrawal_data.amount} submitted. Processing will take 24-48 hours.",
        "transaction_id": transaction_id
    }

# Task system
@app.get("/api/tasks/available")
async def get_available_tasks(current_user: dict = Depends(get_current_user)):
    if not current_user['is_activated']:
        raise HTTPException(status_code=400, detail="Account must be activated to access tasks")
    
    # Get completed task IDs for this user
    completed_tasks = await db.task_completions.find(
        {"user_id": current_user['user_id']}
    ).distinct("task_id")
    
    # Get available tasks (not completed by user and active)
    tasks = await db.tasks.find(
        {"task_id": {"$nin": completed_tasks}, "is_active": True}
    ).to_list(20)
    
    return {
        "success": True,
        "tasks": json_serializable_doc(tasks) # Apply serialization
    }

@app.post("/api/tasks/complete")
async def complete_task(completion_data: TaskCompletion, current_user: dict = Depends(get_current_user)):
    if not current_user['is_activated']:
        raise HTTPException(status_code=400, detail="Account must be activated to complete tasks")
    
    # Check if task exists and is active
    task = await db.tasks.find_one({"task_id": completion_data.task_id, "is_active": True})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found or inactive")
    
    # Check if user already completed this task
    existing_completion = await db.task_completions.find_one({
        "user_id": current_user['user_id'],
        "task_id": completion_data.task_id
    })
    if existing_completion:
        raise HTTPException(status_code=400, detail="Task already completed")
    
    # Record task completion
    completion_doc = {
        "completion_id": str(uuid.uuid4()),
        "user_id": current_user['user_id'],
        "task_id": completion_data.task_id,
        "completion_data": completion_data.completion_data,
        "reward_amount": task['reward'],
        "status": "completed",
        "created_at": datetime.utcnow()
    }
    
    await db.task_completions.insert_one(completion_doc)
    
    # Update user wallet and earnings
    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {
            "$inc": {
                "wallet_balance": task['reward'],
                "task_earnings": task['reward'],
                "total_earned": task['reward']
            }
        }
    )
    
    # Create notification
    await create_notification({
        "title": "Task Completed!",
        "message": f"You earned KSH {task['reward']} for completing '{task['title']}'",
        "user_id": current_user['user_id']
    })
    
    return {
        "success": True,
        "message": f"Task completed! You earned KSH {task['reward']}",
        "reward": task['reward']
    }

# Referral system
@app.get("/api/referrals/stats")
async def get_referral_stats(current_user: dict = Depends(get_current_user)):
    referrals = await db.referrals.find({"referrer_id": current_user['user_id']}).to_list(100)
    
    stats = {
        "total_referrals": len(referrals),
        "pending_referrals": len([r for r in referrals if r['status'] == 'pending']),
        "activated_referrals": len([r for r in referrals if r['status'] in ['activated', 'rewarded']]),
        "total_earnings": sum(r.get('reward_amount', 0) for r in referrals if r['status'] == 'rewarded'),
        "referral_code": current_user['referral_code'],
        "referrals": json_serializable_doc(referrals) # Apply serialization
    }
    
    return {"success": True, "stats": stats}

# Helper function for referral rewards
async def process_referral_reward(referred_user_id: str, referrer_id: str):
    """Process referral reward when referred user activates account"""
    referral = await db.referrals.find_one({
        "referred_id": referred_user_id,
        "referrer_id": referrer_id,
        "status": "pending"
    })
    
    if referral:
        reward_amount = referral['reward_amount']
        
        # Update referral status
        await db.referrals.update_one(
            {"referral_id": referral['referral_id']},
            {
                "$set": {
                    "status": "rewarded",
                    "activation_date": datetime.utcnow()
                }
            }
        )
        
        # Update referrer's wallet
        await db.users.update_one(
            {"user_id": referrer_id},
            {
                "$inc": {
                    "wallet_balance": reward_amount,
                    "referral_earnings": reward_amount,
                    "total_earned": reward_amount,
                    "referral_count": 1
                }
            }
        )
        
        # Create notification for referrer
        await create_notification({
            "title": "Referral Bonus!",
            "message": f"You earned KSH {reward_amount} from a successful referral!",
            "user_id": referrer_id
        })

# Notification system
async def create_notification(notification_data: dict):
    """Create a notification"""
    notification_doc = {
        # Removed "notification_id" here to rely solely on MongoDB's _id
        "title": notification_data['title'],
        "message": notification_data['message'],
        "user_id": notification_data.get('user_id'),  # None for broadcast
        "is_read": False,
        "created_at": datetime.utcnow()
    }
    await db.notifications.insert_one(notification_doc)

@app.post("/api/notifications/create")
async def create_notification_endpoint(notification_data: NotificationCreate, current_user: dict = Depends(get_current_admin_user)): # Admin only
    """Admin endpoint to create notifications"""
    await create_notification(notification_data.dict())
    return {"success": True, "message": "Notification created"}

@app.get("/api/notifications")
async def get_notifications(current_user: dict = Depends(get_current_user)):
    notifications = await db.notifications.find(
        {"$or": [{"user_id": current_user['user_id']}, {"user_id": None}]}
    ).sort("created_at", -1).limit(20).to_list(20)
    
    return {"success": True, "notifications": json_serializable_doc(notifications)} # Apply serialization

@app.put("/api/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, current_user: dict = Depends(get_current_user)):
    # The frontend sends the 'id' which is the string representation of MongoDB's '_id'.
    # Convert it back to ObjectId for the database query.
    try:
        object_id_to_find = ObjectId(notification_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid notification ID format")

    notification = await db.notifications.find_one({"_id": object_id_to_find})
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    # Ensure the user has access to mark this notification as read
    # Either it's a broadcast (user_id is None) or it's for this specific user
    if notification.get('user_id') is not None and notification['user_id'] != current_user['user_id']:
        raise HTTPException(status_code=403, detail="Not authorized to mark this notification as read")

    await db.notifications.update_one(
        {"_id": object_id_to_find}, # Use the ObjectId directly for update
        {"$set": {"is_read": True}}
    )
    return {"success": True, "message": "Notification marked as read"}

# Settings
@app.put("/api/settings/theme")
async def update_theme(theme: str, current_user: dict = Depends(get_current_user)):
    if theme not in ['light', 'dark']:
        raise HTTPException(status_code=400, detail="Invalid theme")
    
    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {"$set": {"theme": theme}}
    )
    
    return {"success": True, "message": f"Theme updated to {theme}"}

# --- Admin Endpoints ---
@app.get("/api/admin/dashboard/stats", dependencies=[Depends(get_current_admin_user)])
async def get_admin_dashboard_stats():
    total_users = await db.users.count_documents({})
    activated_users = await db.users.count_documents({"is_activated": True})
    
    total_deposits_agg = await db.transactions.aggregate([
        {"$match": {"type": "deposit", "status": "completed"}},
        {"$group": {"_id": None, "total_amount": {"$sum": 1}}} # Changed to sum count of documents
    ]).to_list(1)
    total_deposits = total_deposits_agg[0]['total_amount'] if total_deposits_agg else 0.0

    total_withdrawals_agg = await db.transactions.aggregate([
        {"$match": {"type": "withdrawal", "status": "completed"}},
        {"$group": {"_id": None, "total_amount": {"$sum": 1}}} # Changed to sum count of documents
    ]).to_list(1)
    total_withdrawals = total_withdrawals_agg[0]['total_amount'] if total_withdrawals_agg else 0.0

    pending_withdrawals = await db.transactions.count_documents({"type": "withdrawal", "status": "pending"})
    
    return {
        "success": True,
        "stats": {
            "total_users": total_users,
            "activated_users": activated_users,
            "total_deposits": total_deposits,
            "total_withdrawals": total_withdrawals,
            "pending_withdrawals": pending_withdrawals
        }
    }

@app.get("/api/admin/users", dependencies=[Depends(get_current_admin_user)])
async def get_all_users():
    users = await db.users.find({}, {"password": 0}).to_list(1000) # Exclude password
    return {"success": True, "users": json_serializable_doc(users)} # Apply serialization

@app.get("/api/admin/transactions/deposits", dependencies=[Depends(get_current_admin_user)])
async def get_all_deposits(status: Optional[str] = None):
    query = {"type": "deposit"}
    if status:
        query["status"] = status
    deposits = await db.transactions.find(query).sort("created_at", -1).to_list(1000)
    return {"success": True, "deposits": json_serializable_doc(deposits)} # Apply serialization

@app.get("/api/admin/transactions/withdrawals", dependencies=[Depends(get_current_admin_user)])
async def get_all_withdrawals(status: Optional[str] = None):
    query = {"type": "withdrawal"}
    if status:
        query["status"] = status
    withdrawals = await db.transactions.find(query).sort("created_at", -1).to_list(1000)
    return {"success": True, "withdrawals": json_serializable_doc(withdrawals)} # Apply serialization

@app.put("/api/admin/transactions/withdrawals/{transaction_id}/status", dependencies=[Depends(get_current_admin_user)])
async def update_withdrawal_status(transaction_id: str, update_data: UpdateWithdrawalStatus):
    withdrawal = await db.transactions.find_one({"transaction_id": transaction_id, "type": "withdrawal"})
    if not withdrawal:
        raise HTTPException(status_code=404, detail="Withdrawal request not found")
    
    if withdrawal['status'] != 'pending' and update_data.status == 'approved':
        raise HTTPException(status_code=400, detail="Withdrawal already processed.")

    # Only allow 'approved' or 'rejected' from admin UI initially.
    # 'completed'/'failed' will be set by M-Pesa B2C callback or direct admin action if B2C fails.
    if update_data.status not in ["approved", "rejected", "completed", "failed"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be 'approved', 'rejected', 'completed', or 'failed'.")

    update_fields = {"status": update_data.status, "processed_at": datetime.utcnow()}
    if update_data.reason:
        update_fields["admin_reason"] = update_data.reason
    
    await db.transactions.update_one(
        {"_id": withdrawal["_id"]}, # Use internal _id for update
        {"$set": update_fields}
    )

    user = await db.users.find_one({"user_id": withdrawal['user_id']})
    if not user:
        print(f"User {withdrawal['user_id']} not found for withdrawal {transaction_id}")
        return {"success": True, "message": f"Withdrawal {transaction_id} status updated to {update_data.status}"}

    if update_data.status == 'approved':
        # Initiate M-Pesa B2C payment
        access_token = await get_mpesa_access_token()
        
        b2c_payload = {
            "InitiatorName": MPESA_INITIATOR_NAME,
            "SecurityCredential": MPESA_SECURITY_CREDENTIAL, # This must be encrypted
            "CommandID": "BusinessPayment", # Or "SalaryPayment", "PromotionPayment"
            "Amount": int(withdrawal['amount']),
            "PartyA": MPESA_B2C_SHORTCODE,
            "PartyB": withdrawal['phone'],
            "Remarks": withdrawal['reason'] or "Withdrawal from EarnPlatform",
            "QueueTimeOutURL": "YOUR_MPESA_B2C_TIMEOUT_URL_HERE", # IMPORTANT: Replace with your actual timeout URL
            "ResultURL": "YOUR_MPESA_B2C_RESULT_URL_HERE", # IMPORTANT: Replace with your actual result URL
            "Occasion": "User Withdrawal"
        }

        try:
            async with httpx.AsyncClient() as client:
                mpesa_b2c_response = await client.post(
                    MPESA_B2C_URL,
                    json=b2c_payload,
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json"
                    },
                    timeout=30.0
                )
                mpesa_b2c_response.raise_for_status()
                b2c_data = mpesa_b2c_response.json()

                if b2c_data.get("ResponseCode") == "0":
                    await db.transactions.update_one(
                        {"_id": withdrawal["_id"]}, # Use internal _id for update
                        {
                            "$set": {
                                "mpesa_conversation_id": b2c_data.get("ConversationID"),
                                "mpesa_originator_conv_id": b2c_data.get("OriginatorConversationID"),
                                "status": "processing" # New status for B2C in progress
                            }
                        }
                    )
                    await create_notification({
                        "title": "Withdrawal Approved!",
                        "message": f"Your withdrawal of KSH {withdrawal['amount']} has been approved and is being processed by M-Pesa.",
                        "user_id": user['user_id']
                    })
                    return {"success": True, "message": f"Withdrawal {transaction_id} approved and M-Pesa B2C initiated."}
                else:
                    # B2C initiation failed, revert user balance and set status to failed
                    await db.users.update_one(
                        {"user_id": user['user_id']},
                        {"$inc": {"wallet_balance": withdrawal['amount']}} # Revert amount
                    )
                    await db.transactions.update_one(
                        {"_id": withdrawal["_id"]}, # Use internal _id for update
                        {"$set": {"status": "failed", "admin_reason": f"M-Pesa B2C initiation failed: {b2c_data.get('errorMessage', 'Unknown M-Pesa error')}"}}
                    )
                    await create_notification({
                        "title": "Withdrawal Failed",
                        "message": f"Your withdrawal of KSH {withdrawal['amount']} failed due to an M-Pesa error. Funds reverted to wallet. Please try again later.",
                        "user_id": user['user_id']
                    })
                    raise HTTPException(status_code=400, detail=f"M-Pesa B2C initiation failed: {b2c_data.get('errorMessage', 'Unknown M-Pesa error')}")
        except httpx.HTTPStatusError as e:
            print(f"M-Pesa B2C HTTP error: {e.response.status_code} - {e.response.text}")
            await db.users.update_one(
                {"user_id": user['user_id']},
                {"$inc": {"wallet_balance": withdrawal['amount']}} # Revert amount
            )
            await db.transactions.update_one(
                {"_id": withdrawal["_id"]}, # Use internal _id for update
                {"$set": {"status": "failed", "admin_reason": f"M-Pesa B2C HTTP error: {e.response.text}"}}
            )
            await create_notification({
                "title": "Withdrawal Failed",
                "message": f"Your withdrawal of KSH {withdrawal['amount']} failed due to a network error. Funds reverted to wallet. Please try again later.",
                "user_id": user['user_id']
            })
            raise HTTPException(status_code=500, detail=f"M-Pesa B2C failed: {e.response.text}")
        except Exception as e:
            print(f"Error initiating M-Pesa B2C: {e}")
            await db.users.update_one(
                {"user_id": user['user_id']},
                {"$inc": {"wallet_balance": withdrawal['amount']}} # Revert amount
            )
            await db.transactions.update_one(
                {"_id": withdrawal["_id"]}, # Use internal _id for update
                {"$set": {"status": "failed", "admin_reason": f"Internal error during B2C initiation: {e}"}}
            )
            await create_notification({
                "title": "Withdrawal Failed",
                "message": f"Your withdrawal of KSH {withdrawal['amount']} failed due to an internal error. Funds reverted to wallet. Please try again later.",
                "user_id": user['user_id']
            })
            raise HTTPException(status_code=500, detail="Error initiating M-Pesa withdrawal. Please try again.")

    elif update_data.status == 'rejected':
        # Revert the amount to the user's wallet
        await db.users.update_one(
            {"user_id": user['user_id']},
            {"$inc": {"wallet_balance": withdrawal['amount']}}
        )
        await create_notification({
            "title": "Withdrawal Rejected",
            "message": f"Your withdrawal request of KSH {withdrawal['amount']} was rejected. Reason: {update_data.reason or 'No reason provided.'}",
            "user_id": user['user_id']
        })
    elif update_data.status == 'completed':
        # This status should ideally be set by the M-Pesa B2C callback
        # But included for manual override if needed.
        await db.users.update_one(
            {"user_id": user['user_id']},
            {"$inc": {"total_withdrawn": withdrawal['amount']}}
        )
        await create_notification({
            "title": "Withdrawal Completed!",
            "message": f"Your withdrawal of KSH {withdrawal['amount']} has been successfully completed.",
            "user_id": user['user_id']
        })
    elif update_data.status == 'failed':
        # This status should ideally be set by the M-Pesa B2C callback
        # If manually set to failed, revert the amount.
        if withdrawal['status'] != 'pending': # Only revert if it was already deducted
             await db.users.update_one(
                {"user_id": user['user_id']},
                {"$inc": {"wallet_balance": withdrawal['amount']}}
            )
        await create_notification({
            "title": "Withdrawal Failed",
            "message": f"Your withdrawal of KSH {withdrawal['amount']} failed. Reason: {update_data.reason or 'No reason provided.'}",
            "user_id": user['user_id']
        })

    return {"success": True, "message": f"Withdrawal {transaction_id} status updated to {update_data.status}"}

# NOTE: M-Pesa B2C Result and Timeout Callbacks
# These endpoints are essential for M-Pesa B2C to report transaction status.
@app.post("/api/payments/mpesa-b2c-result")
async def mpesa_b2c_result_callback(request: Request):
    """M-Pesa B2C Result Callback URL."""
    try:
        data = await request.json()
        print(f"M-Pesa B2C Result Callback Received: {json.dumps(data, indent=2)}")

        # Extract relevant information
        result = data.get("Result", {})
        originator_conversation_id = result.get("OriginatorConversationID")
        result_code = result.get("ResultCode")
        result_desc = result.get("ResultDesc")
        
        # Find the corresponding withdrawal transaction
        withdrawal_transaction = await db.transactions.find_one({"mpesa_originator_conv_id": originator_conversation_id})

        if withdrawal_transaction:
            user_id = withdrawal_transaction['user_id']
            user = await db.users.find_one({"user_id": user_id})

            if result_code == 0:
                # B2C transaction successful
                await db.transactions.update_one(
                    {"_id": withdrawal_transaction["_id"]},
                    {"$set": {"status": "completed", "completed_at": datetime.utcnow()}}
                )
                if user:
                    await db.users.update_one(
                        {"user_id": user_id},
                        {"$inc": {"total_withdrawn": withdrawal_transaction['amount']}}
                    )
                    await create_notification({
                        "title": "Withdrawal Completed!",
                        "message": f"Your withdrawal of KSH {withdrawal_transaction['amount']} has been successfully completed.",
                        "user_id": user_id
                    })
            else:
                # B2C transaction failed
                await db.transactions.update_one(
                    {"_id": withdrawal_transaction["_id"]},
                    {"$set": {"status": "failed", "completed_at": datetime.utcnow(), "error_message": result_desc}}
                )
                # Revert funds to user's wallet if they were deducted and not yet reverted
                if withdrawal_transaction['status'] != 'rejected' and withdrawal_transaction['status'] != 'failed':
                    if user:
                        await db.users.update_one(
                            {"user_id": user_id},
                            {"$inc": {"wallet_balance": withdrawal_transaction['amount']}}
                        )
                await create_notification({
                    "title": "Withdrawal Failed",
                    "message": f"Your withdrawal of KSH {withdrawal_transaction['amount']} failed. Reason: {result_desc}. Funds have been returned to your wallet.",
                    "user_id": user_id
                })
        else:
            print(f"B2C Result: No matching withdrawal transaction found for OriginatorConversationID: {originator_conversation_id}")

        return JSONResponse({"ResultCode": 0, "ResultDesc": "B2C Result Callback Received Successfully"})
    except Exception as e:
        print(f"Error processing M-Pesa B2C Result callback: {e}")
        return JSONResponse({"ResultCode": 1, "ResultDesc": "Error processing callback"}, status_code=500)

@app.post("/api/payments/mpesa-b2c-timeout")
async def mpesa_b2c_timeout_callback(request: Request):
    """M-Pesa B2C Timeout Callback URL."""
    try:
        data = await request.json()
        print(f"M-Pesa B2C Timeout Callback Received: {json.dumps(data, indent=2)}")

        # Extract relevant information
        conversation_id = data.get("ConversationID")
        originator_conversation_id = data.get("OriginatorConversationID")
        
        # Find the corresponding withdrawal transaction
        withdrawal_transaction = await db.transactions.find_one({"mpesa_originator_conv_id": originator_conversation_id})

        if withdrawal_transaction:
            user_id = withdrawal_transaction['user_id']
            user = await db.users.find_one({"user_id": user_id})

            await db.transactions.update_one(
                {"_id": withdrawal_transaction["_id"]},
                {"$set": {"status": "timed_out", "completed_at": datetime.utcnow(), "error_message": "M-Pesa B2C request timed out."}}
            )
            # Revert funds to user's wallet if they were deducted and not yet reverted
            if withdrawal_transaction['status'] != 'rejected' and withdrawal_transaction['status'] != 'failed':
                if user:
                    await db.users.update_one(
                        {"user_id": user_id},
                        {"$inc": {"wallet_balance": withdrawal_transaction['amount']}}
                    )
            await create_notification({
                "title": "Withdrawal Timed Out",
                "message": f"Your withdrawal of KSH {withdrawal_transaction['amount']} timed out. Funds have been returned to your wallet.",
                "user_id": user_id
            })
        else:
            print(f"B2C Timeout: No matching withdrawal transaction found for OriginatorConversationID: {originator_conversation_id}")

        return JSONResponse({"ResultCode": 0, "ResultDesc": "B2C Timeout Callback Received Successfully"})
    except Exception as e:
        print(f"Error processing M-Pesa B2C Timeout callback: {e}")
        return JSONResponse({"ResultCode": 1, "ResultDesc": "Error processing callback"}, status_code=500)


@app.post("/api/admin/tasks", dependencies=[Depends(get_current_admin_user)])
async def create_task(task_data: Task):
    task_id = str(uuid.uuid4())
    task_doc = {
        "task_id": task_id,
        "title": task_data.title,
        "description": task_data.description,
        "reward": task_data.reward,
        "type": task_data.type,
        "requirements": task_data.requirements,
        "is_active": task_data.is_active,
        "created_at": datetime.utcnow()
    }
    await db.tasks.insert_one(task_doc)
    return {"success": True, "message": "Task created successfully", "task": json_serializable_doc(task_doc)} # Apply serialization

@app.get("/api/admin/tasks", dependencies=[Depends(get_current_admin_user)])
async def get_all_tasks(status: Optional[bool] = None):
    query = {}
    if status is not None:
        query["is_active"] = status
    tasks = await db.tasks.find(query).sort("created_at", -1).to_list(100)
    return {"success": True, "tasks": json_serializable_doc(tasks)} # Apply serialization

@app.put("/api/admin/tasks/{task_id}/status", dependencies=[Depends(get_current_admin_user)])
async def update_task_status(task_id: str, update_data: UpdateTaskStatus):
    task = await db.tasks.find_one({"task_id": task_id})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    
    await db.tasks.update_one(
        {"_id": task["_id"]}, # Use internal _id for update
        {"$set": {"is_active": update_data.is_active}}
    )
    return {"success": True, "message": f"Task status updated to active: {update_data.is_active}"}


# Initialize default tasks
@app.on_event("startup")
async def startup_event():
    """Initialize default tasks and data"""
    # Check if tasks already exist
    task_count = await db.tasks.count_documents({})
    if task_count == 0:
        default_tasks = [
            {
                "task_id": str(uuid.uuid4()),
                "title": "Complete Daily Survey",
                "description": "Answer 10 questions about consumer preferences",
                "reward": 25.0,
                "type": "survey",
                "requirements": {"questions": 10, "time_limit": 300},
                "is_active": True,
                "created_at": datetime.utcnow()
            },
            {
                "task_id": str(uuid.uuid4()),
                "title": "Watch Advertisement",
                "description": "Watch a 30-second advertisement completely",
                "reward": 5.0,
                "type": "ad",
                "requirements": {"duration": 30, "interaction": True},
                "is_active": True,
                "created_at": datetime.utcnow()
            },
            {
                "task_id": str(uuid.uuid4()),
                "title": "Write Product Review",
                "description": "Write a 100-word review of a product",
                "reward": 50.0,
                "type": "writing",
                "requirements": {"min_words": 100, "topic": "product_review"},
                "is_active": True,
                "created_at": datetime.utcnow()
            },
            {
                "task_id": str(uuid.uuid4()),
                "title": "Share on Social Media",
                "description": "Share our platform on your social media",
                "reward": 15.0,
                "type": "social",
                "requirements": {"platforms": ["facebook", "twitter", "whatsapp"]},
                "is_active": True,
                "created_at": datetime.utcnow()
            }
        ]
        
        await db.tasks.insert_many(default_tasks)
        print("Default tasks initialized")
    
    # Ensure at least one admin user exists for testing purposes
    admin_user_count = await db.users.count_documents({"role": "admin"})
    if admin_user_count == 0:
        print("No admin user found. Creating a default admin user...")
        admin_email = os.environ.get('DEFAULT_ADMIN_EMAIL', 'admin@example.com')
        admin_password = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'adminpassword')
        
        await db.users.insert_one({
            "user_id": str(uuid.uuid4()),
            "email": admin_email,
            "password": hash_password(admin_password),
            "full_name": "Admin User",
            "phone": "254700000000",
            "referral_code": generate_referral_code(),
            "referred_by": None,
            "wallet_balance": 0.0,
            "is_activated": True, # Admin accounts are activated by default
            "activation_amount": 500.0,
            "total_earned": 0.0,
            "total_withdrawn": 0.0,
            "referral_earnings": 0.0,
            "task_earnings": 0.0,
            "referral_count": 0,
            "created_at": datetime.utcnow(),
            "last_login": datetime.utcnow(),
            "notifications_enabled": True,
            "theme": "light",
            "role": "admin"
        })
        print(f"Default admin user created: {admin_email}/{admin_password}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
