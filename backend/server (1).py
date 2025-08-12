from fastapi import FastAPI, HTTPException, Depends, Request, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr
from typing import Optional, List, Dict, Any
# Add these imports at the top with your other imports
import paypalrestsdk  # For PayPal SDK configuration
from email_validator import validate_email, EmailNotValidError  # For email validation in PayPal withdrawals
from decimal import Decimal  # For precise monetary calculations
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
    # Create user with enhanced validation and payment integration
user_doc = {
    "user_id": user_id,
    "email": user_data.email.lower().strip(),  # Normalize email
    "password": hash_password(user_data.password),
    "full_name": user_data.full_name.strip(),
    "phone": validate_and_format_phone(user_data.phone),  # Custom phone validation
    "referral_code": referral_code,
    "referred_by": referred_by,
    "wallet_balance": Decimal('0.00'),  # Using Decimal for precise money handling
    "is_activated": False,
    "activation_amount": Decimal('500.00'),  # KSH 500 activation fee
    "total_earned": Decimal('0.00'),
    "total_withdrawn": Decimal('0.00'),
    "referral_earnings": Decimal('0.00'),
    "task_earnings": Decimal('0.00'),
    "referral_count": 0,
    "payment_methods": {  # Track connected payment methods
        "mpesa": {
            "phone": None,
            "verified": False
        },
        "paypal": {
            "email": None,
            "verified": False
        }
    },
    "security": {
        "two_factor_enabled": False,
        "last_password_change": datetime.utcnow()
    },
    "created_at": datetime.utcnow(),
    "updated_at": datetime.utcnow(),
    "last_login": datetime.utcnow(),
    "notifications_enabled": True,
    "communication_preferences": {
        "email": True,
        "sms": True,
        "push": True
    },
    "theme": "light",
    "role": user_data.role.lower() if user_data.role else "user",  # Normalize role
    "status": "active",  # active, suspended, deleted
    "verification": {
        "email_verified": False,
        "phone_verified": False,
        "identity_verified": False
    }
}

# Validate phone number format
def validate_and_format_phone(phone: str) -> str:
    """Convert phone to international format (254...) and validate"""
    phone = phone.strip().replace(" ", "").replace("-", "").replace("+", "")
    
    if phone.startswith("0") and len(phone) == 10:
        return "254" + phone[1:]
    elif phone.startswith("254") and len(phone) == 12:
        return phone
    else:
        raise HTTPException(
            status_code=400,
            detail="Invalid phone number format. Use 07... or 2547..."
        )

# Start a MongoDB session for atomic operations
async with await client.start_session() as session:
    try:
        async with session.start_transaction():
            # Insert user document
            await db.users.insert_one(user_doc, session=session)
            
            # Create referral tracking if referred
            if referred_by:
                referral_doc = {
                    "referral_id": str(uuid.uuid4()),
                    "referrer_id": referred_by,
                    "referred_id": user_id,
                    "status": "pending",
                    "created_at": datetime.utcnow(),
                    "activation_date": None,
                    "reward_amount": Decimal('50.00'),
                    "currency": "KES"
                }
                await db.referrals.insert_one(referral_doc, session=session)
                
                # Increment referrer's referral count
                await db.users.update_one(
                    {"user_id": referred_by},
                    {"$inc": {"referral_count": 1}},
                    session=session
                )
            
            # Create initial wallet transaction record
            transaction_doc = {
                "transaction_id": str(uuid.uuid4()),
                "user_id": user_id,
                "type": "account_creation",
                "amount": Decimal('0.00'),
                "currency": "KES",
                "status": "completed",
                "description": "Initial account creation",
                "created_at": datetime.utcnow(),
                "completed_at": datetime.utcnow()
            }
            await db.transactions.insert_one(transaction_doc, session=session)
            
            # Send verification email/sms
            await send_verification_email(user_doc["email"], user_id)
            await send_verification_sms(user_doc["phone"])
            
    except Exception as e:
        await session.abort_transaction()
        raise HTTPException(
            status_code=500,
            detail=f"Registration failed: {str(e)}"
        )

# Generate JWT token
token = create_jwt_token(
    user_id=user_id,
    email=user_data.email,
    role=user_doc["role"],
    is_activated=user_doc["is_activated"]
)

# Return response with sanitized user data
return {
    "success": True,
    "message": "Registration successful! Please deposit KSH 500 to activate your account.",
    "token": token,
    "user": {
        "user_id": user_id,
        "email": user_data.email,
        "full_name": user_data.full_name,
        "referral_code": referral_code,
        "is_activated": False,
        "wallet_balance": "0.00",
        "currency": "KES",
        "role": user_doc["role"],
        "has_payment_methods": False,
        "verification_status": {
            "email": False,
            "phone": False
        }
    },
    "next_steps": [
        "verify_email",
        "verify_phone",
        "add_payment_method",
        "make_activation_deposit"
    ]
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
    """
    Enhanced Dashboard Statistics with:
    - Parallel data fetching
    - Comprehensive analytics
    - Activity timeline
    - Performance optimizations
    - Tiered referral rewards
    """
    user_id = current_user['user_id']
    
    try:
        # Fetch all data in parallel for better performance
        transactions_task = db.transactions.find(
            {"user_id": user_id}
        ).sort("created_at", -1).limit(10).to_list(None)
        
        referrals_task = db.referrals.aggregate([
            {"$match": {"referrer_id": user_id}},
            {"$group": {
                "_id": "$status",
                "count": {"$sum": 1},
                "total_reward": {"$sum": "$reward_amount"},
                "potential_reward": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$status", "pending"]},
                            "$reward_amount",
                            0
                        ]
                    }
                }
            }},
            {"$group": {
                "_id": None,
                "stats": {"$push": "$$ROOT"},
                "total_referrals": {"$sum": "$count"},
                "total_earned": {"$sum": "$total_reward"},
                "potential_earnings": {"$sum": "$potential_reward"}
            }}
        ]).to_list(None)
        
        notifications_task = db.notifications.find(
            {"$or": [
                {"user_id": user_id},
                {"user_id": None, "type": "broadcast"}
            ]}
        ).sort("created_at", -1).limit(10).to_list(None)
        
        tasks_task = db.task_completions.aggregate([
            {"$match": {"user_id": user_id}},
            {"$group": {
                "_id": "$status",
                "count": {"$sum": 1},
                "total_earnings": {"$sum": "$reward"}
            }}
        ]).to_list(None)
        
        # Execute all queries concurrently
        transactions, referrals, notifications, tasks = await asyncio.gather(
            transactions_task,
            referrals_task,
            notifications_task,
            tasks_task
        )
        
        # Calculate weekly earnings
        weekly_earnings = await db.transactions.aggregate([
            {"$match": {
                "user_id": user_id,
                "type": {"$in": ["task", "referral"]},
                "status": "completed",
                "created_at": {
                    "$gte": datetime.utcnow() - timedelta(days=7)
                }
            }},
            {"$group": {
                "_id": None,
                "total": {"$sum": "$amount"}
            }}
        ]).to_list(None)
        
        # Determine referral tier
        referral_count = referrals[0]['total_referrals'] if referrals else 0
        tier = "gold" if referral_count >= 50 else \
               "silver" if referral_count >= 20 else "bronze"
        
        # Prepare response
        response = {
            "success": True,
            "user": {
                "full_name": current_user['full_name'],
                "wallet_balance": float(current_user['wallet_balance']),
                "is_activated": current_user['is_activated'],
                "activation_amount": float(current_user.get('activation_amount', 500.0)),
                "total_earned": float(current_user.get('total_earned', 0.0)),
                "total_withdrawn": float(current_user.get('total_withdrawn', 0.0)),
                "referral_earnings": float(current_user.get('referral_earnings', 0.0)),
                "task_earnings": float(current_user.get('task_earnings', 0.0)),
                "referral_count": current_user.get('referral_count', 0),
                "referral_code": current_user['referral_code'],
                "referral_tier": tier,
                "role": current_user.get('role', 'user')
            },
            "analytics": {
                "weekly_earnings": float(weekly_earnings[0]['total']) if weekly_earnings else 0,
                "referrals": referrals[0] if referrals else {
                    "stats": [],
                    "total_referrals": 0,
                    "total_earned": 0,
                    "potential_earnings": 0
                },
                "tasks": {
                    "completed": next(
                        (t['count'] for t in tasks if t['_id'] == "completed"), 0),
                    "pending": next(
                        (t['count'] for t in tasks if t['_id'] == "pending"), 0),
                    "total_earnings": next(
                        (t['total_earnings'] for t in tasks if t['_id'] == "completed"), 0)
                }
            },
            "activity": {
                "transactions": json_serializable_doc(transactions),
                "notifications": json_serializable_doc(notifications)
            },
            "quick_actions": await generate_quick_actions(current_user)
        }
        
        return response
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load dashboard: {str(e)}"
        )

async def generate_quick_actions(user: dict) -> list:
    """Generate context-aware quick actions"""
    actions = []
    
    if not user['is_activated']:
        actions.append({
            "title": "Activate Account",
            "description": f"Deposit KSH {user.get('activation_amount', 500)} to activate",
            "action": "deposit",
            "priority": "high"
        })
    
    if user.get('referral_count', 0) < 5:
        actions.append({
            "title": "Earn More",
            "description": "Invite friends to earn bonuses",
            "action": "invite",
            "priority": "medium"
        })
    
    if user['wallet_balance'] >= 200:
        actions.append({
            "title": "Withdraw Earnings",
            "description": "Cash out your balance",
            "action": "withdraw",
            "priority": "medium"
        })
    
    # Add default actions
    actions.extend([
        {
            "title": "Complete Tasks",
            "description": "Earn money by completing tasks",
            "action": "tasks",
            "priority": "low"
        },
        {
            "title": "View Tutorial",
            "description": "Learn how to maximize earnings",
            "action": "tutorial",
            "priority": "low"
        }
    ])
    
    return actions

# Payment routes

@app.post("/api/payments/deposit")
async def initiate_deposit(
    deposit_data: DepositRequest, 
    current_user: dict = Depends(get_current_user),
    request: Request = None  # For IP tracking
):
    """
    Enhanced M-Pesa Deposit Endpoint with:
    - Phone number validation
    - Amount validation
    - Rate limiting
    - IP tracking
    - Atomic transactions
    - Comprehensive error handling
    """
    # 1. Input Validation
    try:
        # Validate phone number format (254XXXXXXXXX)
        if not re.match(r'^254\d{9}$', deposit_data.phone):
            raise HTTPException(
                status_code=400,
                detail="Invalid phone format. Use 254 followed by 9 digits (e.g., 254712345678)"
            )

        # Validate amount (minimum 10 KES, maximum 150,000 KES)
        if not (10 <= deposit_data.amount <= 150000):
            raise HTTPException(
                status_code=400,
                detail="Amount must be between KSH 10 and KSH 150,000"
            )

        # 2. Check for duplicate pending transactions
        existing_txn = await db.transactions.find_one({
            "user_id": current_user['user_id'],
            "phone": deposit_data.phone,
            "amount": deposit_data.amount,
            "status": "pending",
            "created_at": {"$gt": datetime.utcnow() - timedelta(minutes=15)}
        })

        if existing_txn:
            raise HTTPException(
                status_code=400,
                detail="Duplicate transaction detected. Please wait for previous request to complete."
            )

        # 3. Rate limiting check
        txn_count = await db.transactions.count_documents({
            "user_id": current_user['user_id'],
            "created_at": {"$gt": datetime.utcnow() - timedelta(hours=1)}
        })

        if txn_count >= 5:  # Max 5 transactions per hour
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please try again later."
            )

        # 4. Prepare M-Pesa request
        transaction_id = str(uuid.uuid4())
        access_token = await get_mpesa_access_token()
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        password = await generate_mpesa_password(timestamp)

        stk_payload = {
            "BusinessShortCode": MPESA_LIPA_NA_MPESA_SHORTCODE,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(deposit_data.amount),
            "PartyA": deposit_data.phone,
            "PartyB": MPESA_LIPA_NA_MPESA_SHORTCODE,
            "PhoneNumber": deposit_data.phone,
            "CallBackURL": f"{settings.BASE_URL}/api/payments/mpesa-callback",
            "AccountReference": f"USER-{current_user['user_id']}",
            "TransactionDesc": f"Deposit for {current_user['email']}"
        }

        # 5. Create transaction record first (prevents callback issues)
        transaction_doc = {
            "transaction_id": transaction_id,
            "user_id": current_user['user_id'],
            "type": "deposit",
            "amount": float(deposit_data.amount),
            "currency": "KES",
            "phone": deposit_data.phone,
            "status": "pending",
            "method": "mpesa",
            "ip_address": request.client.host if request else None,
            "device_fingerprint": request.headers.get("User-Agent", ""),
            "metadata": {
                "mpesa": {
                    "checkout_request_id": None,
                    "receipt_number": None,
                    "request_payload": stk_payload
                }
            },
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        # 6. Atomic operation
        async with await client.start_session() as session:
            try:
                async with session.start_transaction():
                    # Insert transaction first
                    await db.transactions.insert_one(
                        transaction_doc,
                        session=session
                    )

                    # Make M-Pesa API call
                    async with httpx.AsyncClient(timeout=30.0) as client:
                        headers = {
                            "Authorization": f"Bearer {access_token}",
                            "Content-Type": "application/json"
                        }
                        
                        response = await client.post(
                            MPESA_STKPUSH_URL,
                            json=stk_payload,
                            headers=headers
                        )
                        response.raise_for_status()
                        mpesa_data = response.json()

                        if mpesa_data.get("ResponseCode") != "0":
                            raise HTTPException(
                                status_code=400,
                                detail=mpesa_data.get("CustomerMessage", "M-Pesa request failed")
                            )

                        # Update transaction with checkout ID
                        await db.transactions.update_one(
                            {"transaction_id": transaction_id},
                            {
                                "$set": {
                                    "metadata.mpesa.checkout_request_id": mpesa_data.get("CheckoutRequestID"),
                                    "metadata.mpesa.raw_response": mpesa_data
                                }
                            },
                            session=session
                        )

                    await session.commit_transaction()

                    # 7. Return success response
                    return {
                        "success": True,
                        "message": f"Payment request of KSH {deposit_data.amount} sent to {deposit_data.phone}",
                        "transaction_id": transaction_id,
                        "checkout_request_id": mpesa_data.get("CheckoutRequestID"),
                        "user_message": mpesa_data.get("CustomerMessage")
                    }

            except httpx.HTTPStatusError as e:
                await session.abort_transaction()
                error_detail = f"M-Pesa API Error: {e.response.status_code} - {e.response.text}"
                logging.error(error_detail)
                raise HTTPException(
                    status_code=502,
                    detail="Payment service temporarily unavailable"
                )

            except Exception as e:
                await session.abort_transaction()
                logging.error(f"Deposit processing error: {str(e)}")
                raise HTTPException(
                    status_code=500,
                    detail="Failed to process payment request"
                )

    except HTTPException:
        raise  # Re-raise our custom exceptions

    except Exception as e:
        logging.critical(f"Unexpected error in deposit: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred"
        )

# NOTE: This endpoint is crucial for real M-Pesa integration.
# M-Pesa will send a callback to this URL to confirm payment status.

@app.post("/api/payments/mpesa-callback")
async def mpesa_callback(request: Request):
    """
    Enhanced M-Pesa Callback Handler with:
    - IP Whitelisting
    - Request Validation
    - Atomic Transactions
    - Fraud Checks
    - Comprehensive Logging
    """
    try:
        # 1. Verify the request is from Safaricom IPs
        client_ip = request.client.host
        safaricom_ips = ["196.201.214.200", "196.201.214.206"]  # Add all Safaricom IPs
        if client_ip not in safaricom_ips:
            print(f"⚠️ Unauthorized IP access attempt: {client_ip}")
            return JSONResponse(
                {"ResultCode": 1, "ResultDesc": "Unauthorized"},
                status_code=403
            )

        # 2. Parse and validate request
        data = await request.json()
        logging.info(f"MPesa Callback Received: {json.dumps(data)}")

        if not data.get("Body", {}).get("stkCallback"):
            return JSONResponse(
                {"ResultCode": 1, "ResultDesc": "Invalid callback format"},
                status_code=400
            )

        callback = data["Body"]["stkCallback"]
        required_fields = ["CheckoutRequestID", "ResultCode", "CallbackMetadata"]
        if not all(field in callback for field in required_fields):
            return JSONResponse(
                {"ResultCode": 1, "ResultDesc": "Missing required fields"},
                status_code=400
            )

        # 3. Process callback
        checkout_id = callback["CheckoutRequestID"]
        result_code = int(callback["ResultCode"])
        result_desc = callback["ResultDesc"]

        async with await client.start_session() as session:
            try:
                async with session.start_transaction():
                    # 4. Find transaction
                    transaction = await db.transactions.find_one(
                        {
                            "metadata.mpesa.checkout_request_id": checkout_id,
                            "status": "pending"
                        },
                        session=session
                    )

                    if not transaction:
                        logging.warning(f"Transaction not found: {checkout_id}")
                        return JSONResponse(
                            {"ResultCode": 0, "ResultDesc": "Transaction not found"}
                        )

                    # 5. Handle success/failure
                    if result_code == 0:  # Success
                        metadata = {item["Name"]: item["Value"] for item in callback["CallbackMetadata"]["Item"]}
                        
                        # Update transaction
                        update_result = await db.transactions.update_one(
                            {"_id": transaction["_id"]},
                            {
                                "$set": {
                                    "status": "completed",
                                    "completed_at": datetime.utcnow(),
                                    "metadata.mpesa.receipt_number": metadata.get("MpesaReceiptNumber"),
                                    "amount": float(metadata.get("Amount", transaction["amount"])),
                                    "metadata.mpesa.phone_number": metadata.get("PhoneNumber")
                                }
                            },
                            session=session
                        )

                        # Update user balance
                        amount = float(metadata.get("Amount", transaction["amount"]))
                        user_update = await db.users.update_one(
                            {"user_id": transaction["user_id"]},
                            {
                                "$inc": {"wallet_balance": amount},
                                "$set": {
                                    "payment_methods.mpesa.phone": metadata.get("PhoneNumber"),
                                    "payment_methods.mpesa.verified": True
                                }
                            },
                            session=session
                        )

                        # Check activation and process referrals
                        user = await db.users.find_one(
                            {"user_id": transaction["user_id"]},
                            session=session
                        )
                        
                        if not user["is_activated"] and user["wallet_balance"] + amount >= user["activation_amount"]:
                            await db.users.update_one(
                                {"user_id": user["user_id"]},
                                {"$set": {"is_activated": True}},
                                session=session
                            )
                            
                            if user.get("referred_by"):
                                await process_referral_reward(
                                    referred_id=user["user_id"],
                                    referrer_id=user["referred_by"],
                                    session=session
                                )

                        # Create notification
                        await create_notification(
                            {
                                "title": "Deposit Received",
                                "message": f"KES {amount:,.2f} deposited to your account",
                                "user_id": transaction["user_id"],
                                "type": "payment"
                            },
                            session=session
                        )

                        logging.info(f"✅ Successful deposit: {transaction['user_id']} - KES {amount}")

                    else:  # Failure
                        await db.transactions.update_one(
                            {"_id": transaction["_id"]},
                            {
                                "$set": {
                                    "status": "failed",
                                    "completed_at": datetime.utcnow(),
                                    "metadata.error": result_desc
                                }
                            },
                            session=session
                        )

                        await create_notification(
                            {
                                "title": "Deposit Failed",
                                "message": f"Deposit failed: {result_desc}",
                                "user_id": transaction["user_id"],
                                "type": "payment"
                            },
                            session=session
                        )

                        logging.warning(f"❌ Failed deposit: {transaction['user_id']} - {result_desc}")

                    await session.commit_transaction()

            except Exception as e:
                await session.abort_transaction()
                logging.error(f"Transaction failed: {str(e)}")
                raise

        return JSONResponse({"ResultCode": 0, "ResultDesc": "Success"})

    except json.JSONDecodeError:
        logging.error("Invalid JSON received")
        return JSONResponse(
            {"ResultCode": 1, "ResultDesc": "Invalid JSON"},
            status_code=400
        )
    except Exception as e:
        logging.critical(f"Callback processing error: {str(e)}")
        return JSONResponse(
            {"ResultCode": 1, "ResultDesc": "Internal server error"},
            status_code=500
        )

async def process_referral_reward(referred_id: str, referrer_id: str, session=None):
    """Process referral reward with fraud checks"""
    try:
        # 1. Get referral record
        referral = await db.referrals.find_one(
            {
                "referred_id": referred_id,
                "referrer_id": referrer_id,
                "status": "pending"
            },
            session=session
        )

        if not referral:
            return

        reward_amount = Decimal(str(referral["reward_amount"]))

        # 2. Fraud checks
        if await is_fraudulent_referral(referrer_id, referred_id, session=session):
            await db.referrals.update_one(
                {"_id": referral["_id"]},
                {"$set": {"status": "rejected", "reason": "fraud_check_failed"}},
                session=session
            )
            return

        # 3. Reward referrer
        await db.users.update_one(
            {"user_id": referrer_id},
            {
                "$inc": {
                    "wallet_balance": reward_amount,
                    "referral_earnings": reward_amount,
                    "total_earned": reward_amount
                }
            },
            session=session
        )

        # 4. Update referral status
        await db.referrals.update_one(
            {"_id": referral["_id"]},
            {
                "$set": {
                    "status": "completed",
                    "completed_at": datetime.utcnow()
                }
            },
            session=session
        )

        # 5. Create reward transaction
        await db.transactions.insert_one(
            {
                "transaction_id": str(uuid.uuid4()),
                "user_id": referrer_id,
                "type": "referral_reward",
                "amount": float(reward_amount),
                "currency": "KES",
                "status": "completed",
                "metadata": {
                    "referred_user": referred_id,
                    "referral_id": referral["referral_id"]
                },
                "created_at": datetime.utcnow(),
                "completed_at": datetime.utcnow()
            },
            session=session
        )

        # 6. Create notification
        await create_notification(
            {
                "title": "Referral Reward!",
                "message": f"You earned KES {reward_amount:,.2f} from referral",
                "user_id": referrer_id,
                "type": "reward"
            },
            session=session
        )

        logging.info(f"🎉 Referral reward processed: {referrer_id} -> {referred_id}")

    except Exception as e:
        logging.error(f"Referral processing error: {str(e)}")
        raise

async def is_fraudulent_referral(referrer_id: str, referred_id: str, session=None) -> bool:
    """Check for potential referral fraud"""
    # 1. Same user check
    if referrer_id == referred_id:
        return True
    
    # 2. Device/IP fingerprint check
    referrer = await db.users.find_one({"user_id": referrer_id}, session=session)
    referred = await db.users.find_one({"user_id": referred_id}, session=session)
    
    matching_fields = []
    for field in ["device_fingerprint", "registration_ip"]:
        if referrer.get(field) and referrer[field] == referred.get(field):
            matching_fields.append(field)
    
    if matching_fields:
        logging.warning(f"Fraud detected - matching {', '.join(matching_fields)}")
        return True
    
    # 3. Velocity check (too many referrals)
    referral_count = await db.referrals.count_documents(
        {"referrer_id": referrer_id, "status": "completed"},
        session=session
    )
    
    if referral_count > 50:  # Adjust threshold as needed
        logging.warning(f"Excessive referrals: {referrer_id} has {referral_count} referrals")
        return True
    
    return False

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
            # Referral System Endpoints
@app.get("/api/referrals/stats")
async def get_referral_stats(current_user: dict = Depends(get_current_user)):
    """
    Enhanced Referral Statistics with:
    - Aggregation pipeline for efficient counting
    - Tiered reward tracking
    - Fraud detection metrics
    - Pagination support
    """
    try:
        # Use MongoDB aggregation for efficient stats calculation
        stats = await db.referrals.aggregate([
            {"$match": {"referrer_id": current_user['user_id']}},
            {"$group": {
                "_id": "$status",
                "count": {"$sum": 1},
                "total_rewards": {"$sum": "$reward_amount"},
                "potential_rewards": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$status", "pending"]},
                            "$reward_amount",
                            0
                        ]
                    }
                }
            }},
            {"$group": {
                "_id": None,
                "total_referrals": {"$sum": "$count"},
                "stats": {
                    "$push": {
                        "status": "$_id",
                        "count": "$count",
                        "total_rewards": "$total_rewards"
                    }
                },
                "total_earned": {"$sum": "$total_rewards"},
                "potential_earnings": {"$sum": "$potential_rewards"}
            }},
            {"$project": {
                "_id": 0,
                "referral_code": current_user['referral_code'],
                "total_referrals": 1,
                "stats": 1,
                "total_earned": 1,
                "potential_earnings": 1,
                "tier": {
                    "$switch": {
                        "branches": [
                            {
                                "case": {"$gte": ["$total_referrals", 50]},
                                "then": "gold"
                            },
                            {
                                "case": {"$gte": ["$total_referrals", 20]},
                                "then": "silver"
                            }
                        ],
                        "default": "bronze"
                    }
                }
            }}
        ]).to_list(1)

        # Get recent referrals with pagination
        recent_referrals = await db.referrals.find(
            {"referrer_id": current_user['user_id']},
            {"_id": 0, "referred_id": 1, "status": 1, "created_at": 1}
        ).sort("created_at", -1).limit(5).to_list(5)

        return {
            "success": True,
            "stats": stats[0] if stats else {
                "total_referrals": 0,
                "total_earned": 0,
                "potential_earnings": 0,
                "tier": "bronze",
                "referral_code": current_user['referral_code']
            },
            "recent_referrals": json_serializable_doc(recent_referrals)
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch referral stats: {str(e)}"
        )

# Enhanced Referral Reward Processing
async def process_referral_reward(
    referred_user_id: str,
    referrer_id: str,
    session=None
):
    """
    Atomic referral reward processing with:
    - Fraud detection
    - Tiered rewards
    - Comprehensive logging
    """
    try:
        async with await client.start_session() as s if not session else nullcontext(session):
            async with s.start_transaction() if not session else nullcontext():
                # 1. Get referral record
                referral = await db.referrals.find_one(
                    {
                        "referred_id": referred_user_id,
                        "referrer_id": referrer_id,
                        "status": "pending"
                    },
                    session=s
                )

                if not referral:
                    return False

                # 2. Fraud checks
                if await is_fraudulent_referral(referrer_id, referred_user_id, session=s):
                    await db.referrals.update_one(
                        {"_id": referral["_id"]},
                        {
                            "$set": {
                                "status": "fraud",
                                "fraud_reason": "Same device/IP detected"
                            }
                        },
                        session=s
                    )
                    return False

                # 3. Calculate tiered reward
                base_reward = Decimal(str(referral["reward_amount"]))
                referral_count = await db.referrals.count_documents(
                    {"referrer_id": referrer_id, "status": "rewarded"},
                    session=s
                )

                # Tiered reward multipliers
                reward_multiplier = Decimal('1.0')  # Base
                if referral_count >= 50:
                    reward_multiplier = Decimal('1.5')  # Gold tier
                elif referral_count >= 20:
                    reward_multiplier = Decimal('1.2')  # Silver tier

                final_reward = base_reward * reward_multiplier

                # 4. Update referral status
                await db.referrals.update_one(
                    {"_id": referral["_id"]},
                    {
                        "$set": {
                            "status": "rewarded",
                            "activation_date": datetime.utcnow(),
                            "final_reward": float(final_reward),
                            "reward_multiplier": float(reward_multiplier)
                        }
                    },
                    session=s
                )

                # 5. Update referrer's wallet
                await db.users.update_one(
                    {"user_id": referrer_id},
                    {
                        "$inc": {
                            "wallet_balance": float(final_reward),
                            "referral_earnings": float(final_reward),
                            "total_earned": float(final_reward),
                            "referral_count": 1
                        }
                    },
                    session=s
                )

                # 6. Create reward transaction
                await db.transactions.insert_one(
                    {
                        "transaction_id": str(uuid.uuid4()),
                        "user_id": referrer_id,
                        "type": "referral_reward",
                        "amount": float(final_reward),
                        "currency": "KES",
                        "status": "completed",
                        "metadata": {
                            "referred_user": referred_user_id,
                            "referral_id": referral["referral_id"],
                            "tier_multiplier": float(reward_multiplier)
                        },
                        "created_at": datetime.utcnow(),
                        "completed_at": datetime.utcnow()
                    },
                    session=s
                )

                # 7. Create notification
                await create_notification(
                    {
                        "title": "🎉 Referral Reward!",
                        "message": f"You earned KSH {final_reward:,.2f} ({reward_multiplier}x multiplier)",
                        "user_id": referrer_id,
                        "type": "reward",
                        "metadata": {
                            "referral_id": referral["referral_id"],
                            "referred_user": referred_user_id
                        }
                    },
                    session=s
                )

                # 8. Log the reward
                logging.info(
                    f"Referral reward processed: {referrer_id} -> {referred_user_id} | "
                    f"Amount: {final_reward} | Multiplier: {reward_multiplier}x"
                )

                if not session:
                    await s.commit_transaction()

                return True

    except Exception as e:
        if not session:
            await s.abort_transaction()
        logging.error(f"Referral reward failed: {str(e)}")
        raise

# Fraud Detection Helper
async def is_fraudulent_referral(
    referrer_id: str,
    referred_id: str,
    session=None
) -> bool:
    """Enhanced fraud detection with:
    - Device fingerprinting
    - IP address matching
    - Behavioral patterns
    """
    try:
        # 1. Get both user records
        referrer = await db.users.find_one(
            {"user_id": referrer_id},
            {"device_fingerprint": 1, "registration_ip": 1},
            session=session
        )
        referred = await db.users.find_one(
            {"user_id": referred_id},
            {"device_fingerprint": 1, "registration_ip": 1},
            session=session
        )

        # 2. Check matching fingerprints
        if (referrer and referred and 
            referrer.get("device_fingerprint") and 
            referrer["device_fingerprint"] == referred.get("device_fingerprint")):
            return True

        # 3. Check matching IPs (within 24h of registration)
        if (referrer and referred and 
            referrer.get("registration_ip") and 
            referrer["registration_ip"] == referred.get("registration_ip")):
            
            # Check if registered around the same time
            time_diff = abs((referrer["created_at"] - referred["created_at"]).total_seconds()
            if time_diff < 86400:  # 24 hours
                return True

        # 4. Check for circular referrals
        circular_ref = await db.referrals.find_one({
            "referrer_id": referred_id,
            "referred_id": referrer_id
        }, session=session)

        if circular_ref:
            return True

        return False

    except Exception as e:
        logging.error(f"Fraud detection error: {str(e)}")
        return False  # Fail-safe

# Enhanced Notification System
async def create_notification(
    notification_data: dict,
    session=None
):
    """Enhanced notification system with:
    - Priority levels
    - Expiration dates
    - Actionable notifications
    """
    try:
        notification_doc = {
            "notification_id": str(uuid.uuid4()),
            "title": notification_data['title'],
            "message": notification_data['message'],
            "user_id": notification_data.get('user_id'),
            "type": notification_data.get('type', 'system'),
            "priority": notification_data.get('priority', 'medium'),
            "is_read": False,
            "action_url": notification_data.get('action_url'),
            "expires_at": datetime.utcnow() + timedelta(days=30),
            "metadata": notification_data.get('metadata', {}),
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow()
        }

        if not session:
            await db.notifications.insert_one(notification_doc)
        else:
            await db.notifications.insert_one(notification_doc, session=session)

        # Real-time push notification could be added here
        # await send_push_notification(notification_doc)

        return notification_doc

    except Exception as e:
        logging.error(f"Notification creation failed: {str(e)}")
        raise
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
    
    # Reverted to summing the amount for total deposits
    total_deposits_agg = await db.transactions.aggregate([
        {"$match": {"type": "deposit", "status": "completed"}},
        {"$group": {"_id": None, "total_amount": {"$sum": "$amount"}}} 
    ]).to_list(1)
    total_deposits = total_deposits_agg[0]['total_amount'] if total_deposits_agg else 0.0

    # Reverted to summing the amount for total withdrawals
    total_withdrawals_agg = await db.transactions.aggregate([
        {"$match": {"type": "withdrawal", "status": "completed"}},
        {"$group": {"_id": None, "total_amount": {"$sum": "$amount"}}} 
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
            "QueueTimeOutURL": "https://official-money.onrender.com/api/payments/mpesa-b2c-timeout", # IMPORTANT: Replace with your actual timeout URL
            "ResultURL": "https://official-money.onrender.com/api/payments/mpesa-b2c-result", # IMPORTANT: Replace with your actual result URL
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
    """
    Enhanced M-Pesa B2C Timeout Callback Handler with:
    - IP whitelisting
    - Atomic transaction processing
    - Comprehensive logging
    - Fraud detection
    - Retry mechanism tracking
    """
    try:
        # 1. Verify request source
        client_ip = request.client.host
        safaricom_ips = ["196.201.214.200", "196.201.214.206"]  # Safaricom IPs
        if client_ip not in safaricom_ips:
            logging.warning(f"⚠️ Unauthorized IP access attempt: {client_ip}")
            return JSONResponse(
                {"ResultCode": 1, "ResultDesc": "Unauthorized"},
                status_code=403
            )

        # 2. Parse and validate request
        data = await request.json()
        logging.info(f"MPesa B2C Timeout Callback: {json.dumps(data)}")

        required_fields = ["ResultCode", "OriginatorConversationID", "ConversationID"]
        if not all(field in data for field in required_fields):
            return JSONResponse(
                {"ResultCode": 1, "ResultDesc": "Missing required fields"},
                status_code=400
            )

        # 3. Process timeout
        originator_id = data["OriginatorConversationID"]
        conversation_id = data["ConversationID"]

        async with await client.start_session() as session:
            try:
                async with session.start_transaction():
                    # 4. Find the transaction
                    transaction = await db.transactions.find_one(
                        {
                            "metadata.mpesa.originator_conversation_id": originator_id,
                            "status": {"$in": ["pending", "processing"]}
                        },
                        session=session
                    )

                    if not transaction:
                        logging.warning(f"Transaction not found: {originator_id}")
                        return JSONResponse(
                            {"ResultCode": 0, "ResultDesc": "Transaction not found"}
                        )

                    # 5. Update transaction status
                    update_result = await db.transactions.update_one(
                        {"_id": transaction["_id"]},
                        {
                            "$set": {
                                "status": "timed_out",
                                "completed_at": datetime.utcnow(),
                                "metadata.mpesa.timeout_data": data,
                                "metadata.retry_attempts": transaction.get("metadata", {}).get("retry_attempts", 0) + 1
                            }
                        },
                        session=session
                    )

                    # 6. Refund user if needed
                    user = await db.users.find_one(
                        {"user_id": transaction["user_id"]},
                        session=session
                    )

                    if user and transaction["status"] != "reversed":
                        refund_amount = Decimal(str(transaction["amount"]))
                        
                        await db.users.update_one(
                            {"user_id": user["user_id"]},
                            {
                                "$inc": {"wallet_balance": float(refund_amount)},
                                "$set": {"metadata.last_refund": datetime.utcnow()}
                            },
                            session=session
                        )

                        # 7. Create refund transaction
                        refund_txn_id = str(uuid.uuid4())
                        await db.transactions.insert_one(
                            {
                                "transaction_id": refund_txn_id,
                                "user_id": user["user_id"],
                                "type": "refund",
                                "amount": float(refund_amount),
                                "currency": "KES",
                                "status": "completed",
                                "reference": f"Refund for failed withdrawal {transaction['transaction_id']}",
                                "metadata": {
                                    "original_transaction": transaction["transaction_id"],
                                    "reason": "b2c_timeout"
                                },
                                "created_at": datetime.utcnow(),
                                "completed_at": datetime.utcnow()
                            },
                            session=session
                        )

                    # 8. Create notification
                    await create_notification(
                        {
                            "title": "Withdrawal Timed Out",
                            "message": f"Your withdrawal of KES {transaction['amount']} timed out. Funds have been returned.",
                            "user_id": transaction["user_id"],
                            "type": "payment",
                            "priority": "high",
                            "action_url": f"/transactions/{transaction['transaction_id']}"
                        },
                        session=session
                    )

                    # 9. Log the event
                    logging.info(
                        f"B2C Timeout processed: User {transaction['user_id']} | "
                        f"Amount: {transaction['amount']} | "
                        f"Original TX: {transaction['transaction_id']}"
                    )

                    await session.commit_transaction()

                    return JSONResponse({"ResultCode": 0, "ResultDesc": "Success"})

            except Exception as e:
                await session.abort_transaction()
                logging.error(f"Transaction failed in B2C timeout: {str(e)}")
                raise

    except json.JSONDecodeError:
        logging.error("Invalid JSON in B2C timeout callback")
        return JSONResponse(
            {"ResultCode": 1, "ResultDesc": "Invalid JSON"},
            status_code=400
        )
    except Exception as e:
        logging.critical(f"B2C timeout processing error: {str(e)}")
        return JSONResponse(
            {"ResultCode": 1, "ResultDesc": "Internal server error"},
            status_code=500
                    )
@app.post("/api/admin/tasks", dependencies=[Depends(get_current_admin_user)])
async def create_task(task_data: Task):
    task_id = str(uuid.uuid4())
    task_doc = {
        "task_id": task_id,  # ✅ Include it in the task document
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


# Add these environment variables for PayPal
PAYPAL_CLIENT_ID = os.environ.get('PAYPAL_CLIENT_ID', '')
PAYPAL_CLIENT_SECRET = os.environ.get('PAYPAL_CLIENT_SECRET', '')
PAYPAL_MODE = os.environ.get('PAYPAL_MODE', 'sandbox')  # or 'live'
PAYPAL_CURRENCY = os.environ.get('PAYPAL_CURRENCY', 'USD')
PAYPAL_RETURN_URL = os.environ.get('PAYPAL_RETURN_URL', 'https://yourdomain.com/payment/success')
PAYPAL_CANCEL_URL = os.environ.get('PAYPAL_CANCEL_URL', 'https://yourdomain.com/payment/cancel')

# Configure PayPal SDK
paypalrestsdk.configure({
    "mode": PAYPAL_MODE,
    "client_id": PAYPAL_CLIENT_ID,
    "client_secret": PAYPAL_CLIENT_SECRET
})

# PayPal Utility Functions
async def get_paypal_access_token():
    """Get PayPal OAuth2 access token"""
    auth = f"{PAYPAL_CLIENT_ID}:{PAYPAL_CLIENT_SECRET}"
    encoded_auth = base64.b64encode(auth.encode('utf-8')).decode('utf-8')
    
    headers = {
        "Authorization": f"Basic {encoded_auth}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = "grant_type=client_credentials"
    
    try:
        async with httpx.AsyncClient() as client:
            url = "https://api-m.sandbox.paypal.com/v1/oauth2/token" if PAYPAL_MODE == "sandbox" else "https://api-m.paypal.com/v1/oauth2/token"
            response = await client.post(url, headers=headers, data=data)
            response.raise_for_status()
            return response.json()["access_token"]
    except Exception as e:
        print(f"PayPal auth error: {e}")
        raise HTTPException(status_code=500, detail="Could not get PayPal access token")

async def create_paypal_order(amount: float, currency: str, user_id: str, description: str):
    """Create a PayPal order for payment"""
    access_token = await get_paypal_access_token()
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    
    payload = {
        "intent": "CAPTURE",
        "purchase_units": [{
            "reference_id": user_id,
            "description": description,
            "amount": {
                "currency_code": currency,
                "value": f"{amount:.2f}"
            }
        }],
        "application_context": {
            "return_url": PAYPAL_RETURN_URL,
            "cancel_url": PAYPAL_CANCEL_URL,
            "brand_name": "EarnPlatform",
            "user_action": "PAY_NOW",
            "shipping_preference": "NO_SHIPPING"
        }
    }
    
    try:
        async with httpx.AsyncClient() as client:
            url = "https://api-m.sandbox.paypal.com/v2/checkout/orders" if PAYPAL_MODE == "sandbox" else "https://api-m.paypal.com/v2/checkout/orders"
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        print(f"PayPal order creation error: {e}")
        raise HTTPException(status_code=500, detail="Could not create PayPal order")

async def capture_paypal_order(order_id: str):
    """Capture a PayPal payment"""
    access_token = await get_paypal_access_token()
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            url = f"https://api-m.sandbox.paypal.com/v2/checkout/orders/{order_id}/capture" if PAYPAL_MODE == "sandbox" else f"https://api-m.paypal.com/v2/checkout/orders/{order_id}/capture"
            response = await client.post(url, headers=headers)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        print(f"PayPal capture error: {e}")
        raise HTTPException(status_code=500, detail="Could not capture PayPal payment")

async def get_paypal_payout_status(payout_id: str):
    """Get status of a PayPal payout"""
    access_token = await get_paypal_access_token()
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            url = f"https://api-m.sandbox.paypal.com/v1/payments/payouts/{payout_id}" if PAYPAL_MODE == "sandbox" else f"https://api-m.paypal.com/v1/payments/payouts/{payout_id}"
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
    except Exception as e:
        print(f"PayPal payout status error: {e}")
        raise HTTPException(status_code=500, detail="Could not get PayPal payout status")

# PayPal Routes
@app.post("/api/payments/paypal/create-order")
async def create_paypal_order_endpoint(
    amount: float,
    current_user: dict = Depends(get_current_user)
):
    """Create a PayPal order for deposit"""
    try:
        # Convert KES to USD (you'll need a real exchange rate API for production)
        # This is a simplified example - use a real exchange rate service
        exchange_rate = 0.007  # Example: 1 KES = 0.007 USD
        usd_amount = amount * exchange_rate
        
        # Create PayPal order
        order = await create_paypal_order(
            amount=usd_amount,
            currency=PAYPAL_CURRENCY,
            user_id=current_user['user_id'],
            description=f"Deposit of {amount} KES to EarnPlatform"
        )
        
        # Create transaction record
        transaction_id = str(uuid.uuid4())
        transaction_doc = {
            "transaction_id": transaction_id,
            "user_id": current_user['user_id'],
            "type": "deposit",
            "amount": amount,
            "currency": "KES",
            "converted_amount": usd_amount,
            "converted_currency": PAYPAL_CURRENCY,
            "status": "pending",
            "method": "paypal",
            "paypal_order_id": order['id'],
            "created_at": datetime.utcnow(),
            "completed_at": None
        }
        await db.transactions.insert_one(transaction_doc)
        
        # Find the approval link
        approval_link = next(
            (link['href'] for link in order['links'] if link['rel'] == 'approve'),
            None
        )
        
        if not approval_link:
            raise HTTPException(status_code=500, detail="No approval link found in PayPal response")
        
        return {
            "success": True,
            "message": "PayPal order created",
            "order_id": order['id'],
            "approval_url": approval_link,
            "transaction_id": transaction_id
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/payments/paypal/capture-order")
async def capture_paypal_order_endpoint(
    order_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Capture a PayPal payment after user approval"""
    try:
        # Capture the payment
        capture_result = await capture_paypal_order(order_id)
        
        # Find the transaction
        transaction = await db.transactions.find_one({
            "paypal_order_id": order_id,
            "user_id": current_user['user_id']
        })
        
        if not transaction:
            raise HTTPException(status_code=404, detail="Transaction not found")
        
        # Update transaction status
        if capture_result['status'] == 'COMPLETED':
            # Find the purchase unit to get the amount
            purchase_unit = capture_result['purchase_units'][0]
            payment = purchase_unit['payments']['captures'][0]
            
            # Update user balance
            amount = transaction['amount']  # Original KES amount
            
            await db.users.update_one(
                {"user_id": current_user['user_id']},
                {
                    "$inc": {"wallet_balance": amount},
                    "$inc": {"total_earned": amount}
                }
            )
            
            # Update transaction
            await db.transactions.update_one(
                {"transaction_id": transaction['transaction_id']},
                {
                    "$set": {
                        "status": "completed",
                        "completed_at": datetime.utcnow(),
                        "paypal_capture_id": payment['id'],
                        "details": capture_result
                    }
                }
            )
            
            # Check if this is an activation deposit
            user = await db.users.find_one({"user_id": current_user['user_id']})
            if not user['is_activated'] and user['wallet_balance'] >= user['activation_amount']:
                await db.users.update_one(
                    {"user_id": current_user['user_id']},
                    {"$set": {"is_activated": True}}
                )
                
                # Check for referral activation
                referral = await db.referrals.find_one({
                    "referred_id": current_user['user_id'],
                    "status": "pending"
                })
                
                if referral:
                    # Update referral status and reward referrer
                    await db.referrals.update_one(
                        {"referral_id": referral['referral_id']},
                        {
                            "$set": {
                                "status": "activated",
                                "activation_date": datetime.utcnow()
                            }
                        }
                    )
                    
                    reward_amount = referral['reward_amount']
                    await db.users.update_one(
                        {"user_id": referral['referrer_id']},
                        {
                            "$inc": {
                                "wallet_balance": reward_amount,
                                "referral_earnings": reward_amount,
                                "total_earned": reward_amount,
                                "referral_count": 1
                            }
                        }
                    )
                    
                    # Create transaction for referrer
                    referral_transaction_id = str(uuid.uuid4())
                    await db.transactions.insert_one({
                        "transaction_id": referral_transaction_id,
                        "user_id": referral['referrer_id'],
                        "type": "referral",
                        "amount": reward_amount,
                        "status": "completed",
                        "method": "system",
                        "created_at": datetime.utcnow(),
                        "completed_at": datetime.utcnow(),
                        "reference": f"Referral bonus for {current_user['email']}"
                    })
            
            return {
                "success": True,
                "message": "Payment captured successfully",
                "amount": amount,
                "wallet_balance": user['wallet_balance'] + amount,
                "is_activated": user['wallet_balance'] + amount >= user['activation_amount']
            }
        else:
            raise HTTPException(status_code=400, detail="Payment not completed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/payments/paypal/withdraw")
async def withdraw_to_paypal(
    withdrawal_data: PayPalWithdrawalRequest,
    current_user: dict = Depends(get_current_user)
):
    """Withdraw funds to PayPal"""
    try:
        user_id = current_user['user_id']
        
        # Validate user has sufficient balance
        if current_user['wallet_balance'] < withdrawal_data.amount:
            raise HTTPException(status_code=400, detail="Insufficient balance")
        
        # Convert KES to USD (use real exchange rate in production)
        exchange_rate = 0.007  # Example rate
        usd_amount = withdrawal_data.amount * exchange_rate
        
        # Create payout
        payout_id = str(uuid.uuid4())
        access_token = await get_paypal_access_token()
        
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "sender_batch_header": {
                "sender_batch_id": payout_id,
                "email_subject": "You have a payment from EarnPlatform",
                "email_message": f"You have received a payment of {usd_amount:.2f} USD from EarnPlatform."
            },
            "items": [{
                "recipient_type": "EMAIL",
                "amount": {
                    "value": f"{usd_amount:.2f}",
                    "currency": PAYPAL_CURRENCY
                },
                "note": "Withdrawal from EarnPlatform",
                "sender_item_id": user_id,
                "receiver": withdrawal_data.email,
                "notification_language": "en-US"
            }]
        }
        
        # First create transaction record
        transaction_id = str(uuid.uuid4())
        transaction_doc = {
            "transaction_id": transaction_id,
            "user_id": user_id,
            "type": "withdrawal",
            "amount": withdrawal_data.amount,
            "original_kes": withdrawal_data.original_kes,
            "converted_amount": usd_amount,
            "converted_currency": PAYPAL_CURRENCY,
            "status": "processing",
            "method": "paypal",
            "paypal_payout_id": payout_id,
            "recipient_email": withdrawal_data.email,
            "created_at": datetime.utcnow(),
            "completed_at": None
        }
        await db.transactions.insert_one(transaction_doc)
        
        # Deduct from user balance immediately
        await db.users.update_one(
            {"user_id": user_id},
            {
                "$inc": {
                    "wallet_balance": -withdrawal_data.amount,
                    "total_withdrawn": withdrawal_data.amount
                }
            }
        )
        
        # Make the payout request
        try:
            async with httpx.AsyncClient() as client:
                url = "https://api-m.sandbox.paypal.com/v1/payments/payouts" if PAYPAL_MODE == "sandbox" else "https://api-m.paypal.com/v1/payments/payouts"
                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                payout_response = response.json()
                
                # Update transaction with PayPal response
                await db.transactions.update_one(
                    {"transaction_id": transaction_id},
                    {
                        "$set": {
                            "paypal_batch_id": payout_response['batch_header']['payout_batch_id'],
                            "details": payout_response
                        }
                    }
                )
                
                return {
                    "success": True,
                    "message": "Withdrawal processing",
                    "transaction_id": transaction_id,
                    "payout_batch_id": payout_response['batch_header']['payout_batch_id'],
                    "new_balance": current_user['wallet_balance'] - withdrawal_data.amount
                }
        except httpx.HTTPStatusError as e:
            # If payout fails, refund the user
            await db.users.update_one(
                {"user_id": user_id},
                {
                    "$inc": {
                        "wallet_balance": withdrawal_data.amount,
                        "total_withdrawn": -withdrawal_data.amount
                    }
                }
            )
            
            await db.transactions.update_one(
                {"transaction_id": transaction_id},
                {
                    "$set": {
                        "status": "failed",
                        "completed_at": datetime.utcnow(),
                        "error": e.response.text
                    }
                }
            )
            
            raise HTTPException(status_code=400, detail=f"PayPal payout failed: {e.response.text}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/payments/paypal/webhook")
async def paypal_webhook(request: Request):
    """Handle PayPal webhook events"""
    try:
        data = await request.json()
        event_type = data['event_type']
        
        # Verify webhook signature (important for production)
        # You should implement proper signature verification here
        
        # Handle different event types
        if event_type == "PAYMENT.CAPTURE.COMPLETED":
            # Handle completed payment
            resource = data['resource']
            order_id = resource['supplementary_data']['related_ids']['order_id']
            
            # Update transaction status
            await db.transactions.update_one(
                {"paypal_capture_id": resource['id']},
                {
                    "$set": {
                        "status": "completed",
                        "completed_at": datetime.utcnow(),
                        "details": resource
                    }
                }
            )
            
        elif event_type == "PAYMENT.PAYOUTS-ITEM.SUCCEEDED":
            # Handle successful payout
            resource = data['resource']
            payout_item_id = resource['payout_item']['sender_item_id']
            
            await db.transactions.update_one(
                {"paypal_payout_id": payout_item_id},
                {
                    "$set": {
                        "status": "completed",
                        "completed_at": datetime.utcnow(),
                        "details": resource
                    }
                }
            )
            
        elif event_type == "PAYMENT.PAYOUTS-ITEM.FAILED":
            # Handle failed payout
            resource = data['resource']
            payout_item_id = resource['payout_item']['sender_item_id']
            
            # Find transaction and refund user
            transaction = await db.transactions.find_one({"paypal_payout_id": payout_item_id})
            if transaction:
                await db.users.update_one(
                    {"user_id": transaction['user_id']},
                    {
                        "$inc": {
                            "wallet_balance": transaction['amount'],
                            "total_withdrawn": -transaction['amount']
                        }
                    }
                )
                
                await db.transactions.update_one(
                    {"transaction_id": transaction['transaction_id']},
                    {
                        "$set": {
                            "status": "failed",
                            "completed_at": datetime.utcnow(),
                            "details": resource
                        }
                    }
                )
        
        return {"success": True}
    except Exception as e:
        print(f"PayPal webhook error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
