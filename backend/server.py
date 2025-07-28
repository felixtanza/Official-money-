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

# Environment variables
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-secret-key-here')
MPESA_CONSUMER_KEY = os.environ.get('MPESA_CONSUMER_KEY', '')
MPESA_CONSUMER_SECRET = os.environ.get('MPESA_CONSUMER_SECRET', '')
MPESA_BUSINESS_SHORTCODE = os.environ.get('MPESA_BUSINESS_SHORTCODE', '')
MPESA_PASSKEY = os.environ.get('MPESA_PASSKEY', '')

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
    type: str  # survey, ad, writing, referral
    requirements: Dict[str, Any]

class TaskCompletion(BaseModel):
    task_id: str
    completion_data: Dict[str, Any]

class NotificationCreate(BaseModel):
    title: str
    message: str
    user_id: Optional[str] = None  # None means broadcast to all users

# Utility functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
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
        "theme": "light"
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
    
    token = create_jwt_token(user_id, user_data.email)
    
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
            "wallet_balance": 0.0
        }
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
    
    token = create_jwt_token(user['user_id'], user['email'])
    
    return {
        "success": True,
        "message": "Login successful!",
        "token": token,
        "user": {
            "user_id": user['user_id'],
            "email": user['email'],
            "full_name": user['full_name'],
            "referral_code": user['referral_code'],
            "is_activated": user['is_activated'],
            "wallet_balance": user['wallet_balance'],
            "theme": user.get('theme', 'light')
        }
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
    
    # Get task completion stats
    task_completions = await db.task_completions.count_documents({"user_id": user_id})
    
    # Get notifications
    notifications = await db.notifications.find(
        {"$or": [{"user_id": user_id}, {"user_id": None}]}
    ).sort("created_at", -1).limit(5).to_list(5)
    
    return {
        "success": True,
        "user": {
            "full_name": current_user['full_name'],
            "wallet_balance": current_user['wallet_balance'],
            "is_activated": current_user['is_activated'],
            "activation_amount": current_user.get('activation_amount', 500.0),
            "total_earned": current_user.get('total_earned', 0.0),
            "total_withdrawn": current_user.get('total_withdrawn', 0.0),
            "referral_earnings": current_user.get('referral_earnings', 0.0),
            "task_earnings": current_user.get('task_earnings', 0.0),
            "referral_count": current_user.get('referral_count', 0),
            "referral_code": current_user['referral_code']
        },
        "recent_transactions": transactions,
        "referral_stats": referral_stats,
        "task_completions": task_completions,
        "notifications": notifications
    }

# Payment routes
@app.post("/api/payments/deposit")
async def initiate_deposit(deposit_data: DepositRequest, current_user: dict = Depends(get_current_user)):
    transaction_id = str(uuid.uuid4())
    
    # For now, simulate M-Pesa integration
    # In production, this would call actual M-Pesa STK Push
    transaction_doc = {
        "transaction_id": transaction_id,
        "user_id": current_user['user_id'],
        "type": "deposit",
        "amount": deposit_data.amount,
        "phone": deposit_data.phone,
        "status": "pending",
        "method": "mpesa",
        "created_at": datetime.utcnow(),
        "completed_at": None,
        "mpesa_receipt": None
    }
    
    await db.transactions.insert_one(transaction_doc)
    
    return {
        "success": True,
        "message": f"Deposit of KSH {deposit_data.amount} initiated. Please complete payment on your phone.",
        "transaction_id": transaction_id,
        "amount": deposit_data.amount,
        "phone": deposit_data.phone
    }

@app.post("/api/payments/simulate-deposit-success")
async def simulate_deposit_success(transaction_id: str, current_user: dict = Depends(get_current_user)):
    """Simulate successful M-Pesa deposit for testing"""
    transaction = await db.transactions.find_one({"transaction_id": transaction_id, "user_id": current_user['user_id']})
    if not transaction:
        raise HTTPException(status_code=404, detail="Transaction not found")
    
    if transaction['status'] != 'pending':
        raise HTTPException(status_code=400, detail="Transaction already processed")
    
    # Update transaction
    await db.transactions.update_one(
        {"transaction_id": transaction_id},
        {
            "$set": {
                "status": "completed",
                "completed_at": datetime.utcnow(),
                "mpesa_receipt": f"MPESA{secrets.token_hex(4).upper()}"
            }
        }
    )
    
    # Update user wallet
    new_balance = current_user['wallet_balance'] + transaction['amount']
    update_data = {"wallet_balance": new_balance}
    
    # Check if this activates the account
    if not current_user['is_activated'] and transaction['amount'] >= current_user.get('activation_amount', 500.0):
        update_data['is_activated'] = True
        
        # Process referral reward if user was referred
        if current_user.get('referred_by'):
            await process_referral_reward(current_user['user_id'], current_user['referred_by'])
    
    await db.users.update_one(
        {"user_id": current_user['user_id']},
        {"$set": update_data}
    )
    
    # Create notification
    await create_notification({
        "title": "Deposit Successful!",
        "message": f"Your deposit of KSH {transaction['amount']} has been processed successfully.",
        "user_id": current_user['user_id']
    })
    
    return {
        "success": True,
        "message": f"Deposit of KSH {transaction['amount']} completed successfully!",
        "new_balance": new_balance,
        "is_activated": update_data.get('is_activated', current_user['is_activated'])
    }

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
        "status": "pending",
        "method": "mpesa",
        "created_at": datetime.utcnow(),
        "processed_at": None,
        "approved_by": None
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
    
    # Get available tasks (not completed by user)
    tasks = await db.tasks.find(
        {"task_id": {"$nin": completed_tasks}, "is_active": True}
    ).to_list(20)
    
    return {
        "success": True,
        "tasks": tasks
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
        "referrals": referrals
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
        "notification_id": str(uuid.uuid4()),
        "title": notification_data['title'],
        "message": notification_data['message'],
        "user_id": notification_data.get('user_id'),  # None for broadcast
        "is_read": False,
        "created_at": datetime.utcnow()
    }
    await db.notifications.insert_one(notification_doc)

@app.post("/api/notifications/create")
async def create_notification_endpoint(notification_data: NotificationCreate):
    """Admin endpoint to create notifications"""
    await create_notification(notification_data.dict())
    return {"success": True, "message": "Notification created"}

@app.get("/api/notifications")
async def get_notifications(current_user: dict = Depends(get_current_user)):
    notifications = await db.notifications.find(
        {"$or": [{"user_id": current_user['user_id']}, {"user_id": None}]}
    ).sort("created_at", -1).limit(20).to_list(20)
    
    return {"success": True, "notifications": notifications}

@app.put("/api/notifications/{notification_id}/read")
async def mark_notification_read(notification_id: str, current_user: dict = Depends(get_current_user)):
    await db.notifications.update_one(
        {"notification_id": notification_id},
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)