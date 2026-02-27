from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import secrets
import uuid

import database
import models
import parser
import detection

# Create the DB tables
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="TENEX SOC Analyst API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()

# --- Authentication Logic ---
def verify_credentials(credentials: HTTPBasicCredentials = Depends(security), db: Session = Depends(database.get_db)):
    # Check database for user
    user = db.query(models.User).filter(models.User.username == credentials.username).first()
    
    if not user or not secrets.compare_digest(user.password, credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user.username

# --- Endpoints ---

@app.get("/")
def health_check(username: str = Depends(verify_credentials)):
    return {"status": "ok", "message": f"Welcome {username}, TENEX Backend is running"}

@app.post("/signup")
def signup(user_in: dict, db: Session = Depends(database.get_db)):
    existing_user = db.query(models.User).filter(models.User.username == user_in.get('username')).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    new_user = models.User(username=user_in['username'], password=user_in['password'])
    db.add(new_user)
    db.commit()
    return {"message": "User created successfully"}

@app.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...), 
    db: Session = Depends(database.get_db),
    username: str = Depends(verify_credentials)
):
    if not file.filename.endswith(('.log', '.txt')):
        raise HTTPException(status_code=400, detail="Only .log or .txt files allowed")

    content = await file.read()
    decoded_content = content.decode("utf-8", errors="replace")

    print("--- [DEBUG] 1. UPLOAD RECEIVED ---")
    
    # 1. Parse the data ONLY ONCE
    parsed_data = parser.parse_nginx_log_lines(decoded_content)
    if not parsed_data:
        raise HTTPException(status_code=400, detail="Could not parse any valid logs.")
        
    print(f"--- [DEBUG] 2. PARSER FINISHED: {len(parsed_data)} lines parsed ---")
    
    # 2. Run the ML/AI detection ONLY ONCE
    analyzed_data = detection.run_detection_pipeline(parsed_data)
    
    print("--- [DEBUG] 3. DETECTION FINISHED ---")
    
    current_batch_id = str(uuid.uuid4())

    # 3. Filter and save ONLY anomalies
    db_logs = []
    for log in analyzed_data:
        if log.get('is_anomaly') is True:
            db_log = models.LogEntry(**log, batch_id=current_batch_id)
            db_logs.append(db_log)
    
    # NEW: Create a master record for this upload in BatchHistory
    new_batch_record = models.BatchHistory(
        batch_id=current_batch_id,
        username=username,
        filename=file.filename,
        anomalies_count=len(db_logs)
    )
    db.add(new_batch_record)
        
    if db_logs:
        db.add_all(db_logs)
        
    db.commit()
    print(f"--- [DEBUG] 4. DATABASE SAVED: {len(db_logs)} anomalies and batch metadata ---")

    return {
        "message": "File uploaded and parsed successfully",
        "batch_id": current_batch_id,
        "lines_processed": len(parsed_data),     
        "anomalies_saved": len(db_logs),         
        "data": analyzed_data                    
    }

# --- NEW: History Retrieval Endpoints ---

@app.get("/batches")
def get_user_batches(db: Session = Depends(database.get_db), username: str = Depends(verify_credentials)):
    """Fetches a lightweight list of all past uploads for the sidebar UI."""
    batches = db.query(models.BatchHistory)\
        .filter(models.BatchHistory.username == username)\
        .order_by(models.BatchHistory.created_at.desc())\
        .all()
    
    return {"batches": batches}

@app.get("/batches/{batch_id}")
def get_batch_data(batch_id: str, db: Session = Depends(database.get_db), username: str = Depends(verify_credentials)):
    """Fetches the full anomaly data for a specific historical batch."""
    
    # 1. Security Check: Ensure this batch actually belongs to the logged-in user!
    batch_record = db.query(models.BatchHistory)\
        .filter(models.BatchHistory.batch_id == batch_id, models.BatchHistory.username == username)\
        .first()
        
    if not batch_record:
        raise HTTPException(status_code=404, detail="Batch not found or unauthorized access.")
        
    # 2. Retrieve the logs associated with this batch
    logs = db.query(models.LogEntry).filter(models.LogEntry.batch_id == batch_id).all()
    
    return {
        "batch_info": batch_record,
        "data": logs
    }