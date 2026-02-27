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
    
    parsed_data = parser.parse_nginx_log_lines(decoded_content)
    if not parsed_data:
        raise HTTPException(status_code=400, detail="Could not parse any valid Nginx logs.")

    parsed_data = detection.run_detection_pipeline(parsed_data)
    current_batch_id = str(uuid.uuid4())

    # --- UPDATED: Filter and save ONLY anomalies ---
    db_logs = []
    for log in parsed_data:
        if log.get('is_anomaly') is True:
            db_log = models.LogEntry(**log, batch_id=current_batch_id)
            db_logs.append(db_log)
        
    # Only interact with the DB if we found anomalies
    if db_logs:
        db.add_all(db_logs)
        db.commit()

    return {
        "message": "File uploaded and parsed successfully",
        "batch_id": current_batch_id,
        "lines_processed": len(parsed_data),     # Total lines in the file
        "anomalies_saved": len(db_logs),         # Only the threats stored in DB
        "data": parsed_data                      # Return all data so UI chart still works
    }