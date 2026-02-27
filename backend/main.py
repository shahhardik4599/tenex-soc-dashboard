from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import secrets

import database
import models
import parser
import detection
import uuid

# Create the DB tables
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="TENEX SOC Analyst API")

# --- CORS BLOCK ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"], # Allows the Next.js frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()

# --- Basic Authentication ---
def verify_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, "admin")
    correct_password = secrets.compare_digest(credentials.password, "tenex2026")
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# --- Endpoints ---
@app.get("/")
def health_check():
    return {"status": "ok", "message": "TENEX Backend is running"}

import uuid # NEW: Make sure to import uuid at the top of main.py, or just leave it here!

@app.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...), 
    db: Session = Depends(database.get_db),
    username: str = Depends(verify_credentials)
):
    if not file.filename.endswith(('.log', '.txt')):
        raise HTTPException(status_code=400, detail="Only .log or .txt files allowed")

    # Read and parse the file
    content = await file.read()
    decoded_content = content.decode("utf-8", errors="replace")
    
    parsed_data = parser.parse_nginx_log_lines(decoded_content)
    
    if not parsed_data:
        raise HTTPException(status_code=400, detail="Could not parse any valid Nginx logs.")

    # Run the Triangulation AI Detection Pipeline
    parsed_data = detection.run_detection_pipeline(parsed_data)

    # NEW: Generate a unique ID for this specific file upload
    current_batch_id = str(uuid.uuid4())

    # Save to Database
    db_logs = []
    for log in parsed_data:
        # NEW: Pass the batch_id into the database row
        db_log = models.LogEntry(**log, batch_id=current_batch_id)
        db_logs.append(db_log)
        
    db.add_all(db_logs)
    db.commit()

    return {
        "message": "File uploaded and parsed successfully",
        "batch_id": current_batch_id, # NEW: Return it to the frontend
        "lines_processed": len(db_logs),
        "data": parsed_data
    }