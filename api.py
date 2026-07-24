import os
import io
import json
import psycopg
import psycopg.rows
import pandas as pd
from fastapi import FastAPI, Query, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from dotenv import load_dotenv
from datetime import datetime
from auth import create_access_token, decode_access_token
from users import authenticate_user, get_user, create_user, validate_password

load_dotenv(override=True)

app = FastAPI(title="CryptoWatch API", version="1.0.0")

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── DB connection ─────────────────────────────────────────────────────────────
def get_conn():
    return psycopg.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        row_factory=psycopg.rows.dict_row
    )

# ── Auth Bearer ───────────────────────────────────────────────────────────────
security = HTTPBearer(auto_error=False)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token   = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    user = get_user(payload.get("sub"))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user

# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"status": "CryptoWatch API is running"}

# ── Pydantic Models ───────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str
    password: str

class RegisterRequest(BaseModel):
    username:  str
    password:  str
    full_name: str = ""
    email:     str = ""

class AddAddressRequest(BaseModel):
    address:     str
    crypto_type: str   = "BTC"
    source_type: str   = "manual"
    category:    str   = "uncategorized"
    confidence:  float = 0.5
    raw_context: str   = ""
    notes:       str   = ""

# ── Login ─────────────────────────────────────────────────────────────────────
@app.post("/auth/login")
def login(credentials: LoginRequest):
    if not credentials.username or not credentials.password:
        raise HTTPException(status_code=400, detail="Username and password required")
    user, error = authenticate_user(credentials.username, credentials.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=error)
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return {
        "access_token": token,
        "token_type":   "bearer",
        "username":     user["username"],
        "role":         user["role"],
        "full_name":    user["full_name"]
    }

# ── Register ──────────────────────────────────────────────────────────────────
@app.post("/auth/register")
def register(data: RegisterRequest):
    if len(data.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    is_valid, error_msg = validate_password(data.password)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)
    if get_user(data.username):
        raise HTTPException(status_code=400, detail="Username already exists. Choose a different one")
    success = create_user(
        username=data.username, password=data.password,
        role="investigator", full_name=data.full_name, email=data.email
    )
    if not success:
        raise HTTPException(status_code=500, detail="Could not create user. Try again")
    return {"message": f"Account created successfully for {data.username}"}

# ── Get current user ──────────────────────────────────────────────────────────
@app.get("/auth/me")
def get_me(current_user: dict = Depends(get_current_user)):
    return {
        "username":   current_user["username"],
        "role":       current_user["role"],
        "full_name":  current_user["full_name"],
        "email":      current_user["email"],
        "last_login": current_user["last_login"].isoformat() if current_user["last_login"] else None
    }

# ── List users (admin only) ───────────────────────────────────────────────────
@app.get("/auth/users")
def list_users(current_user: dict = Depends(require_admin)):
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("""
        SELECT id, username, role, full_name, email,
               created_at, last_login, is_active,
               failed_attempts, locked_until
        FROM users ORDER BY created_at DESC
    """)
    rows = cur.fetchall()
    cur.close(); conn.close()
    results = []
    for row in rows:
        r = dict(row)
        for k, v in r.items():
            if isinstance(v, datetime): r[k] = v.isoformat()
        results.append(r)
    return results

# ── Query addresses ───────────────────────────────────────────────────────────
@app.get("/addresses")
def get_addresses(
    crypto_type: str = Query(None),
    category:    str = Query(None),
    date_from:   str = Query(None),
    date_to:     str = Query(None),
    search:      str = Query(None),
    source_type: str = Query(None),
    limit:       int = Query(100),
    offset:      int = Query(0)
):
    conn = get_conn()
    cur  = conn.cursor()
    filters, params = [], []
    if crypto_type: filters.append("crypto_type = %s");   params.append(crypto_type)
    if category:    filters.append("category = %s");      params.append(category)
    if date_from:   filters.append("last_scanned >= %s"); params.append(date_from)
    if date_to:     filters.append("last_scanned <= %s"); params.append(date_to)
    if search:      filters.append("address ILIKE %s");   params.append(f"%{search}%")
    if source_type: filters.append("source_type = %s");   params.append(source_type)
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    cur.execute(f"""
        SELECT id, address, crypto_type, category, confidence,
               first_seen, last_scanned, source_url, source_type, notes
        FROM crypto_addresses {where}
        ORDER BY last_scanned DESC
        LIMIT %s OFFSET %s
    """, params + [limit, offset])
    rows = cur.fetchall()
    cur.close(); conn.close()
    results = []
    for row in rows:
        r = dict(row)
        for k, v in r.items():
            if isinstance(v, datetime): r[k] = v.isoformat()
        results.append(r)
    return results

# ── Add new address ───────────────────────────────────────────────────────────
@app.post("/addresses/add")
def add_address(
    data: AddAddressRequest,
    current_user: dict = Depends(get_current_user)
):
    from ml_model import predict_address
    # Auto-detect coin type via ML if not provided
    if not data.crypto_type or data.crypto_type == "AUTO":
        try:
            pred = predict_address(data.address)
            data.crypto_type = pred["coin_type"]
        except Exception:
            data.crypto_type = "BTC"
    conn = get_conn()
    cur  = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO crypto_addresses
                (address, crypto_type, source_type, category,
                 confidence, raw_context, notes, first_seen, last_scanned)
            VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
            ON CONFLICT (address) DO UPDATE
                SET crypto_type  = EXCLUDED.crypto_type,
                    category     = EXCLUDED.category,
                    source_type  = EXCLUDED.source_type,
                    confidence   = EXCLUDED.confidence,
                    notes        = EXCLUDED.notes,
                    last_scanned = NOW()
            RETURNING id
        """, (
            data.address, data.crypto_type, data.source_type,
            data.category, data.confidence, data.raw_context, data.notes
        ))
        row = cur.fetchone()
        conn.commit()
        return {"id": row["id"], "message": "Address saved successfully"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close(); conn.close()

# ── Update address category ───────────────────────────────────────────────────
@app.patch("/addresses/{address_id}/category")
def update_category(
    address_id: int,
    data: dict,
    current_user: dict = Depends(get_current_user)
):
    category = data.get("category")
    if not category:
        raise HTTPException(status_code=400, detail="Category is required")
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("""
        UPDATE crypto_addresses
        SET category = %s, last_scanned = NOW()
        WHERE id = %s
    """, (category, address_id))
    conn.commit()
    cur.close(); conn.close()
    return {"message": f"Category updated to {category}"}

# ── Get single address detail ─────────────────────────────────────────────────
@app.get("/addresses/{address_id}")
def get_address_detail(address_id: int):
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("""
        SELECT ca.*,
               array_agg(DISTINCT t.tag)  FILTER (WHERE t.tag  IS NOT NULL) as tags,
               array_agg(DISTINCT e.name) FILTER (WHERE e.name IS NOT NULL) as entities
        FROM crypto_addresses ca
        LEFT JOIN tags t                 ON t.address_id   = ca.id
        LEFT JOIN address_entity_map aem ON aem.address_id = ca.id
        LEFT JOIN entities e             ON e.id           = aem.entity_id
        WHERE ca.id = %s
        GROUP BY ca.id
    """, (address_id,))
    row = cur.fetchone()
    cur.close(); conn.close()
    if not row:
        return JSONResponse(status_code=404, content={"error": "Not found"})
    r = dict(row)
    for k, v in r.items():
        if isinstance(v, datetime): r[k] = v.isoformat()
    return r

# ── Statistics ────────────────────────────────────────────────────────────────
@app.get("/stats")
def get_stats():
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT category, COUNT(*) as count FROM crypto_addresses GROUP BY category ORDER BY COUNT(*) DESC")
    by_category = cur.fetchall()
    cur.execute("SELECT crypto_type, COUNT(*) as count FROM crypto_addresses GROUP BY crypto_type ORDER BY COUNT(*) DESC")
    by_type = cur.fetchall()
    cur.execute("SELECT source_type, COUNT(*) as count FROM crypto_addresses GROUP BY source_type ORDER BY COUNT(*) DESC")
    by_source = cur.fetchall()
    cur.execute("SELECT COUNT(*) as count FROM crypto_addresses")
    total = cur.fetchone()["count"]
    cur.execute("SELECT COUNT(*) as count FROM scrape_logs WHERE status = 'success'")
    successful_scrapes = cur.fetchone()["count"]
    cur.close(); conn.close()
    return {
        "total_addresses":    total,
        "successful_scrapes": successful_scrapes,
        "by_category":        by_category,
        "by_crypto_type":     by_type,
        "by_source_type":     by_source
    }

# ── Export CSV ────────────────────────────────────────────────────────────────
@app.get("/export/csv")
def export_csv(
    category:    str = Query(None),
    crypto_type: str = Query(None),
    date_from:   str = Query(None),
    date_to:     str = Query(None)
):
    conn = psycopg.connect(
        host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )
    filters, params = [], []
    if category:    filters.append("category = %s");      params.append(category)
    if crypto_type: filters.append("crypto_type = %s");   params.append(crypto_type)
    if date_from:   filters.append("last_scanned >= %s"); params.append(date_from)
    if date_to:     filters.append("last_scanned <= %s"); params.append(date_to)
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    cur = conn.cursor()
    cur.execute(f"""
        SELECT id, address, crypto_type, category, confidence,
               first_seen, last_scanned, source_url, source_type
        FROM crypto_addresses {where} ORDER BY last_scanned DESC
    """, params if params else None)
    rows = cur.fetchall()
    cols = ["id","address","crypto_type","category","confidence",
            "first_seen","last_scanned","source_url","source_type"]
    cur.close(); conn.close()
    df = pd.DataFrame(rows, columns=cols)
    stream = io.StringIO()
    df.to_csv(stream, index=False)
    stream.seek(0)
    return StreamingResponse(
        iter([stream.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=cryptowatch_export.csv"}
    )

# ── Export JSON ───────────────────────────────────────────────────────────────
@app.get("/export/json")
def export_json(
    category:    str = Query(None),
    crypto_type: str = Query(None),
    date_from:   str = Query(None),
    date_to:     str = Query(None)
):
    conn = psycopg.connect(
        host=os.getenv("DB_HOST"), port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"), user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )
    filters, params = [], []
    if category:    filters.append("category = %s");      params.append(category)
    if crypto_type: filters.append("crypto_type = %s");   params.append(crypto_type)
    if date_from:   filters.append("last_scanned >= %s"); params.append(date_from)
    if date_to:     filters.append("last_scanned <= %s"); params.append(date_to)
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    cur = conn.cursor()
    cur.execute(f"""
        SELECT id, address, crypto_type, category, confidence,
               first_seen, last_scanned, source_url, source_type
        FROM crypto_addresses {where} ORDER BY last_scanned DESC
    """, params if params else None)
    rows = cur.fetchall()
    cols = ["id","address","crypto_type","category","confidence",
            "first_seen","last_scanned","source_url","source_type"]
    cur.close(); conn.close()
    records = []
    for row in rows:
        record = dict(zip(cols, row))
        for k, v in record.items():
            if isinstance(v, datetime): record[k] = v.isoformat()
            elif v is None: record[k] = ""
        records.append(record)
    result = json.dumps(records, indent=4, ensure_ascii=False)
    return StreamingResponse(
        iter([result]), media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=cryptowatch_export.json"}
    )

# ── ML: Model info ────────────────────────────────────────────────────────────
@app.get("/ml/info")
def ml_info():
    from ml_model import get_model_info
    return get_model_info()

# ── ML: Predict single address ────────────────────────────────────────────────
@app.post("/ml/predict_single")
def ml_predict_single(
    data:         dict,
    current_user: dict = Depends(get_current_user)
):
    from ml_model import predict_address

    address = data.get("address", "").strip()
    if not address:
        raise HTTPException(status_code=400, detail="Address is required")

    try:
        result = predict_address(address)
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction error: {str(e)}")

    return {
        "coin_type":              result["coin_type"],
        "category":               result["category"],
        "source_type":            result["source_type"],
        "confidence":             result["confidence"],
        "coin_confidence":        result["coin_confidence"],
        "category_confidence":    result["category_confidence"],
        "source_confidence":      result["source_confidence"],
        "top3_coin_types":        result["top3_coin_types"],
        "top3_categories":        result["top3_categories"],
        "top3_source_types":      result["top3_source_types"],
    }

# ── Scrape logs ───────────────────────────────────────────────────────────────
@app.get("/logs")
def get_logs(limit: int = 50):
    conn = get_conn()
    cur  = conn.cursor()
    cur.execute("SELECT * FROM scrape_logs ORDER BY scraped_at DESC LIMIT %s", (limit,))
    rows = cur.fetchall()
    cur.close(); conn.close()
    results = []
    for row in rows:
        r = dict(row)
        for k, v in r.items():
            if isinstance(v, datetime): r[k] = v.isoformat()
        results.append(r)
    return results
