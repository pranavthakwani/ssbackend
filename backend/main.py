from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import io
import csv
import json
from phishing_detector import PhishingDetector
from utils import clean_url, extract_domain

app = FastAPI(title="SurfSecure API", description="Advanced Phishing URL Detection System", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize detector
detector = PhishingDetector()

class URLRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    phishing: bool
    confidence: float
    domain: str
    risk_factors: list

@app.get("/")
async def root():
    return {"message": "SurfSecure API - Advanced Phishing Detection System", "version": "1.0.0"}

@app.post("/scan", response_model=ScanResponse)
async def scan_url(request: URLRequest):
    """Scan a single URL for phishing indicators"""
    try:
        cleaned_url = clean_url(request.url)
        domain = extract_domain(cleaned_url)
        
        # Get prediction from detector
        prediction = detector.predict(cleaned_url)
        
        return ScanResponse(
            phishing=prediction['phishing'],
            confidence=prediction['confidence'],
            domain=domain,
            risk_factors=prediction['risk_factors']
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing URL: {str(e)}")

@app.post("/batch-scan")
async def batch_scan(file: UploadFile = File(...)):
    """Batch scan URLs from CSV file"""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")
    
    try:
        content = await file.read()
        csv_content = content.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(csv_content))
        
        results = []
        for row in csv_reader:
            if 'URL' in row or 'url' in row:
                url = row.get('URL') or row.get('url')
                if url:
                    try:
                        cleaned_url = clean_url(url)
                        domain = extract_domain(cleaned_url)
                        prediction = detector.predict(cleaned_url)
                        
                        results.append({
                            'url': url,
                            'domain': domain,
                            'phishing': prediction['phishing'],
                            'confidence': prediction['confidence']
                        })
                    except Exception as e:
                        results.append({
                            'url': url,
                            'domain': 'unknown',
                            'phishing': False,
                            'confidence': 0.0,
                            'error': str(e)
                        })
        
        return {"results": results, "total_processed": len(results)}
    
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error processing file: {str(e)}")

@app.get("/stats")
async def get_stats():
    """Get system statistics and insights"""
    # In a real application, this would query a database
    # For demo purposes, we return mock statistics
    return {
        "total_scanned": 15247,
        "phishing_percentage": 12.3,
        "safe_percentage": 87.7,
        "top_phishing_keywords": [
            "secure", "login", "verify", "account", "suspended", "update"
        ],
        "recent_activity": [
            {"date": "2025-01-20", "scanned": 156, "phishing_found": 19},
            {"date": "2025-01-19", "scanned": 203, "phishing_found": 25},
            {"date": "2025-01-18", "scanned": 178, "phishing_found": 22},
            {"date": "2025-01-17", "scanned": 145, "phishing_found": 18},
            {"date": "2025-01-16", "scanned": 189, "phishing_found": 23},
            {"date": "2025-01-15", "scanned": 167, "phishing_found": 20},
            {"date": "2025-01-14", "scanned": 134, "phishing_found": 16}
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)