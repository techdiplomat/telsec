import os
import subprocess
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from typing import Dict

app = FastAPI(title="TelSec Kali API v2")
API_KEY = os.environ.get("TELSEC_API_KEY", "telsec-kali-2024")

class ToolRequest(BaseModel):
    target: str = ""
    msisdn: str = ""
    gt: str = ""
    module: str = ""
    command: str = ""

def verify_key(x_api_key: str):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

@app.post("/run/sigploit")
async def run_sigploit(req: ToolRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    # Example: python3 sigploit.py --module ss7 --attack location --msisdn <num>
    cmd = ["python3", "/opt/tools/SigPloit/sigploit.py", "--module", req.module, "--msisdn", req.msisdn]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return {"stdout": result.stdout, "stderr": result.stderr}

@app.post("/run/ss7maper")
async def run_ss7maper(req: ToolRequest, x_api_key: str = Header(None)):
    verify_key(x_api_key)
    cmd = ["/opt/tools/ss7MAPer/ss7maper", "-t", req.target]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return {"stdout": result.stdout, "stderr": result.stderr}

@app.get("/health")
async def health():
    return {"status": "v2_online"}
