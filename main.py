import os
import json
from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google.cloud import vision_v1 as vision, firestore
from google.api_core.exceptions import GoogleAPICallError, InvalidArgument, ResourceExhausted
import logging
from urllib.parse import urlparse, parse_qs
import requests
from bs4 import BeautifulSoup
from requests_oauthlib import OAuth2Session
import xml.etree.ElementTree as ET
from config import settings
import time
from google.cloud import secretmanager
import os
def load_credentials():
    client = secretmanager.SecretManagerServiceClient()
    secret_name = "projects/authentisell/secrets/authentisell-credentials/versions/latest"
    response = client.access_secret_version(name=secret_name)
    credentials = response.payload.data.decode("UTF-8")
    with open("/tmp/credentials.json", "w") as f:
        f.write(credentials)
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "/tmp/credentials.json"
load_credentials()

app = FastAPI(title="AuthentiSell Backend")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://authentisell-frontend-lixu1tme4-derek-geslisons-projects.vercel.app",
        "http://localhost:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simplified Authentication
async def mock_auth(authorization: str = Header(default=None)):
    import logging
    logging.basicConfig(level=logging.INFO)
    logging.info(f"Received Authorization header: {authorization}")
    if authorization != "Bearer mock_token":
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"user": "test@example.com"}

# Login Request Model
class LoginRequest(BaseModel):
    email: str
    password: str
    class Config:
        schema_extra = {
            "example": {
                "email": "test@example.com",
                "password": "password123"
            }
        }

@app.post("/auth/login")
async def login(request: LoginRequest):
    # Mock authentication: accept any email/password
    return {"access_token": "mock_token", "token_type": "bearer"}

# 1. IP Theft Detection
def detect_ip_theft(image_content: bytes) -> dict:
    if not image_content:
        raise ValueError("Image content cannot be empty.")
    if len(image_content) > 20 * 1024 * 1024:
        raise ValueError("Image exceeds 20MB limit for web detection.")

    platform_map = {
        'etsy.com': 'Etsy', 'www.etsy.com': 'Etsy',
        'ebay.com': 'eBay', 'www.ebay.com': 'eBay',
        'aliexpress.com': 'AliExpress', 'www.aliexpress.com': 'AliExpress',
    }

    client = vision.ImageAnnotatorClient()
    try:
        image = vision.Image(content=image_content)
        response = client.web_detection(image=image)
        web_detection = response.web_detection

        matches = []
        for page in web_detection.pages_with_matching_images:
            parsed_url = urlparse(page.url)
            netloc = parsed_url.netloc.lower()
            if netloc in platform_map:
                platform = platform_map[netloc]
                for img in page.full_matching_images + page.partial_matching_images:
                    if img.score >= 0.9:
                        matches.append({
                            "image_url": img.url,
                            "platform": platform,
                            "confidence": img.score,
                            "page_url": page.url
                        })
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        return {"matches": matches, "error": None}
    except InvalidArgument as e:
        return {"matches": [], "error": f"Invalid input: {str(e)}"}
    except ResourceExhausted as e:
        return {"matches": [], "error": f"API rate limit exceeded: {str(e)}"}
    except GoogleAPICallError as e:
        return {"matches": [], "error": f"API error: {str(e)}"}
    except Exception as e:
        return {"matches": [], "error": f"Unexpected error: {str(e)}"}

@app.post("/api/scan")
async def scan_image(file: UploadFile = File(...), user: dict = Depends(mock_auth)):
    try:
        logger.info(f"Scan request received, file: {file.filename}, size: {file.size}")
        image_content = await file.read()
        logger.info(f"Image content read: {len(image_content)} bytes")
        if not image_content:
            raise HTTPException(status_code=400, detail="Empty file")
        result = detect_ip_theft(image_content)
        if result.get("error"):
            logger.error(f"Detect IP theft error: {result['error']}")
            raise HTTPException(status_code=500, detail=result["error"])
        return result
    except Exception as e:
        logger.error(f"Scan error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

# 2. DMCA Takedown
def etsy_takedown(request_json: dict, listing_id: str) -> dict:
    client_id = settings.etsy_client_id
    client_secret = settings.etsy_client_secret
    token_url = "https://api.etsy.com/v3/public/oauth/token"
    api_url = f"https://api.etsy.com/v3/ip/report/{listing_id}"

    if not client_id or not client_secret:
        return {"success": False, "error": "Etsy credentials missing."}

    oauth = OAuth2Session(client_id)
    try:
        token = oauth.fetch_token(token_url=token_url, client_id=client_id, client_secret=client_secret, grant_type="client_credentials")
        headers = {"Authorization": f"Bearer {token['access_token']}"}
        body = {
            "infringing_listing_id": listing_id,
            "evidence": request_json["evidence"],
            "copyrighted_work": request_json["copyright_proof"],
            "contact_info": request_json["user_contact"],
            "good_faith_statement": request_json["statement_good_faith"],
            "accuracy_statement": request_json["statement_accuracy"],
            "signature": request_json["signature"]
        }

        resp = requests.post(api_url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return {"success": True, "request_id": data.get("report_id")}
    except requests.RequestException as e:
        return {"success": False, "error": str(e)}

def ebay_takedown(request_json: dict, listing_id: str) -> dict:
    api_url = "https://api.ebay.com/ws/api.dll"
    app_id = settings.ebay_app_id
    oauth_token = settings.ebay_oauth_token

    if not app_id or not oauth_token:
        return {"success": False, "error": "eBay credentials missing."}

    root = ET.Element("VeROReportItemsRequest", xmlns="urn:ebay:apis:eBLBaseComponents")
    requester_credentials = ET.SubElement(root, "RequesterCredentials")
    ET.SubElement(requester_credentials, "eBayAuthToken").text = oauth_token
    report_packet = ET.SubElement(root, "VeROReportPacket")
    report_item = ET.SubElement(report_packet, "ReportItem")
    ET.SubElement(report_item, "ItemID").text = listing_id
    ET.SubElement(report_item, "ReasonCodeID").text = "1"
    ET.SubElement(report_item, "DetailedMessage").text = (
        f"Evidence: {request_json['evidence']}\n"
        f"Proof: {request_json['copyright_proof']}\n"
        f"Contact: {json.dumps(request_json['user_contact'])}\n"
        f"Statements: {request_json['statement_good_faith']} {request_json['statement_accuracy']}\n"
        f"Signature: {request_json['signature']}"
    )
    xml_body = ET.tostring(root, encoding="utf-8", method="xml")

    headers = {
        "X-EBAY-API-COMPATIBILITY-LEVEL": "1193",
        "X-EBAY-API-DEV-NAME": os.environ.get("EBAY_DEV_ID", ""),
        "X-EBAY-API-APP-NAME": app_id,
        "X-EBAY-API-CERT-NAME": os.environ.get("EBAY_CERT_ID", ""),
        "X-EBAY-API-CALL-NAME": "VeROReportItems",
        "X-EBAY-API-SITEID": "0",
        "X-EBAY-API-IAF-TOKEN": oauth_token,
        "Content-Type": "text/xml"
    }

    try:
        resp = requests.post(api_url, data=xml_body, headers=headers)
        resp.raise_for_status()
        resp_root = ET.fromstring(resp.text)
        ack = resp_root.find(".//Ack").text
        if ack == "Success":
            packet_id = resp_root.find(".//VeROReportPacketID").text
            return {"success": True, "request_id": packet_id}
        else:
            error = resp_root.find(".//LongMessage").text
            return {"success": False, "error": error}
    except requests.RequestException as e:
        return {"success": False, "error": str(e)}
    except ET.ParseError as pe:
        return {"success": False, "error": f"XML parse error: {pe}"}

def submit_takedown(request_json: dict) -> dict:
    platform = request_json.get("platform")
    if not platform or platform not in ["Etsy", "eBay"]:
        raise ValueError("Invalid or missing platform.")

    listing_id = request_json.get("listing_id")
    if not listing_id:
        parsed = urlparse(request_json["listing_url"])
        if platform == "Etsy":
            listing_id = parsed.path.split('/')[-1]
        elif platform == "eBay":
            query = parse_qs(parsed.query)
            listing_id = query.get("item", [None])[0] or parsed.path.split('/')[-1]

    if not listing_id:
        raise ValueError("Could not parse listing_id from URL.")

    try:
        if platform == "Etsy":
            response = etsy_takedown(request_json, listing_id)
        elif platform == "eBay":
            response = ebay_takedown(request_json, listing_id)

        status = "submitted" if response["success"] else "failed"
        error = response.get("error")
        request_id = response.get("request_id")

        db = firestore.Client()
        log_data = {
            "platform": platform,
            "listing_id": listing_id,
            "status": status,
            "error": error,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "input_json": request_json
        }
        db.collection("takedown_logs").add(log_data)
        return {"status": status, "error": error, "request_id": request_id}
    except Exception as e:
        try:
            db = firestore.Client()
            db.collection("takedown_logs").add({
                "platform": platform,
                "listing_id": listing_id,
                "status": "failed",
                "error": str(e),
                "timestamp": firestore.SERVER_TIMESTAMP,
                "input_json": request_json
            })
        except GoogleAPICallError as gae:
            print(f"Firestore error: {gae}")
        return {"status": "failed", "error": str(e), "request_id": None}

class TakedownRequest(BaseModel):
    platform: str
    listing_url: str
    evidence: str
    copyright_proof: str
    user_contact: dict
    statement_good_faith: str
    statement_accuracy: str
    signature: str

@app.post("/api/takedown")
async def initiate_takedown(request: TakedownRequest, user: dict = Depends(mock_auth)):
    result = submit_takedown(request.dict())
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])
    return result

# 3. Data Privacy Monitoring
def monitor_data_exposure(email: str, shop_name: str) -> dict:
    if not email or not shop_name:
        raise ValueError("Email and shop name are required.")

    results = {"breaches": [], "exposures": [], "error": None}
    api_key = settings.hibp_api_key
    if not api_key:
        results["error"] = "HIBP API key missing."
        return results

    db = None
    try:
        db = firestore.Client()
        cache_ref = db.collection("privacy_cache").document(email)
        cached = cache_ref.get()
        if cached.exists:
            cached_data = cached.to_dict()
            if "breaches" in cached_data:
                results["breaches"] = cached_data["breaches"]
            if "exposures" in cached_data:
                results["exposures"] = cached_data["exposures"]
                return results
    except GoogleAPICallError as e:
        print(f"Firestore cache error: {e}")

    try:
        hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        headers = {"hibp-api-key": api_key, "user-agent": "AuthentiSell-Monitoring"}
        response = requests.get(hibp_url, headers=headers)
        if response.status_code == 200:
            breaches = response.json()
            results["breaches"] = [
                {"name": b["Name"], "description": b["Description"], "date": b["BreachDate"]}
                for b in breaches
            ]
        elif response.status_code == 404:
            pass
        elif response.status_code == 429:
            results["error"] = "HIBP rate limit exceeded. Try again later."
            return results
        else:
            response.raise_for_status()
    except requests.RequestException as e:
        results["error"] = f"HIBP API error: {str(e)}"
        return results

    exposures = []
    try:
        spokeo_email_url = f"https://www.spokeo.com/email-search/search?e={requests.utils.quote(email)}"
        response = requests.get(spokeo_email_url, headers={"user-agent": "AuthentiSell-Scraper"})
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            found = bool(soup.find("div", class_="search-results")) and "no results" not in soup.text.lower()
            exposures.append({
                "source": "Spokeo",
                "found": found,
                "removal": "https://www.spokeo.com/optout"
            })
        else:
            raise requests.RequestException(f"Status: {response.status_code}")
    except requests.RequestException as e:
        exposures.append({"source": "Spokeo", "found": None, "removal": "https://www.spokeo.com/optout", "error": str(e)})

    try:
        spokeo_name_url = f"https://www.spokeo.com/{requests.utils.quote(shop_name.replace(' ', '-'))}"
        response = requests.get(spokeo_name_url, headers={"user-agent": "AuthentiSell-Scraper"})
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            found = "results" in soup.text.lower() and "no results" not in soup.text.lower()
            exposures.append({
                "source": "Spokeo (Name)",
                "found": found,
                "removal": "https://www.spokeo.com/optout"
            })
        else:
            raise requests.RequestException(f"Status: {response.status_code}")
    except requests.RequestException as e:
        exposures.append({"source": "Spokeo (Name)", "found": None, "removal": "https://www.spokeo.com/optout", "error": str(e)})

    try:
        beenverified_url = f"https://www.beenverified.com/lp/es-2?search_type=email&term={requests.utils.quote(email)}"
        response = requests.get(beenverified_url, headers={"user-agent": "AuthentiSell-Scraper"})
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            found = "report available" in soup.text.lower() or "results found" in soup.text.lower()
            exposures.append({
                "source": "BeenVerified",
                "found": found,
                "removal": "https://www.beenverified.com/optout"
            })
        else:
            raise requests.RequestException(f"Status: {response.status_code}")
    except requests.RequestException as e:
        exposures.append({"source": "BeenVerified", "found": None, "removal": "https://www.beenverified.com/optout", "error": str(e)})

    results["exposures"] = exposures
    if db:
        try:
            cache_ref.set({"breaches": results["breaches"], "exposures": results["exposures"], "timestamp": firestore.SERVER_TIMESTAMP})
        except GoogleAPICallError as e:
            print(f"Firestore cache write error: {e}")
    return results

class PrivacyRequest(BaseModel):
    email: str
    shop_name: str

@app.post("/api/privacy")
async def monitor_privacy(request: PrivacyRequest, user: dict = Depends(mock_auth)):
    result = monitor_data_exposure(request.email, request.shop_name)
    if result.get("error"):
        raise HTTPException(status_code=500, detail=result["error"])
    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)