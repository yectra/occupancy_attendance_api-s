import json
import logging
import azure.functions as func
# from natsort import natsorted
from dotenv import load_dotenv
from azure.cosmos import CosmosClient, exceptions 
from azure.storage.blob import BlobServiceClient, ContentSettings
import os
import uuid
from pydantic import BaseModel
from typing import List, Optional, Literal
import base64
import numpy as np
from datetime import datetime
import re
import jwt
# from jwt import PyJWTError
import requests
from functools import lru_cache
import functools
from azure.functions import HttpRequest, HttpResponse
from jwt.exceptions import InvalidTokenError, InvalidSignatureError, ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Load environment variables
load_dotenv()

# Azure Cosmos DB configuration
COSMOS_CONNECTION_STRING = os.getenv('COSMOS_CONNECTION_STRING')
DATABASE_NAME = os.getenv('DATABASE_NAME')
EMPLOYEE_CONTAINER_NAME = os.getenv('EMPLOYEE_CONTAINER_NAME')
ATTENDANCE_CONTAINER_NAME = os.getenv('ATTENDANCE_CONTAINER_NAME')
ORGANIZATION_CONTAINER_NAME = os.getenv('ORGANIZATION_CONTAINER_NAME')
CAMERA_URLS_CONTAINER_NAME = os.getenv('CAMERA_URLS_CONTAINER_NAME')
BLOB_CONNECTION_STRING = os.getenv('STORAGE_CONNECTION_STRING')
BLOB_CONTAINER_NAME = os.getenv('STORAGE_CONTAINER_NAME')
COUNTS_CONTAINER = os.getenv('COUNTS_CONTAINER')
SETUP_CONTAINER_NAME = os.getenv('SETUP_CONTAINER_NAME')
PERSON_FEATURE_CONTAINER = os.getenv('PERSON_FEATURE_CONTAINER')

# Azure B2C Configuration
TENANT_NAME = os.getenv('AZURE_B2C_TENANT_NAME')
POLICY_NAME = os.getenv('AZURE_B2C_POLICY_NAME')
CLIENT_ID = os.getenv('AZURE_B2C_CLIENT_ID')

# Initialize clients
client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
database = client.get_database_client(DATABASE_NAME)

# Container clients
employee_container = database.get_container_client(EMPLOYEE_CONTAINER_NAME)
attendance_container = database.get_container_client(ATTENDANCE_CONTAINER_NAME)
camera_urls_container = database.get_container_client(CAMERA_URLS_CONTAINER_NAME)
organization_container = database.get_container_client(ORGANIZATION_CONTAINER_NAME)
setup_container = database.get_container_client(SETUP_CONTAINER_NAME)
counts_container = database.get_container_client(COUNTS_CONTAINER)
person_features = database.get_container_client(PERSON_FEATURE_CONTAINER)

# Blob service client
blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)
blob_container_client = blob_service_client.get_container_client(BLOB_CONTAINER_NAME)

from urllib.parse import quote

@lru_cache(maxsize=1)
def get_jwks_uri():
    """Get the JWKS URI from Azure B2C OpenID configuration."""
    try:
        tenant_name = os.getenv('AZURE_B2C_TENANT_NAME')
        policy_name = os.getenv('AZURE_B2C_POLICY_NAME')
        
        # Remove any spaces from the tenant name for the domain
        tenant_domain = tenant_name.replace(' ', '')
        # Properly encode the tenant name for the path
        tenant_path = quote(f"{tenant_name}.onmicrosoft.com")
        
        openid_config_url = f"https://{tenant_domain}.b2clogin.com/{tenant_path}/{policy_name}/v2.0/.well-known/openid-configuration"
        logging.info(f"Attempting to fetch JWKS URI from: {openid_config_url}")
        
        response = requests.get(openid_config_url)
        response.raise_for_status()
        jwks_uri = response.json()['jwks_uri']
        logging.info(f"Successfully retrieved JWKS URI: {jwks_uri}")
        return jwks_uri
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching JWKS URI: {str(e)}")
        logging.error(f"Response status code: {e.response.status_code if hasattr(e, 'response') else 'N/A'}")
        logging.error(f"Response content: {e.response.text if hasattr(e, 'response') else 'N/A'}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error fetching JWKS URI: {str(e)}")
        return None

@lru_cache(maxsize=1)
def get_public_keys():
    """Get public keys from Azure B2C JWKS endpoint."""
    try:
        jwks_uri = get_jwks_uri()
        if not jwks_uri:
            return None
        
        response = requests.get(jwks_uri)
        response.raise_for_status()
        jwks = response.json()
        public_keys = {}
        for jwk in jwks['keys']:
            kid = jwk['kid']
            public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        return public_keys
    except Exception as e:
        logging.error(f"Error fetching public keys: {str(e)}")
        return None

def validate_jwt_token(token):
    """Validate the JWT token from Azure B2C."""
    try:
        # First decode without verification to get the header
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        
        if not kid:
            logging.error("No 'kid' found in token header")
            return None
        
        # Get public keys
        public_keys = get_public_keys()
        if not public_keys or kid not in public_keys:
            logging.error("Unable to find appropriate public key")
            return None
        
        # Verify and decode the token
        decoded_token = jwt.decode(
            token,
            key=public_keys[kid],
            algorithms=['RS256'],
            audience=CLIENT_ID,
            verify=True,
            options={
                'verify_iss': False  # Temporarily disable issuer verification
            }
        )
        
        # Verify required claims
        if not all(k in decoded_token for k in ['sub', 'exp']):
            logging.error("Missing required claims in token")
            return None
        
        # More flexible issuer verification
        token_issuer = decoded_token['iss'].lower()
        tenant_name = os.getenv('AZURE_B2C_TENANT_NAME').lower()
        
        # Check if the issuer contains our tenant name (case-insensitive)
        if tenant_name not in token_issuer:
            logging.error(f"Invalid token issuer. Expected tenant '{tenant_name}' not found in issuer: {token_issuer}")
            return None
        
        return {
            'user_id': decoded_token.get('sub'),
            'email': decoded_token.get('emails', [None])[0],
            'name': decoded_token.get('name')
        }
        
    except jwt.exceptions.InvalidTokenError as e:
        logging.error(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error during token validation: {str(e)}")
        return None
# Authentication Decorator
def require_auth(func):
    @functools.wraps(func)
    async def wrapper(req: HttpRequest) -> HttpResponse:
        auth_header = req.headers.get('Authorization')
        if not auth_header:
            return HttpResponse(
                json.dumps({"detail": "Authorization token is required."}),
                status_code=401
            )

        try:
            # Check if the header starts with "Bearer "
            if not auth_header.startswith('Bearer '):
                return HttpResponse(
                    json.dumps({"detail": "Invalid authorization header format. Must start with 'Bearer'."}),
                    status_code=401
                )

            # Extract token (everything after "Bearer ")
            token = auth_header[7:]
            if not token:
                return HttpResponse(
                    json.dumps({"detail": "Token not found in authorization header."}),
                    status_code=401
                )

            user_info = validate_jwt_token(token)
            if not user_info:
                return HttpResponse(
                    json.dumps({"detail": "Invalid token."}),
                    status_code=401
                )

            req.user_info = user_info
            return await func(req)

        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return HttpResponse(
                json.dumps({"detail": "Authentication failed."}),
                status_code=500
            )

    return wrapper

# Pydantic Models
class CameraDetail(BaseModel):
    entranceName: str
    cameraPosition: Literal["inside-out", "outside-in"]
    videoUrl: str
    doorCoordinates: Optional[List[List[int]]] = None

class PageData(BaseModel):
    capacityOfPeople: int
    alertMessage: Literal["0-20", "20-40", "40-60", "60-80", "80-100"]
    documentId: str = None
    cameraDetails: List[CameraDetail]

# Utility Functions
def upsert_document(container, data: dict):
    try:
        container.upsert_item(data)
        logging.info(f"Document with ID {data['id']} upserted successfully.")
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Error upserting document: {str(e)}")
        raise Exception("Failed to save data to the database.")

# APIs
@app.function_name(name="saveData")
@app.route(route='api/saveData', methods=[func.HttpMethod.POST])
@require_auth
async def authenticated_save_data(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    try:
        req_body = req.get_json()
        data = PageData(**req_body)
        user_id = user_info['user_id']

        # Query to check if user already has a document
        query = "SELECT * FROM c WHERE c.user_id = @user_id"
        parameters = [{"name": "@user_id", "value": user_id}]
        
        existing_items = list(setup_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        if existing_items:
            # Update existing document
            existing_item = existing_items[0]
            existing_item["capacityOfPeople"] = data.capacityOfPeople
            existing_item["alertMessage"] = data.alertMessage
            existing_item["cameraDetails"] = [camera.dict() for camera in data.cameraDetails]

            upsert_document(setup_container, existing_item)
            return func.HttpResponse(
                json.dumps({
                    "message": "Data updated successfully.",
                    "documentId": existing_item["id"]
                }),
                status_code=200
            )
        else:
            # Create new document
            documentId = str(uuid.uuid4())
            document = {
                "id": user_id,
                "capacityOfPeople": data.capacityOfPeople,
                "alertMessage": data.alertMessage,
                "cameraDetails": [camera.dict() for camera in data.cameraDetails],
                
            }
            upsert_document(setup_container, document)
            return func.HttpResponse(
                json.dumps({
                    "message": "Data saved successfully.",
                    "documentId": documentId
                }),
                status_code=201
            )

    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An error occurred during processing."}),
            status_code=500
        )

@app.function_name(name="getCameraUrlsTracker")
@app.route(route='api/getCameraUrls', methods=[func.HttpMethod.GET])
@require_auth
async def getCameraUrls(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info

    try:
        query = f"SELECT * FROM c WHERE c.user_id = '{user_info['user_id']}'"
        items = list(setup_container.query_items(
            query=query, 
            enable_cross_partition_query=True
        ))
        
        video_urls = []
        for item in items:
            camera_details = item.get("cameraDetails", [])
            urls = [camera["videoUrl"] for camera in camera_details if "videoUrl" in camera]
            video_urls.extend(urls)
        
        return func.HttpResponse(
            json.dumps({"videoUrls": video_urls}),
            status_code=200
        )
    
    except Exception as e:
        logging.error(f"Error retrieving camera URLs: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An error occurred while retrieving camera URLs."}),
            status_code=500
        )

@app.function_name(name="getPersonCountOverTime")
@app.route(route='api/getPersonCountOverTime', methods=[func.HttpMethod.GET])
@require_auth
async def get_person_count_over_time(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info

    try:
        query = f"""
        SELECT c.person_id, c.timestamp
        FROM c
        WHERE NOT IS_NULL(c.person_id) AND c.user_id = '{user_info['user_id']}'
        """
        
        items = list(person_features.query_items(query=query, enable_cross_partition_query=True))
        
        from collections import defaultdict
        import datetime

        person_count_by_hour = defaultdict(set)

        for item in items:
            timestamp = item.get("timestamp")
            person_id = item.get("person_id")

            hour_key = datetime.datetime.fromisoformat(timestamp).strftime("%Y-%m-%dT%H")
            person_count_by_hour[hour_key].add(person_id)

        time_series_data = [
            {"time_interval": time_interval, "person_count": len(person_ids)}
            for time_interval, person_ids in sorted(person_count_by_hour.items())
        ]

        return func.HttpResponse(
            json.dumps({"data": time_series_data}),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An unexpected error occurred."}),
            status_code=500
        )

@app.function_name(name="getAllCounts")
@app.route(route='api/getAllCounts', methods=[func.HttpMethod.GET])
@require_auth
async def getAllCounts(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info

    try:
        query = f"SELECT * FROM c WHERE c.user_id = '{user_info['user_id']}'"
        items = counts_container.query_items(query=query, enable_cross_partition_query=True)
       
        counts = {}
        total_entry = 0
        total_exit = 0
 
        for item in items:
            camera_id = str(item["camera_id"])
            entry_count = int(item.get("entry", 0))
            exit_count = int(item.get("exit", 0))
 
            counts[camera_id] = {
                "entry": entry_count,
                "exit": exit_count
            }
 
            total_entry += entry_count
            total_exit += exit_count
 
        response_data = {
            "counts": counts,
            "total": {
                "entry": total_entry,
                "exit": total_exit
            }
        }
 
        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An unexpected error occurred."}),
            status_code=500
        )