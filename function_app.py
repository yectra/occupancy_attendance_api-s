import asyncio
import functools
import json
import logging
import random
import string
from natsort import natsorted
from dotenv import load_dotenv
from azure.cosmos import CosmosClient, exceptions 
from azure.storage.blob import BlobServiceClient, ContentSettings
import os
import uuid
from pydantic import BaseModel
from typing import List, Optional, Tuple, Literal
import base64
import numpy as np
import pendulum
import datetime
from datetime import datetime,date,timedelta
import isodate
import requests
import re
from datetime import timedelta
import jwt
from jwt import InvalidTokenError
from azure.functions import HttpRequest, HttpResponse
from jwt.algorithms import RSAAlgorithm
from functools import lru_cache, wraps
import logging
import json
import os
from jwt.exceptions import InvalidTokenError
import azure.functions as func
from typing import Dict, Any, Callable
from collections import defaultdict
from urllib.parse import quote
from azure.identity import ClientSecretCredential
from azure.core.exceptions import HttpResponseError
import urllib.parse
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, From, To
import time
from azure.cosmos import ContainerProxy
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Load environment variables from .env file
load_dotenv()

# Azure B2C configuration from .env
AZURE_B2C_AUTHORITY = os.getenv("AZURE_B2C_AUTHORITY")
AZURE_B2C_CLIENT_ID = os.getenv("AZURE_B2C_CLIENT_ID")
B2C_ISSUER = os.getenv("B2C_ISSUER")
B2C_OPENID_KEYS_ENDPOINT = os.getenv("B2C_OPENID_KEYS_ENDPOINT")

# Azure Cosmos DB configuration
COSMOS_CONNECTION_STRING = os.getenv('COSMOS_CONNECTION_STRING')
DATABASE_NAME = os.getenv('DATABASE_NAME')
EMPLOYEE_CONTAINER_NAME = os.getenv('EMPLOYEE_CONTAINER_NAME')
ATTENDANCE_CONTAINER_NAME = os.getenv('ATTENDANCE_CONTAINER_NAME')
ORGANIZATION_CONTAINER_NAME = os.getenv('ORGANIZATION_CONTAINER_NAME')
SETUP_CONTAINER_NAME = os.getenv('SETUP_CONTAINER_NAME')
CAMERA_URLS_CONTAINER_NAME = os.getenv('CAMERA_URLS_CONTAINER_NAME')
CAMERA_STATUS_CONTAINER_NAME=os.getenv('CAMERA_STATUS_CONTAINER_NAME')
CAMERA_STATUS_CONTAINER_NAME_ATTENDANCE=os.getenv('CAMERA_STATUS_CONTAINER_NAME_ATTENDANCE')
# Azure Blob Storage configuration
BLOB_CONNECTION_STRING = os.getenv('STORAGE_CONNECTION_STRING')
BLOB_CONTAINER_NAME = os.getenv('STORAGE_CONTAINER_NAME')


COUNTS_CONTAINER = os.getenv('COUNTS_CONTAINER')
SETUP_CONTAINER_NAME=os.getenv('SETUP_CONTAINER_NAME')
PERSON_FEATURE_CONTAINER=os.getenv('PERSON_FEATURE_CONTAINER')

# Azure B2C Configuration
TENANT_NAME = os.getenv('AZURE_B2C_TENANT_NAME')
POLICY_NAME = os.getenv('AZURE_B2C_POLICY_NAME')
CLIENT_ID = os.getenv('AZURE_B2C_CLIENT_ID')
TENANT_ID = os.getenv("AZURE_B2C_TENANT_ID")
CLIENT_SECRET = os.getenv("AZURE_B2C_CLIENT_SECRET")
# container(tracker)
USER_COUNTS=os.getenv('USER_COUNTS')
USER_LOGS=os.getenv('USER_LOGS')
USERS=os.getenv('USERS')

#notifications_email(sendgrid)
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY')
SENDGRID_TEMPLATE_ID = os.getenv('SENDGRID_TEMPLATE_ID')
FROM_EMAIL = os.getenv('FROM_EMAIL')

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Set the logging level to DEBUG

# Storage_blob_configs
STORAGE_ACCOUNT_NAME = os.getenv('STORAGE_ACCOUNT_NAME')
STORAGE_CONTAINER_NAME=os.getenv('STORAGE_CONTAINER_NAME')
# Initialize the Cosmos client
client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
database = client.get_database_client(DATABASE_NAME)
employee_container = database.get_container_client(EMPLOYEE_CONTAINER_NAME)
attendance_container = database.get_container_client(ATTENDANCE_CONTAINER_NAME)
camera_urls_container = database.get_container_client(CAMERA_URLS_CONTAINER_NAME)
organization_container_name = database.get_container_client(ORGANIZATION_CONTAINER_NAME) 
setup_container = database.get_container_client(SETUP_CONTAINER_NAME)
camera_status_container_attendance=database.get_container_client(CAMERA_STATUS_CONTAINER_NAME_ATTENDANCE)
 
  # Define attendance_container
camera_status_container = database.get_container_client(CAMERA_STATUS_CONTAINER_NAME)
setup_container_name = database.get_container_client(SETUP_CONTAINER_NAME)
counts_container = database.get_container_client(COUNTS_CONTAINER)
person_features =database.get_container_client(PERSON_FEATURE_CONTAINER)
user_counts_container = database.get_container_client(USER_COUNTS)
user_logs_container = database.get_container_client(USER_LOGS)
users_container=database.get_container_client(USERS)
# Initialize the Blob Service Client
blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)
blob_container_client = blob_service_client.get_container_client(BLOB_CONTAINER_NAME)

for var in ["AZURE_B2C_AUTHORITY", "AZURE_B2C_CLIENT_ID", "B2C_OPENID_KEYS_ENDPOINT"]:
    if not os.getenv(var):
        raise EnvironmentError(f"Missing required environment variable: {var}")

print('Successfully connected all the strings')


def get_openid_config():
    """Fetch OpenID configuration from Azure AD B2C"""
    response = requests.get(B2C_OPENID_KEYS_ENDPOINT)
    if response.status_code != 200:
        raise Exception("Failed to retrieve OpenID Configuration")
    return response.json()


def get_signing_keys():
    """Fetch signing keys from OpenID Connect endpoint"""
    openid_config = get_openid_config()
    jwks_uri = openid_config.get("jwks_uri")

    response = requests.get(jwks_uri)
    if response.status_code != 200:
        raise Exception("Failed to retrieve JWT signing keys")

    keys = response.json().get("keys", [])
    key_dict = {key["kid"]: RSAAlgorithm.from_jwk(json.dumps(key)) for key in keys}
    return key_dict

def decode_jwt(token: str):
    """Decode and validate JWT token, and determine if the user is Admin or Employee."""
    try:
        key_dict = get_signing_keys()
        headers = jwt.get_unverified_header(token)
        kid = headers.get("kid")

        if not kid or kid not in key_dict:
            raise InvalidTokenError("No matching key found for token")
        logging.info(f"Expected Issuer: {B2C_ISSUER}")

        # Decode token
        decoded_token = jwt.decode(
            token,
            key=key_dict[kid],
            algorithms=["RS256"],
            audience=AZURE_B2C_CLIENT_ID,
            issuer=B2C_ISSUER,
            leeway=200
        )

         # Log token issue time (iat) and current UTC time
        issue_time = datetime.utcfromtimestamp(decoded_token['iat'])
        current_time = datetime.utcnow()
        logging.info(f"Token issued at (iat): {issue_time}, Current UTC time: {current_time}")

        if issue_time > current_time:
            logging.warning(f"Token iat is in the future! Possible time sync issue.")

        return decoded_token
        

    except InvalidTokenError as e:
        logging.error(f"Token validation error: {str(e)}")
        raise




def validate_and_decode_token(req: func.HttpRequest) -> Dict[str, Any]:
    """Validates the JWT token from the request and decodes it.""" 
    logging.info(f"Authorization header: {req.headers.get('Authorization')}")  # Log the header

    # Extract token from header
    auth_header = req.headers.get("Authorization")

    if not auth_header:
        logging.error("No Authorization header found")
        raise ValueError("Authorization header is missing")
    
    # Validate Bearer token format
    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logging.error(f"Invalid Authorization header format: {auth_header}")
        raise ValueError("Invalid Authorization header format")
    
    token = parts[1]
    # Decode and validate the token
    try:
        decoded_token = decode_jwt(token)
        if not decoded_token.get('sub'):
            raise ValueError("Token missing required 'sub' claim")
        return decoded_token
    except Exception as e:
        logging.error(f"Token validation failed: {str(e)}")
        raise



def require_auth(func):
    @wraps(func)
    async def wrapper(req: HttpRequest) -> HttpResponse:
        try:
            # Validate and decode the token
            decoded_token = validate_and_decode_token(req)
            logging.info(f"Request is authorized. Token claims: {decoded_token}")
            
            # Attach user info to the request object
            req.user_info = {
                'user_id': decoded_token.get('sub'),
                'email': decoded_token.get('emails', [None])[0],
                'name': decoded_token.get('name'),
                'sub': decoded_token.get('sub'),
                'jobTitle': decoded_token.get('jobTitle'), 
                'token_claims': decoded_token
            }
            return await func(req)
        
        except Exception as e:
            logging.error(f"Unauthorized Request: {e}")
            return HttpResponse(
                json.dumps({"error": "Unauthorized: Invalid or expired token"}), 
                status_code=401,
                mimetype="application/json"
            )
    return wrapper

    
class CameraDetail(BaseModel):
    entranceName: str
    cameraPosition: Literal["inside-out", "outside-in"]
    videoUrl: str
    doorCoordinates: Optional[List[List[int]]] = None
 
class PageData(BaseModel):
    capacityOfPeople: int
    alertMessage: Literal["0-20", "20-40", "40-60", "60-80", "80-100"]
    documentId: str = None  # Optional for new entries
    cameraDetails: List[CameraDetail]  # Required field
 


# get employee
@app.function_name(name="get_employee")
@app.route(route='employee/{employee_id}', methods=[func.HttpMethod.GET])
@require_auth
async def get_employee(req: func.HttpRequest) -> func.HttpResponse:
    logging.info(f"Authorization Header: {req.headers.get('Authorization')}")  # Log authorization header

    employee_id = req.route_params.get('employee_id')
    if not employee_id:
        logging.error("Employee ID missing in request.")
        return func.HttpResponse(
            json.dumps({"warn": "Employee ID missing in request"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        query = "SELECT * FROM c WHERE c.employeeId = @employee_id"
        parameters = [{"name": "@employee_id", "value": str(employee_id)}]
        items = list(employee_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        if items:
            logging.info(f"Employee found: {items[0]}")
            return func.HttpResponse(
                json.dumps(items[0]),
                status_code=200,
                mimetype="application/json"
            )

        logging.warning(f"No employee found with ID: {employee_id}")
        return func.HttpResponse(
            json.dumps({'warn': 'Employee not found'}),
            status_code=404,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error fetching employee with ID {employee_id}: {str(e)}")
        return func.HttpResponse(
            json.dumps({'warn': "Internal server error"}),
            status_code=500,
            mimetype="application/json"
        )







# for attendance
# Pydantic model for camera details
class CameraDetail(BaseModel):
    entranceName: str
    cameraPosition: Literal["inside-out", "outside-in"]
    punchinUrl: str
    punchoutUrl: str

class CameraUrls(BaseModel):
    id: str
    cameraDetails: List[CameraDetail]



# Logs for the HTTP function route handling



    
                                # Fetch all employee records -getall
# @app.function_name(name="get_all_employees")
# @app.route(route='employees', methods=[func.HttpMethod.GET])
# @require_auth
# async def get_all_employees(req: func.HttpRequest) -> func.HttpResponse:
#     try:
#         logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")

#         # Proceed with the rest of the logic
#         page_number = int(req.params.get('page_number', 1))
#         page_size = int(req.params.get('page_size', 10))
#         offset = (page_number - 1) * page_size

#         query = "SELECT * FROM c"
#         all_items = list(employee_container.query_items(query=query, enable_cross_partition_query=True))
#         paginated_items = all_items[offset:offset + page_size]

#         return func.HttpResponse(
#             body=json.dumps(paginated_items),
#             status_code=200,
#             mimetype="application/json"
#         )
#     except Exception as e:
#         logging.error(f"Error fetching employees: {str(e)}")
#         return func.HttpResponse(
#             body=json.dumps({'error': str(e)}),
#             status_code=500,
#             mimetype="application/json"
#         )






                                           # Search bar Attendance

@app.function_name(name="search_bar_attendance")
@app.route(route='attendance/search', methods=[func.HttpMethod.GET])
@require_auth
async def search_attendance(req: func.HttpRequest) -> func.HttpResponse:
    try:
        user_sub = req.user_info.get("sub")  # Organization ID from token
        if not user_sub:
            return func.HttpResponse(
                body=json.dumps({'error': 'Invalid user token. Missing organization identifier.'}),
                status_code=401,
                mimetype="application/json"
            )

        # Parameters
        search_query = req.params.get('search')  # for employeeName or email
        period = req.params.get('period')        # today, yesterday, week, month
        start_date = req.params.get('start_date')
        end_date = req.params.get('end_date')
        employee_id = req.params.get('employeeId')  # new optional parameter
        specific_date = req.params.get('date')      # new optional parameter
        page_number = int(req.params.get('page_number', 1))
        page_size = int(req.params.get('page_size', 10))

        logging.info(f"Search Attendance for OrgID (sub): {user_sub}, Search: {search_query}, Period: {period}, Start: {start_date}, End: {end_date}, EmployeeID: {employee_id}, Date: {specific_date}")

        query_conditions = ["c.organizationId = @org_id"]
        parameters = [{"name": "@org_id", "value": user_sub}]

        if search_query:
            query_conditions.append("(CONTAINS(LOWER(c.employeeName), LOWER(@search)) OR CONTAINS(LOWER(c.email), LOWER(@search)))")
            parameters.append({"name": "@search", "value": search_query.lower()})

        if employee_id:
            query_conditions.append("c.employeeId = @employee_id")
            parameters.append({"name": "@employee_id", "value": employee_id})

        if specific_date:
            query_conditions.append("c.date = @specific_date")
            parameters.append({"name": "@specific_date", "value": specific_date})

        if period:
            today = datetime.utcnow().date()
            if period.lower() == "today":
                start = end = today
            elif period.lower() == "yesterday":
                start = end = today - timedelta(days=1)
            elif period.lower() == "week":
                start = today - timedelta(days=7)
                end = today
            elif period.lower() == "month":
                start = today - timedelta(days=30)
                end = today
            else:
                return func.HttpResponse(
                    body=json.dumps({'error': 'Invalid period. Use today, yesterday, week, or month.'}),
                    status_code=400,
                    mimetype="application/json"
                )
            query_conditions.append("c.date >= @start_date AND c.date <= @end_date")
            parameters.append({"name": "@start_date", "value": start.strftime("%Y-%m-%d")})
            parameters.append({"name": "@end_date", "value": end.strftime("%Y-%m-%d")})

        if start_date and end_date:
            query_conditions.append("c.date >= @custom_start AND c.date <= @custom_end")
            parameters.append({"name": "@custom_start", "value": start_date})
            parameters.append({"name": "@custom_end", "value": end_date})

        query = "SELECT * FROM c WHERE " + " AND ".join(query_conditions)
        query += " ORDER BY c.employeeId ASC"

        all_items = list(attendance_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        offset = (page_number - 1) * page_size
        paginated_items = all_items[offset:offset + page_size]

        return func.HttpResponse(
            body=json.dumps({
                "page_number": page_number,
                "page_size": page_size,
                "total_records": len(all_items),
                "data": paginated_items
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error during attendance search: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': 'Internal Server Error'}),
            status_code=500,
            mimetype="application/json"
        )









                                            # post emp






# Function to upload image to Azure Blob Storage
def upload_image_to_blob(base64_image, employee_id):
    """Uploads the base64 image to Azure Blob storage and returns the image URL."""
    try:
        # Log the base64 image received (limited to first 100 chars for security reasons)
        logging.info(f"Received base64 image for employee {employee_id}: {base64_image[:100]}...")

        # Check and remove the data URL prefix if present
        if "data:image/" in base64_image and ";base64," in base64_image:
            # Split the base64 string and get the actual encoded data
            image_format = base64_image.split(';')[0].split('/')[1]  # Extract the image format (e.g., jpeg, png)
            base64_image = base64_image.split(";base64,")[1]
        else:
            logging.error("Invalid base64 image data")
            return None

        logging.info(f"Base64 image cleaned: {base64_image[:100]}...")

        # Decode the base64 string into binary data
        image_data = base64.b64decode(base64_image)

        # Generate a unique blob name using the employee_id and UUID
        blob_name = f"{employee_id}/{str(uuid.uuid4())}.{image_format}"

        # Upload the image to the blob container
        blob_client = blob_container_client.get_blob_client(blob_name)

        # Upload the image with the correct content type based on format
        blob_client.upload_blob(image_data, blob_type="BlockBlob", content_type=f"image/{image_format}")

        # Generate the image URL
        blob_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net/{STORAGE_CONTAINER_NAME}/{blob_name}"

        logging.info(f"Image uploaded successfully for employee {employee_id}. Blob URL: {blob_url}")
        return blob_url

    except Exception as e:
        logging.error(f"Error uploading image for employee {employee_id} to blob: {e}")
        return None




def delete_image_from_blob(blob_url):
    """Delete image from blob storage with improved error handling."""
    if not blob_url:
        logging.warning("No blob URL provided for deletion")
        return

    try:
        logging.info(f"Attempting to delete blob with URL: {blob_url}")

        # Extract the blob name from the URL
        try:
            # Parse the URL to extract the blob name
            blob_name = blob_url.split(f"{STORAGE_CONTAINER_NAME}/")[1]
            logging.info(f"Extracted blob name for deletion: {blob_name}")
        except Exception as e:
            logging.error(f"Error parsing blob URL: {e}")
            return

        # Get the blob client and delete with retry logic
        max_retries = 3
        retry_count = 0
        while retry_count < max_retries:
            try:
                blob_client = blob_container_client.get_blob_client(blob_name)
                if blob_client.exists():
                    blob_client.delete_blob()
                    logging.info(f"Blob {blob_name} deleted successfully.")
                else:
                    logging.warning(f"Blob {blob_name} does not exist.")
                break
            except Exception as e:
                retry_count += 1
                if retry_count == max_retries:
                    logging.error(f"Failed to delete blob after {max_retries} attempts: {e}")
                    break
                logging.warning(f"Delete attempt {retry_count} failed: {e}")

    except Exception as e:
        logging.error(f"Error in delete_image_from_blob: {e}")






# # Allowed image formats
# ALLOWED_IMAGE_FORMATS = ('.jpg', '.jpeg', '.png', '.bmp')

# @app.function_name(name="add_employee")
# @app.route(route='employee', methods=[func.HttpMethod.POST])
# @require_auth
# async def add_employee(req: func.HttpRequest) -> func.HttpResponse:
#     try:
#         logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")
#         logging.info(f"User Info: {req.user_info}")

#         # Extract JSON data from the request body
#         json_data = req.get_json()

#         if not json_data:
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'JSON data is required in the request body'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Extract fields from the JSON data
#         employee_id = json_data.get('employeeId')
#         name = json_data.get('employeeName')
#         role = json_data.get('role')
#         email = json_data.get('email')
#         image_name = json_data.get('imageName')  # Image file name with extension

#         # Check if required fields are provided
#         if not employee_id or not name or not role or not email:
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'All fields except image are required'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Validate email format using regex
#         EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
#         if not re.match(EMAIL_REGEX, email):
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'Invalid email format'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Validate image format if image is provided
#         if image_name:
#             if not image_name.lower().endswith(ALLOWED_IMAGE_FORMATS):
#                 return func.HttpResponse(
#                     body=json.dumps({'error': f'Invalid image format. Allowed formats: {ALLOWED_IMAGE_FORMATS}'}),
#                     status_code=400,
#                     mimetype="application/json"
#                 )

#         # Get `organizationId` from token (same as `sub`)
#         organization_id = req.user_info.get('user_id')

#         if not organization_id:
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'Invalid token: organizationId (sub) missing'}),
#                 status_code=401,
#                 mimetype="application/json"
#             )

#         # Check if employeeId already exists in Cosmos DB
#         query = f"SELECT * FROM c WHERE c.employeeId = '{employee_id}'"
#         existing_employees = list(employee_container.query_items(query=query, enable_cross_partition_query=True))

#         if existing_employees:
#             return func.HttpResponse(
#                 body=json.dumps({'Warn': f'Employee with employeeId {employee_id} already exists'}),
#                 status_code=409,  # Conflict status code
#                 mimetype="application/json"
#             )

#         # Upload the image if provided (assuming upload_image_to_blob handles it)
#         image_url = upload_image_to_blob(json_data.get('imageBase64'), employee_id) if json_data.get('imageBase64') else None

#         # Create the employee record
#         employee_record = {
#             'id': str(uuid.uuid4()),
#             'employeeId': employee_id,
#             'employeeName': name,
#             'role': role,
#             'email': email,
#             'imageUrl': image_url,
#             'organizationId': organization_id,
#             'userId': organization_id
#         }

#         # Save the employee record in Cosmos DB
#         employee_container.create_item(body=employee_record)

#         return func.HttpResponse(
#             body=json.dumps({'message': 'Employee added successfully', 'data': employee_record}),
#             status_code=201,
#             mimetype="application/json"
#         )

#     except Exception as e:
#         logging.error(f"Error adding employee: {str(e)}")
#         return func.HttpResponse(
#             body=json.dumps({'error': str(e)}),
#             status_code=500,
#             mimetype="application/json"
#         )



                                                    # put function
# #Update Employee function (for PUT requests)
# @app.function_name(name="update_employee")
# @app.route(route="update-employee/{employee_id}", methods=[func.HttpMethod.PUT])
# @require_auth
# async def update_employee(req: func.HttpRequest) -> func.HttpResponse:
#     logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")
#     logging.info('Processing update employee request.')

#     try:
#         # Get employee ID from the route and validate
#         employee_id = str(req.route_params.get('employee_id'))
#         if not employee_id:
#             return func.HttpResponse(
#                 json.dumps({'warn': 'Employee ID is required'}), 
#                 status_code=400, 
#                 mimetype="application/json"
#             )

#         # Parse request body to get the update data
#         try:
#             data = req.get_json()
#         except ValueError:
#             return func.HttpResponse(
#                 json.dumps({'error': 'Invalid JSON in request body'}), 
#                 status_code=400, 
#                 mimetype="application/json"
#             )

#         logging.info(f"Processing update for employee ID: {employee_id}")

#         # Fetch the existing employee record from Cosmos DB
#         query = "SELECT * FROM c WHERE c.employeeId = @employeeId"
#         parameters = [{"name": "@employeeId", "value": employee_id}]
#         items = list(employee_container.query_items(
#             query=query,
#             parameters=parameters,
#             enable_cross_partition_query=True
#         ))

#         if not items:
#             return func.HttpResponse(
#                 json.dumps({'error': 'Employee not found'}), 
#                 status_code=404, 
#                 mimetype="application/json"
#             )

#         item = items[0]  # Existing employee record

#         # Handle image upload if new image is provided
#         new_image_base64 = data.get('newImageBase64')
#         if new_image_base64:  # Only process if a new image is provided
#             try:
#                 # Upload the new image and get its URL
#                 new_image_url = upload_image_to_blob(new_image_base64, employee_id)

#                 if new_image_url:
#                     # If there was a previous image, delete it
#                     if item.get('imageUrl'):
#                         delete_image_from_blob(item['imageUrl'])

#                     # Update the image URL in the employee record
#                     item['imageUrl'] = new_image_url
#                     logging.info(f"Updated image URL for employee {employee_id}: {new_image_url}")
#             except Exception as e:
#                 logging.error(f"Error handling image upload: {e}")
#                 return func.HttpResponse(
#                     json.dumps({'error': f'Error processing image: {str(e)}'}), 
#                     status_code=500, 
#                     mimetype="application/json"
#                 )
#         else:
#             logging.info(f"No new image provided. Keeping existing image URL: {item.get('imageUrl')}")

#         # Define the allowed fields
#         allowed_fields = {
#             "employeeName", "role", "email", "organizationId", "userId"
#         }
#         # Remove protected fields from the update data
#         protected_fields = {'id', '_rid', '_self', '_etag', '_attachments', '_ts', 'employeeId', 'newImageBase64'}
#         update_data = {k: v for k, v in data.items() if k in allowed_fields and k not in protected_fields}

#         # Update the existing employee record with new data
#         item.update(update_data)

#         # Replace the employee record in Cosmos DB
#         try:
#             employee_container.replace_item(
#                 item=item['id'],
#                 body=item
#             )
#             logging.info(f"Employee {employee_id} updated successfully.")
#         except exceptions.CosmosHttpResponseError as e:
#             logging.error(f"Error updating employee in Cosmos DB: {e}")

#             # Clean up the newly uploaded image in case of an error
#             if new_image_base64 and 'new_image_url' in locals():
#                 delete_image_from_blob(new_image_url)

#             return func.HttpResponse(
#                 json.dumps({'error': 'Failed to update employee record'}), 
#                 status_code=500, 
#                 mimetype="application/json"
#             )

#         # Return the updated employee data as the response
#         return func.HttpResponse(
#             json.dumps({
#                 'message': 'Employee updated successfully',
#                 'data': item
#             }),
#             status_code=200,
#             mimetype="application/json"
#         )

#     except Exception as e:
#         logging.error(f"Unexpected error in update_employee: {e}")
#         return func.HttpResponse(
#             json.dumps({'error': str(e)}),
#             status_code=500,
#             mimetype="application/json"
#         )


    
                    # Define the Azure Function for delete an employee

# @app.function_name(name="delete_employee")
# @app.route(route="employee/{employee_id}", methods=[func.HttpMethod.DELETE])
# def delete_employee(req: func.HttpRequest) -> func.HttpResponse:
#     # Validate and decode the token
#     try:
#         user_info = validate_and_decode_token(req)
#         logging.info(f"Token validated for user: {user_info.get('email', 'unknown')}")
#     except Exception as e:
#         logging.error(f"Unauthorized Request: {str(e)}")
#         return func.HttpResponse(
#             json.dumps({"error": "Unauthorized: Missing or Invalid Token"}),
#             status_code=401,
#             mimetype="application/json"
#         )

#     logging.info('Processing delete employee request.')

#     try:
#         # Get the employee ID from the route parameters
#         employee_id = req.route_params.get('employee_id')

#         # Query to fetch the employee record by id
#         query = f"SELECT * FROM c WHERE c.employeeId = '{employee_id}'"
#         logging.info(f"Query: {query}")
#         items = list(employee_container.query_items(query=query, enable_cross_partition_query=True))
#         logging.info(f"Items found: {items}")

#         if items:
#             item = items[0]  # Get the first (and expected only) result

#             # Delete the employee record from Cosmos DB
#             # Use the partition key and document id for deletion
#             employee_container.delete_item(item=item['id'], partition_key=item['id'])
#             return func.HttpResponse(
#                 body=json.dumps({'message': 'Employee deleted successfully'}),
#                 status_code=200,
#                 mimetype="application/json"
#             )

#         return func.HttpResponse(
#             body=json.dumps({'message': 'Employee not found'}),
#             status_code=404,
#             mimetype="application/json"
#         )
#     except Exception as e:
#         logging.error(f"Error deleting employee: {str(e)}")
#         return func.HttpResponse(
#             body=json.dumps({'error': str(e)}),
#             status_code=500,
#             mimetype="application/json"
#         )

    

    
                                # Attendance API's to GET all,date,id,page_number,page_size

def fetch_employee_image(employee_id):
    """Fetches the employee image URL based on the employee ID."""
    try:
        # Query to fetch employee record by employeeId
        query = "SELECT c.imageUrl FROM c WHERE c.employeeId = @employee_id"
        parameters = [{"name": "@employee_id", "value": employee_id}]
        
        # Execute the query
        items = list(employee_container.query_items(
            query=query, 
            parameters=parameters, 
            enable_cross_partition_query=True
        ))

        # Check if an employee record is found and return the imageUrl
        if items:
            return items[0].get('imageUrl')

        # If no record is found, return None
        return None

    except Exception as e:
        logging.error(f"Error fetching employee image for {employee_id}: {str(e)}")
        return None




@app.function_name(name="get_all_attendance")
@app.route(route='attendance/all', methods=[func.HttpMethod.GET])
@require_auth
async def get_all_attendance(req: func.HttpRequest) -> func.HttpResponse:
    """
    Retrieve attendance records by organizationId with optional filtering by employeeId, 
    a specific date, start_date/end_date, or predefined period (today, yesterday, week, month).
    Includes pagination and sorting by date (latest first).
    """
    logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")

    try:
        user_info = req.user_info
        organization_id = user_info.get("sub")

        if not organization_id:
            return func.HttpResponse(
                body=json.dumps({'error': 'Unauthorized. Missing organization ID.'}),
                status_code=401,
                mimetype="application/json"
            )

        # Pagination
        page_number = int(req.params.get('page_number', 1))
        page_size = int(req.params.get('page_size', 10))
        offset = (page_number - 1) * page_size

        # Filters
        employee_id = req.params.get('employeeId')
        start_date = req.params.get('start_date')
        end_date = req.params.get('end_date')
        period = req.params.get('period')  # today, yesterday, week, month
        specific_date = req.params.get('date')  # Exact date filter

        query = "SELECT * FROM c WHERE c.organizationId = @orgId"
        parameters = [{"name": "@orgId", "value": organization_id}]

        if employee_id:
            query += " AND c.employeeId = @employeeId"
            parameters.append({"name": "@employeeId", "value": employee_id})

        # If exact date is provided
        if specific_date:
            query += " AND c.date = @specificDate"
            parameters.append({"name": "@specificDate", "value": specific_date})

        # If predefined period is provided
        elif period:
            today = datetime.utcnow().date()

            if period.lower() == "today":
                start = end = today
            elif period.lower() == "yesterday":
                start = end = today - timedelta(days=1)
            elif period.lower() == "week":
                start = today - timedelta(days=7)
                end = today
            elif period.lower() == "month":
                start = today - timedelta(days=30)
                end = today
            else:
                return func.HttpResponse(
                    body=json.dumps({'error': 'Invalid period. Use today, yesterday, week, or month.'}),
                    status_code=400,
                    mimetype="application/json"
                )

            query += " AND c.date >= @startDate AND c.date <= @endDate"
            parameters.append({"name": "@startDate", "value": start.strftime("%Y-%m-%d")})
            parameters.append({"name": "@endDate", "value": end.strftime("%Y-%m-%d")})

        # If custom start and end dates are provided
        elif start_date and end_date:
            query += " AND c.date >= @startDate AND c.date <= @endDate"
            parameters.append({"name": "@startDate", "value": start_date})
            parameters.append({"name": "@endDate", "value": end_date})

        # Sort by date descending
        query += " ORDER BY c.date DESC"

        all_items = list(attendance_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        paginated_items = all_items[offset:offset + page_size]

        return func.HttpResponse(
            body=json.dumps({
                "page_number": page_number,
                "page_size": page_size,
                "total_records": len(all_items),
                "data": paginated_items
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error fetching attendance records: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': 'Internal Server Error'}),
            status_code=500,
            mimetype="application/json"
        )











# Helper function to upsert data into Cosmos DB
def upsert_document(data: dict):
    try:
        setup_container_name.upsert_item(data)
        logging.info(f"Document with ID {data['id']} upserted successfully.")
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Error upserting document: {str(e)}")
        raise Exception("Failed to save data to the database.")
 

 
 
    

    # SEARCH API for Employee


@app.function_name(name="search_employee")
@app.route(route='employees/search', methods=['GET'])
@require_auth
async def search_employee(req: func.HttpRequest) -> func.HttpResponse:
    """
    Search for employees by ID or name within a specific organization (based on sub in token).
    Includes pagination support.
    """
    logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")

    try:
        organization_id = req.user_info.get("sub")
        if not organization_id:
            return func.HttpResponse(
                body=json.dumps({'error': 'Unauthorized. Missing organization ID.'}),
                status_code=401,
                mimetype="application/json"
            )

        search = req.params.get('search', '').strip()
        if not search:
            return func.HttpResponse(
                body=json.dumps({'error': 'Missing search parameter'}),
                status_code=400,
                mimetype="application/json"
            )

        # Pagination
        page_number = int(req.params.get('page_number', 1))
        page_size = int(req.params.get('page_size', 10))
        offset = (page_number - 1) * page_size

        # Build base query
        query = (
            "SELECT c.employeeId, c.employeeName, c.role, c.email, c.dateOfJoining, c.imageUrl "
            "FROM c WHERE c.organizationId = @orgId"
        )
        parameters = [{"name": "@orgId", "value": organization_id}]

        if search.isnumeric():
            query += " AND c.employeeId = @searchId"
            parameters.append({"name": "@searchId", "value": search})
        else:
            query += (
                " AND (CONTAINS(LOWER(c.employeeName), LOWER(@search)) "
                "OR CONTAINS(LOWER(c.firstName), LOWER(@search)) "
                "OR CONTAINS(LOWER(c.lastName), LOWER(@search)))"
            )
            parameters.append({"name": "@search", "value": search.lower()})

        logging.info(f"Employee search query: {query}")

        items = list(employee_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        paginated_items = items[offset:offset + page_size]

        return func.HttpResponse(
            body=json.dumps({
                "page_number": page_number,
                "page_size": page_size,
                "total_records": len(items),
                "employees": paginated_items
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error during employee search: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': 'Internal Server Error'}),
            status_code=500,
            mimetype="application/json"
        )





# post method to give camera details -attendance
# Function to get camera data by id
def get_camera_data_by_id(camera_id: str):
    try:
        # Query the container to get the camera data by id
        query = f"SELECT * FROM c WHERE c.id = '{camera_id}'"
        items = list(camera_urls_container.query_items(query, enable_cross_partition_query=True))
        
        if items:
            return items[0]  # Return the first match (assuming id is unique)
        else:
            return None  # No data found for the given id
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Error retrieving camera data: {str(e)}")
        return None

@app.function_name(name="saveattendanceCameraUrl")
@app.route(route='api/cameraUrl', methods=[func.HttpMethod.POST])
@require_auth
async def saveCameraUrls(req: func.HttpRequest) -> func.HttpResponse:
    EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    ALLOWED_URL_SCHEMES = {"http", "https", "rtsp"}

    try:
        logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")

        # Extract organizationId (same as sub/user_id)
        organization_id = req.user_info.get('user_id')
        if not organization_id:
            return func.HttpResponse(
                json.dumps({'warn': 'Invalid token: organizationId (sub) missing'}),
                status_code=401,
                mimetype="application/json"
            )

        # Parse the incoming JSON data
        req_body = req.get_json()

        # Extract and validate email
        email = req_body.get("email") or req.user_info.get("email", "")
        if not email or not re.match(EMAIL_REGEX, email):
            return func.HttpResponse(
                json.dumps({"warn": "Invalid email format."}),
                status_code=400
            )

        # Extract and validate `cameraDetails`
        new_camera_details = req_body.get("cameraDetails", [])
        if not new_camera_details or not isinstance(new_camera_details, list):
            return func.HttpResponse(
                json.dumps({"warn": "Missing or invalid field: 'cameraDetails'."}),
                status_code=400
            )

        # Query existing records for the organization
        query = f"SELECT * FROM c WHERE c.organizationId = '{organization_id}'"
        existing_records = list(camera_urls_container.query_items(query=query, enable_cross_partition_query=True))

        # Determine next cameraId
        existing_camera_ids = []
        if existing_records:
            for record in existing_records:
                existing_camera_ids.extend([cam.get("cameraId", 0) for cam in record.get("cameraDetails", [])])

        next_camera_id = max(existing_camera_ids, default=0) + 1  # Increment the highest cameraId

        validated_camera_details = []
        for detail in new_camera_details:
            required_keys = ["punchinCamera", "punchinUrl", "punchoutCamera", "punchoutUrl"]
            if not all(key in detail for key in required_keys):
                return func.HttpResponse(
                    json.dumps({"warn": f"Each item in 'cameraDetails' must contain {required_keys}."}),
                    status_code=400
                )

            # Validate punch-in and punch-out URLs
            for key in ["punchinUrl", "punchoutUrl"]:
                url = detail[key]
                if not any(url.startswith(scheme + "://") for scheme in ALLOWED_URL_SCHEMES):
                    return func.HttpResponse(
                        json.dumps({"warn": f"Invalid {key} format. Allowed formats: {', '.join(ALLOWED_URL_SCHEMES)}."}),
                        status_code=400
                    )

            validated_camera_details.append({
                "cameraId": next_camera_id,
                "punchinCamera": detail["punchinCamera"],
                "punchinUrl": detail["punchinUrl"],
                "punchoutCamera": detail["punchoutCamera"],
                "punchoutUrl": detail["punchoutUrl"]
            })
            next_camera_id += 1  # Increment for each new camera

        if existing_records:
            # Update the existing record - Append new camera details
            existing_record = existing_records[0]
            existing_record["email"] = email  # Update email at root level
            existing_record["cameraDetails"].extend(validated_camera_details)  # Append new cameras

            upsert_camera_urls(existing_record)
            response_message = {"message": "Camera URLs updated successfully.", "id": existing_record["id"]}
        else:
            # Insert new record with `organizationId`
            camera_id = str(uuid.uuid4())
            camera_data = {
                "id": camera_id,
                "organizationId": organization_id,  # Map to the organization
                "email": email,  # Store email at root level
                "cameraDetails": validated_camera_details
            }
            upsert_camera_urls(camera_data)
            response_message = {"message": "Camera URLs saved successfully.", "id": camera_id}

        return func.HttpResponse(json.dumps(response_message), status_code=200)

    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": "An error occurred during processing."}),
            status_code=500
        )




def get_camera_record_by_email(email: str):
    query = f"SELECT * FROM c WHERE ARRAY_CONTAINS(c.cameraDetails1, {{'email': '{email}'}}, true)"
    items = list(camera_urls_container.query_items(query=query, enable_cross_partition_query=True))
    return items[0] if items else None

def upsert_camera_urls(camera_data):
    # Assuming camera_urls_container is your Cosmos DB container
    # Upsert the item directly as a dictionary
    camera_urls_container.upsert_item(camera_data)



# PUT method to update camera URL - Attendance
@app.function_name(name="updateCameraUrl")
@app.route(route='api/editcameraUrl', methods=[func.HttpMethod.PUT])
@require_auth
async def updateCameraUrls(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Validate and decode the token
        logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")
    except Exception as e:
        logging.error(f"Unauthorized Request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": "Unauthorized: Missing or Invalid Token"}),
            status_code=401,
            mimetype="application/json"
        )

    try:
        # Parse the incoming JSON data
        req_body = req.get_json()
        
        # Get the camera ID
        camera_id = req_body.get("id")
        
        if not camera_id:
            return func.HttpResponse(
                json.dumps({"warn": "Missing required field: 'id'."}),
                status_code=400
            )
        
        # Extract new camera details
        camera_details = req_body.get("cameraDetails", [])

        if not camera_details:
            return func.HttpResponse(
                json.dumps({"warn": "Missing required field: 'cameraDetails'."}),
                status_code=400
            )

        # Fetch existing camera data
        existing_data = get_camera_data_by_id(camera_id)

        if not existing_data:
            return func.HttpResponse(
                json.dumps({"warn": f"No camera data found for ID: {camera_id}."}),
                status_code=404
            )

        # Retain the existing email if a new one is not provided
        existing_email = existing_data.get("email", "")
        new_email = req_body.get("email", existing_email)

        # Define the allowed fields for cameraDetails
        allowed_fields = {"punchinCamera", "punchinUrl", "punchoutCamera", "punchoutUrl"}

        # Validate and clean up camera details
        validated_camera_details = []
        for detail in camera_details:
            if not isinstance(detail, dict):
                return func.HttpResponse(
                    json.dumps({"warn": "Invalid format in 'cameraDetails'. Expected list of objects."}),
                    status_code=400
                )

            # Filter only allowed fields
            filtered_detail = {key: value for key, value in detail.items() if key in allowed_fields}

            # Ensure all required fields exist
            if set(filtered_detail.keys()) != allowed_fields:
                return func.HttpResponse(
                    json.dumps({"warn": "Invalid or missing fields in 'cameraDetails'. Only specific fields are allowed."}),
                    status_code=400
                )

            validated_camera_details.append(filtered_detail)

        # Update the existing camera data with cleaned camera details and email
        existing_data["cameraDetails"] = validated_camera_details
        existing_data["email"] = new_email  # Ensure email is outside cameraDetails

        # Upsert the updated camera URLs into Cosmos DB
        upsert_camera_urls(existing_data)

        return func.HttpResponse(
            json.dumps({"detail": "Camera details updated successfully."}),
            status_code=200
        )

    except ValueError:
        return func.HttpResponse(
            json.dumps({"warn": "Invalid JSON format."}),
            status_code=400
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"warn": str(e)}),
            status_code=500
        )


# GET method to retrieve camera URL by ID -attendance
@app.function_name(name="attendanceGetCameraUrlById")
@app.route(route='api/cameraUrl', methods=[func.HttpMethod.GET])
@require_auth
async def getCameraUrlById(req: func.HttpRequest) -> func.HttpResponse:
    # Log the validated user's email
    logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")

    try:
        # Extract 'id' from query parameters
        camera_id = req.params.get("id")

        # Check if the 'id' key is present
        if not camera_id:
            return func.HttpResponse(
                json.dumps({"warn": "Missing required parameter: 'id'."}),
                status_code=400
            )

        # Fetch camera data from Cosmos DB
        camera_data = get_camera_by_id(camera_id)

        # Return the response
        return func.HttpResponse(
            json.dumps(camera_data),
            status_code=200,
            mimetype="application/json"
        )
    except exceptions.CosmosResourceNotFoundError:
        return func.HttpResponse(
            json.dumps({"warn": "Camera details not found for the provided ID."}),
            status_code=404
        )
    except Exception as e:
        logging.error(f"Error retrieving camera details: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": "An error occurred while retrieving the data."}),
            status_code=500
        )

# Fetch the camera data from Cosmos DB by ID
def get_camera_by_id(camera_id):
    return camera_urls_container.read_item(item=camera_id, partition_key=camera_id)






@app.function_name(name="add_organization")
@app.route(route="organization", methods=[func.HttpMethod.POST])
@require_auth
async def add_organization(req: func.HttpRequest) -> func.HttpResponse:
    logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")
    logging.info(f"User Info: {req.user_info}")

    try:
        json_data = req.get_json()
        if not json_data:
            return func.HttpResponse(
                json.dumps({'warn': 'JSON data is required in the request body'}),
                status_code=400,
                mimetype="application/json"
            )

        # Extract organization details
        organization_name = json_data.get('organizationName')
        phone_number = json_data.get('phoneNumber')
        website_url = json_data.get('websiteUrl')
        # address = json_data.get('address')
        street = json_data.get('street')
        city = json_data.get('city')
        state = json_data.get('state')
        zip_code = json_data.get('zipCode')
        country = json_data.get('country')
        work_timing = json_data.get('workTiming')  # Extract workTiming
        
        try:
             # Convert workTiming to an integer if provided
            work_timing = int(work_timing) if work_timing else None
            if work_timing is not None and (work_timing < 0 or work_timing > 24):
                return func.HttpResponse(
                    json.dumps({'warn': 'workTiming must be between 0 and 24 hours'}),
                    status_code=400,
                    mimetype="application/json"
                )
        except ValueError:
            return func.HttpResponse(
                json.dumps({'warn': 'workTiming must be a valid integer'}),
                status_code=400,
                mimetype="application/json"
            )

        # Validate required fields
        if not organization_name:
            return func.HttpResponse(
                json.dumps({'warn': 'Organization name is mandatory'}),
                status_code=400,
                mimetype="application/json"
            )


        # Validate phone number (only digits with optional + at the beginning, 10-15 digits)
        phone_number_pattern = r'^\+?\d{10,15}$'
        if phone_number and not re.match(phone_number_pattern, phone_number):
            return func.HttpResponse(
                json.dumps({'warn': 'Invalid phone number. Must be 10-15 digits, with optional + at the start.'}),
                status_code=400,
                mimetype="application/json"
            )

        # Validate website URL format
        valid_domain_pattern = r'^(https?://)?(www\.)?[\w-]+\.(com|net|org|io|co|edu|gov|info|biz|dev|app|in)$'
        if website_url:
            if not re.match(valid_domain_pattern, website_url):
                return func.HttpResponse(
                    json.dumps({'warn': 'Invalid website URL format. Must be like https://example.com'}),
                    status_code=400,
                    mimetype="application/json"
                )

        # Extra check: Prevent repeated TLDs like '.in.in'
        tld_repetition_pattern = r'\.(com|net|org|io|co|edu|gov|info|biz|dev|app|in)\.\1$'
        if re.search(tld_repetition_pattern, website_url):
            return func.HttpResponse(
                json.dumps({'warn': 'Invalid website URL: repeated TLDs are not allowed'}),
                status_code=400,
                mimetype="application/json"
            )

        # Use `sub` (user_id) as the `id` and `organizationId`
        organization_id = req.user_info.get('user_id')
        if not organization_id:
            return func.HttpResponse(
                json.dumps({'warn': 'Invalid token: user ID (sub) missing'}),
                status_code=401,
                mimetype="application/json"
            )

        # Check if an organization with the same name exists (case-insensitive)
        query = "SELECT * FROM c WHERE LOWER(c.organizationName) = @organizationName"
        parameters = [{"name": "@organizationName", "value": organization_name.lower()}]

        existing_organizations = list(organization_container_name.query_items(
            query=query, parameters=parameters, enable_cross_partition_query=True
        ))

        if existing_organizations:
            return func.HttpResponse(
                json.dumps({'warn': 'Organization name already exists'}),
                status_code=409,
                mimetype="application/json"
            )

        # Create or update organization record
        organization_record = {
            'id': organization_id,
            'organizationId': organization_id,
            'organizationName': organization_name,
            'phoneNumber': phone_number,
            'websiteUrl': website_url,
            # 'address': address,
            'street': street,
            'city': city,
            'state': state,
            'zipCode': zip_code,
            'country': country,
            'workTiming': work_timing,  # Store as an integer
            'createdAt': datetime.utcnow().isoformat(),
        }

        required_fields = [street, city, state, zip_code, country]
        if not all(required_fields):
            return func.HttpResponse(
                json.dumps({'warn': 'All address fields (street, city, state, zipCode, country) are required'}),
                status_code=400,
                mimetype="application/json"
            )


        # Use `upsert_item()` to avoid conflicts
        organization_container_name.upsert_item(organization_record)

        return func.HttpResponse(
            json.dumps({'message': 'Organization added successfully', 'organizationId': organization_id}),
            status_code=201,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error adding organization: {str(e)}")
        return func.HttpResponse(
            json.dumps({'warn': 'Internal Server Error'}),
            status_code=500,
            mimetype="application/json"
        )





# tracker api's



def upsert_document(container, data: dict):
    try:
        container.upsert_item(data)
        logging.info(f"Document with ID {data['id']} upserted successfully.")
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Error upserting document: {str(e)}")
        raise Exception("Failed to save data to the database.")

from urllib.parse import quote
 
@lru_cache(maxsize=1)
def get_jwks_uri():
    """Get the JWKS URI from Azure B2C OpenID configuration."""
    try:
        tenant_name = os.getenv('AZURE_B2C_TENANT_NAME')
        policy_name = os.getenv('AZURE_B2C_POLICY_NAME')
       
        tenant_domain = tenant_name.replace(' ', '')
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
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
       
        if not kid:
            logging.error("No 'kid' found in token header")
            return None
       
        public_keys = get_public_keys()
        if not public_keys or kid not in public_keys:
            logging.error("Unable to find appropriate public key")
            return None
       
        decoded_token = jwt.decode(
            token,
            key=public_keys[kid],
            algorithms=['RS256'],
            audience=CLIENT_ID,
            verify=True,
            options={
                'verify_iss': False
            }
        )
       
        if not all(k in decoded_token for k in ['sub', 'exp']):
            logging.error("Missing required claims in token")
            return None
       
        token_issuer = decoded_token['iss'].lower()
        tenant_name = os.getenv('AZURE_B2C_TENANT_NAME').lower()
       
        if tenant_name not in token_issuer:
            logging.error(f"Invalid token issuer. Expected tenant '{tenant_name}' not found in issuer: {token_issuer}")
            return None
       
        return {
            'user_id': decoded_token.get('sub'),
            'email': decoded_token.get('emails', [None])[0],
            'name': decoded_token.get('name'),
            'sub': decoded_token.get('sub')  # Added sub claim for organization_id
        }
       
    except jwt.exceptions.InvalidTokenError as e:
        logging.error(f"Invalid token: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error during token validation: {str(e)}")
        return None
 
def require_auth(func):
    @functools.wraps(func)
    async def wrapper(req: HttpRequest) -> HttpResponse:
        auth_header = req.headers.get('Authorization')
        if not auth_header:
            return HttpResponse(
                json.dumps({"warn": "Authorization token is required."}),
                status_code=401
            )
 
        try:
            if not auth_header.startswith('Bearer '):
                return HttpResponse(
                    json.dumps({"warn": "Invalid authorization header format. Must start with 'Bearer'."}),
                    status_code=401
                )
 
            token = auth_header[7:]
            if not token:
                return HttpResponse(
                    json.dumps({"warn": "Token not found in authorization header."}),
                    status_code=401
                )
 
            user_info = validate_jwt_token(token)
            if not user_info:
                return HttpResponse(
                    json.dumps({"warn": "Invalid token."}),
                    status_code=401
                )
 
            req.user_info = user_info
            return await func(req)
 
        except Exception as e:
            logging.error(f"Authentication error: {str(e)}")
            return HttpResponse(
                json.dumps({"warn": "Authentication failed."}),
                status_code=500
            )
 
    return wrapper
 
 
def upsert_document(container, data: dict):
    try:
        container.upsert_item(data)
        logging.info(f"Document with ID {data['id']} upserted successfully.")
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Error upserting document: {str(e)}")
        raise Exception("Failed to save data to the database.")
 
@app.function_name(name="saveData")
@app.route(route='api/saveData', methods=[func.HttpMethod.POST])
@require_auth
async def authenticated_save_data(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    try:
        req_body = req.get_json()
        data = PageData(**req_body)
        user_id = user_info['user_id']
        organization_id = user_info['sub']
 
        # Check if data for this organization already exists
        query = "SELECT * FROM c WHERE c.organization_id = @organization_id"
        parameters = [{"name": "@organization_id", "value": organization_id}]
       
        existing_items = list(setup_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        if existing_items:
            # If data already exists, return a message to use edit API instead
            return func.HttpResponse(
                json.dumps({
                    "warn": "Data already exists. Use the edit API to update.",
                    "documentId": existing_items[0]["id"]
                }),
                status_code=409
            )
        else:
            document_id = str(uuid.uuid4())
            document = {
                "id": document_id,
                "user_id": user_id,
                "organization_id": organization_id,
                "capacityOfPeople": data.capacityOfPeople,
                "alertMessage": data.alertMessage,  # Changed to alertMessage
                "cameraDetails": [camera.dict() for camera in data.cameraDetails]
                # Removed counts, persons, logs
            }
           
            # Insert the new document
            setup_container.create_item(body=document)
           
            return func.HttpResponse(
                json.dumps({
                    "message": "Data saved successfully.",
                    "documentId": document_id
                }),
                status_code=201
            )
 
    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": f"An error occurred during processing: {str(e)}"}),
            status_code=500
        )
 
 
 
 
# Adding missing functions:
 
@app.function_name(name="getCameraUrlsTracker")
@app.route(route='api/getCameraUrls', methods=[func.HttpMethod.GET])
@require_auth
async def getCameraUrls(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    user_id = user_info['sub']
   
    # Initialize containers
    users_container = database.get_container_client(USERS)
   
    try:
        # First check users container
        user_query = "SELECT c.organization_id FROM c WHERE c.azure_b2c_id = @user_id"
        user_params = [{"name": "@user_id", "value": user_id}]
       
        user_items = list(users_container.query_items(
            query=user_query,
            parameters=user_params,
            enable_cross_partition_query=True
        ))
       
        # Determine organization_id to use
        if user_items and len(user_items) > 0 and 'organization_id' in user_items[0]:
            organization_id = user_items[0]['organization_id']
        else:
            # Fallback to using sub directly as organization_id
            organization_id = user_id
 
        # Query setup-details with the determined organization_id
        query = "SELECT c FROM c WHERE c.organization_id = @organization_id"
        parameters = [{"name": "@organization_id", "value": organization_id}]
       
        items = list(setup_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
       
        if items:
            # Get the document
            doc = items[0]
           
            # Check if 'c' key exists in the document
            if 'c' in doc:
                c_data = doc['c']
                filtered_data = {
                    "capacityOfPeople": c_data.get("capacityOfPeople"),
                    "alertMessage": c_data.get("alertMessage"),
                    "cameraDetails": c_data.get("cameraDetails")
                }
            else:
                # Directly access the fields if 'c' doesn't exist
                filtered_data = {
                    "capacityOfPeople": doc.get("capacityOfPeople"),
                    "alertMessage": doc.get("alertMessage"),
                    "cameraDetails": doc.get("cameraDetails")
                }
           
            # Return data with the "data" key
            return func.HttpResponse(
                json.dumps({"data": filtered_data}),
                status_code=200
            )
        else:
            # No data found for this organization
            return func.HttpResponse(
                json.dumps({"data": {}}),
                status_code=200
            )
   
    except Exception as e:
        logging.error(f"Error retrieving data: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": "An error occurred while retrieving the data."}),
            status_code=500
        )
   
 
@app.function_name(name="getPersonDetectionOverTime")
@app.route(route='api/getPersonDetectionOverTime', methods=[func.HttpMethod.GET])
@require_auth
async def get_person_detection_over_time(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    user_id = user_info['sub']
 
    # Initialize containers
    users_container = database.get_container_client(USERS)
   
    try:
        # First check users container for organization_id
        user_query = "SELECT c.organization_id FROM c WHERE c.azure_b2c_id = @user_id"
        user_params = [{"name": "@user_id", "value": user_id}]
       
        user_items = list(users_container.query_items(
            query=user_query,
            parameters=user_params,
            enable_cross_partition_query=True
        ))
       
        # Determine organization_id to use
        if user_items and len(user_items) > 0 and 'organization_id' in user_items[0]:
            organization_id = user_items[0]['organization_id']
        else:
            # Fallback to using sub directly as organization_id
            organization_id = user_id
 
        # Query to get capacity from setup container using organization_id
        capacity_query = """
        SELECT c.capacityOfPeople
        FROM c
        WHERE c.organization_id = @organization_id
        """
        parameters = [{"name": "@organization_id", "value": organization_id}]
       
        setup_items = list(setup_container.query_items(
            query=capacity_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        if not setup_items:
            return func.HttpResponse(
                json.dumps({"data": []}),
                status_code=200
            )
 
        capacity = setup_items[0].get("capacityOfPeople", 0)
        if capacity == 0:
            return func.HttpResponse(
                json.dumps({"error": "Capacity not set or is zero"}),
                status_code=400
            )
 
        # Query to get person logs and manual adjustments from user_logs table using organization_id
        logs_query = """
        SELECT c.logs, c.manual_adjustments
        FROM c
        WHERE c.user_id = @organization_id
        """
       
        logs_items = list(user_logs_container.query_items(
            query=logs_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        if not logs_items or ("logs" not in logs_items[0] and "manual_adjustments" not in logs_items[0]):
            return func.HttpResponse(
                json.dumps({"data": []}),
                status_code=200
            )
 
        # Dictionary to count entries and exits per hour per camera
        entry_counts_by_hour = defaultdict(lambda: defaultdict(int))
        exit_counts_by_hour = defaultdict(lambda: defaultdict(int))
        # Dictionary to aggregate manual adjustments by date
        manual_adjustments_by_date = defaultdict(lambda: {"entries": 0, "exits": 0})
       
        # Process logs and group by hour
        logs = logs_items[0].get("logs", [])
        for log in logs:
            timestamp = log.get("timestamp")
            camera_id = log.get("camera_id")
            event_type = log.get("event_type")
 
            if timestamp and camera_id and event_type:
                try:
                    # Convert timestamp to pendulum and truncate to hour
                    dt = pendulum.parse(timestamp)
                    dt = dt.start_of('hour')
                    hour_key = dt.format('YYYY-MM-DD HH')
                   
                    if event_type == "person_entry":
                        entry_counts_by_hour[hour_key][camera_id] += 1
                    elif event_type == "person_exit":
                        exit_counts_by_hour[hour_key][camera_id] += 1
                except Exception as parse_error:
                    logging.warning(f"Failed to parse timestamp {timestamp}: {str(parse_error)}")
                    continue
 
        # Process manual adjustments and group by date
        manual_adjustments = logs_items[0].get("manual_adjustments", [])
        manual_adjustment_dates = set()
        for adjustment in manual_adjustments:
            date = adjustment.get("date")
            entries = adjustment.get("entries", 0)
            exits = adjustment.get("exits", 0)
            if date:
                try:
                    # Validate date format
                    pendulum.from_format(date, 'YYYY-MM-DD')
                    manual_adjustments_by_date[date]["entries"] += entries
                    manual_adjustments_by_date[date]["exits"] += exits
                    manual_adjustment_dates.add(date)
                except Exception as parse_error:
                    logging.warning(f"Failed to parse manual adjustment date {date}: {str(parse_error)}")
                    continue
 
        # Get all hour keys from camera logs
        all_hour_keys = set(entry_counts_by_hour.keys()) | set(exit_counts_by_hour.keys())
       
        # Create time series data dictionary by date and hour
        time_series_by_date_hour = {}
       
        # Process camera logs
        for hour_key in all_hour_keys:
            try:
                dt = pendulum.from_format(hour_key, 'YYYY-MM-DD HH')
                date_key = dt.format('YYYY-MM-DD')
                camera_counts = {}
                total_entries = 0
                total_exits = 0
               
                # Get all camera IDs for this hour
                all_cameras = set(entry_counts_by_hour[hour_key].keys()) | set(exit_counts_by_hour[hour_key].keys())
               
                # Calculate net count for each camera
                for camera_id in all_cameras:
                    entries = entry_counts_by_hour[hour_key][camera_id]
                    exits = exit_counts_by_hour[hour_key][camera_id]
                    net_count = entries - exits
                   
                    camera_counts[camera_id] = net_count
                    total_entries += entries
                    total_exits += exits
               
                total_count = total_entries - total_exits
               
                # Create hour range
                next_hour = dt.add(hours=1)
                hour_range = f"{dt.format('h:mm A')} - {next_hour.format('h:mm A')}"
               
                time_series_by_date_hour[(date_key, hour_range)] = {
                    "date": date_key,
                    "hour_range": hour_range,
                    "total_person_count": total_count,
                    "camera_counts": camera_counts,
                    "percentage": 0  # Will be updated after adding manual adjustments
                }
            except Exception as format_error:
                logging.error(f"Failed to format hour_key {hour_key}: {str(format_error)}")
                continue
 
        # Add manual adjustments to existing entries or create new ones
        for date in manual_adjustment_dates:
            try:
                dt = pendulum.from_format(date, 'YYYY-MM-DD')
                # Use a default hour (e.g., 12 AM) for dates with only manual adjustments
                default_hour = dt.start_of('day')
                next_hour = default_hour.add(hours=1)
                default_hour_range = f"{default_hour.format('h:mm A')} - {next_hour.format('h:mm A')}"
               
                # Check if this date has any camera logs
                existing_hours = {hr for (d, hr) in time_series_by_date_hour.keys() if d == date}
               
                if existing_hours:
                    # Add manual adjustments to all existing hours for this date
                    for hour_range in existing_hours:
                        if (date, hour_range) in time_series_by_date_hour:
                            time_series_by_date_hour[(date, hour_range)]["total_person_count"] += (
                                manual_adjustments_by_date[date]["entries"] -
                                manual_adjustments_by_date[date]["exits"]
                            )
                else:
                    # Create a new entry for this date with manual adjustments only
                    time_series_by_date_hour[(date, default_hour_range)] = {
                        "date": date,
                        "hour_range": default_hour_range,
                        "total_person_count": (
                            manual_adjustments_by_date[date]["entries"] -
                            manual_adjustments_by_date[date]["exits"]
                        ),
                        "camera_counts": {},
                        "percentage": 0
                    }
            except Exception as format_error:
                logging.error(f"Failed to process manual adjustment date {date}: {str(format_error)}")
                continue
 
        # Calculate percentages and prepare final time series data
        time_series_data = []
        for entry in time_series_by_date_hour.values():
            total_count = entry["total_person_count"]
            percentage = (total_count / capacity * 100) if capacity > 0 else 0
            entry["percentage"] = round(percentage, 2)
            time_series_data.append(entry)
 
        # Sort data by datetime
        time_series_data.sort(key=lambda x: pendulum.from_format(
            f"{x['date']} {x['hour_range'].split(' - ')[0]}",
            'YYYY-MM-DD h:mm A'
        ))
 
        return func.HttpResponse(
            json.dumps({
                "data": time_series_data
            }),
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
async def get_all_counts(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    if not user_info or 'sub' not in user_info:
        logging.error("Missing or invalid user_info in request")
        return func.HttpResponse(
            json.dumps({"status": "error", "detail": "Unauthorized: Missing user information"}),
            mimetype="application/json",
            status_code=401
        )
 
    user_id = user_info['sub']
    logging.info(f"Fetching counts for user_id: {user_id}")
 
    try:
        # Get organization_id
        user_query = "SELECT c.organization_id FROM c WHERE c.azure_b2c_id = @user_id"
        user_params = [{"name": "@user_id", "value": user_id}]
        user_items = list(users_container.query_items(
            query=user_query,
            parameters=user_params,
            enable_cross_partition_query=True
        ))
        organization_id = user_items[0]['organization_id'] if user_items and 'organization_id' in user_items[0] else user_id
 
        # Query counts
        counts_query = "SELECT c.cameras, c.last_updated FROM c WHERE c.user_id = @org_id"
        parameters = [{"name": "@org_id", "value": organization_id}]
        count_items = list(user_counts_container.query_items(
            query=counts_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        # Query manual adjustments
        logs_query = "SELECT c.manual_adjustments FROM c WHERE c.user_id = @org_id"
        logs_items = list(user_logs_container.query_items(
            query=logs_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        # Initialize response data
        camera_counts = {}
        total_current_count = 0
        total_manual_entries = 0
        total_manual_exits = 0
 
        # Process camera counts
        if count_items:
            cameras_data = count_items[0].get("cameras", {})
            for camera_id, camera_data in cameras_data.items():
                entry = camera_data.get("entry_count", 0)
                exit = camera_data.get("exit_count", 0)
                current_count = entry - exit
                camera_counts[camera_id] = {
                    "entry": entry,
                    "exit": exit,
                    "current_count": current_count,
                    "last_updated": camera_data.get("timestamp", "")
                }
                total_current_count += current_count
 
        # Process manual adjustments
        if logs_items and "manual_adjustments" in logs_items[0]:
            manual_adjustments = logs_items[0].get("manual_adjustments", [])
            for adjustment in manual_adjustments:
                entries = adjustment.get("entries", 0)
                exits = adjustment.get("exits", 0)
                total_manual_entries += entries
                total_manual_exits += exits
                total_current_count += (entries - exits)
 
        # Get alert info
        alert_flag, capacity, alert_message, occupancy_percentage = get_alert_info(
            organization_id, total_current_count, setup_container
        )
 
        # Prepare response
        response_data = {
            "data": {
                "camera_counts": camera_counts,
                "Manual Adjustments": {
                    "entry": total_manual_entries,
                    "exit": total_manual_exits,
                    "current_count": total_manual_entries - total_manual_exits
                },
                "total": {
                    "current_count": total_current_count,
                    "percentage": occupancy_percentage,
                    "alert": alert_flag,
                    "capacity": capacity,
                    "alert_message": alert_message
                }
            }
        }
 
        return func.HttpResponse(
            json.dumps(response_data),
            mimetype="application/json",
            status_code=200
        )
 
    except Exception as e:
        logging.error(f"Unexpected error: {type(e).__name__}: {str(e)}")
        return func.HttpResponse(
            json.dumps({"status": "error", "detail": "An unexpected error occurred."}),
            mimetype="application/json",
            status_code=500
        )
 


class CameraDetail(BaseModel):
    entranceName: str
    cameraPosition: Literal["inside-out", "outside-in"]
    videoUrl: str
    doorCoordinates: Optional[List[List[int]]] = None
 
class PageData(BaseModel):
    capacityOfPeople: int
    alertMessage: str
    documentId: str = None
    cameraDetails: List[CameraDetail]


@app.function_name(name="editData")
@app.route(route='api/editData', methods=[func.HttpMethod.PUT])
@require_auth
async def authenticated_edit_data(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    try:
        req_body = req.get_json()
        data = PageData(**req_body)
        user_id = user_info['user_id']
        organization_id = user_info['sub']
 
        # Find the document for this organization
        query = "SELECT * FROM c WHERE c.organization_id = @organization_id"
        parameters = [{"name": "@organization_id", "value": organization_id}]
       
        existing_items = list(setup_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        if not existing_items:
            return func.HttpResponse(
                json.dumps({"warn": "No data found for this organization."}),
                status_code=404
            )
 
        existing_item = existing_items[0]
        document_id = existing_item["id"]
       
        # Update the document with new values
        updated_document = {
            "id": document_id,
            "user_id": user_id,
            "organization_id": organization_id,
            "capacityOfPeople": data.capacityOfPeople,
            "alertMessage": data.alertMessage,  
            "cameraDetails": [camera.dict() for camera in data.cameraDetails]
            # Removed counts, persons, logs
        }
       
        # Replace the existing document
        setup_container.replace_item(
            item=document_id,
            body=updated_document
        )
       
        return func.HttpResponse(
            json.dumps({
                "message": "Data updated successfully.",
                "documentId": document_id
            }),
            status_code=200
        )
 
    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": f"An error occurred during processing: {str(e)}"}),
            status_code=500
        )
 
 
@app.function_name(name="deleteData")
@app.route(route='api/deleteData', methods=[func.HttpMethod.DELETE])
@require_auth
async def authenticated_delete_data(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    try:
        organization_id = user_info['sub']
 
        # Find the document for this organization
        query = "SELECT * FROM c WHERE c.organization_id = @organization_id"
        parameters = [{"name": "@organization_id", "value": organization_id}]
       
        existing_items = list(setup_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        if not existing_items:
            return func.HttpResponse(
                json.dumps({"warn": "No data found for this organization."}),
                status_code=404
            )
 
        document_id = existing_items[0]["id"]
       
        # Delete the document
        setup_container.delete_item(
            item=document_id,
            partition_key=document_id
        )
       
        return func.HttpResponse(
            json.dumps({
                "message": "Data deleted successfully."
            }),
            status_code=200
        )
 
    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": f"An error occurred during processing: {str(e)}"}),
            status_code=500
        )
    


@app.function_name(name="get_organization_camera_data")
@app.route(route='api/organization/camera-data', methods=[func.HttpMethod.GET])
@require_auth
async def get_organization_camera_data(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Extract organizationId from token (sub claim)
        organization_id = req.user_info.get('sub')

        if not organization_id:
            return func.HttpResponse(
                json.dumps({"warn": "Invalid token: organizationId (sub) missing"}),
                status_code=401,
                mimetype="application/json"
            )

        # Fetch organization details
        org_query = "SELECT * FROM c WHERE c.organizationId = @organizationId"
        org_params = [{"name": "@organizationId", "value": organization_id}]

        organization = list(organization_container_name.query_items(
            query=org_query, 
            parameters=org_params, 
            enable_cross_partition_query=True
        ))

        # Fetch camera URLs
        camera_query = "SELECT * FROM c WHERE c.organizationId = @organizationId"
        camera_params = [{"name": "@organizationId", "value": organization_id}]

        camera_urls = list(camera_urls_container.query_items(
            query=camera_query, 
            parameters=camera_params, 
            enable_cross_partition_query=True
        ))

        # Build the response
        response_data = {
            "organizationData": organization[0] if organization else {},
            "cameraData": camera_urls[0] if camera_urls else {
                "cameraDetails": []
            }
        }

        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error fetching organization and camera data for {organization_id}: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": "Internal server error"}),
            status_code=500,
            mimetype="application/json"
        )

@app.function_name(name="getPersonCountByDate")
@app.route(route='api/getPersonCountByDate', methods=[func.HttpMethod.GET])
@require_auth
async def get_person_count_by_date(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    user_id = user_info['sub']
   
    # Initialize containers
    users_container = database.get_container_client(USERS)
    user_logs_container = database.get_container_client(USER_LOGS)
   
    # Get date parameters from the request query string
    date_param = req.params.get('date')
    start_date_param = req.params.get('start_date')
    end_date_param = req.params.get('end_date')
    period_param = req.params.get('period')
   
    # Determine if we're processing a single date, date range, or period
    if period_param in ['yesterday', 'week', 'month']:
        try:
            today = pendulum.now().start_of('day')
            if period_param == 'yesterday':
                start_date = today.subtract(days=1).start_of('day')
                end_date = today.subtract(days=1).end_of('day')
                selected_date = start_date.format('YYYY-MM-DD')
                mode = "single"
            elif period_param == 'week':
                start_date = today.start_of('week')
                end_date = today.end_of('day')
                mode = "range"
                selected_date = None
            elif period_param == 'month':
                start_date = today.start_of('month')
                end_date = today.end_of('day')
                mode = "range"
                selected_date = None
        except Exception as e:
            return func.HttpResponse(
                json.dumps({"error": f"Invalid period parameter. Details: {str(e)}"}),
                status_code=400,
                mimetype="application/json"
            )
    elif start_date_param and end_date_param:
        try:
            start_date = pendulum.parse(start_date_param).start_of('day')
            end_date = pendulum.parse(end_date_param).end_of('day')
            if start_date > end_date:
                return func.HttpResponse(
                    json.dumps({"warn": "start_date cannot be after end_date"}),
                    status_code=400,
                    mimetype="application/json"
                )
            mode = "range"
            selected_date = None
        except Exception as e:
            return func.HttpResponse(
                json.dumps({"warn": f"Invalid date format for start_date or end_date. Please use YYYY-MM-DD. Details: {str(e)}"}),
                status_code=400,
                mimetype="application/json"
            )
    else:
        if date_param:
            try:
                selected_date = pendulum.parse(date_param).format('YYYY-MM-DD')
            except Exception as e:
                return func.HttpResponse(
                    json.dumps({"warn": f"Invalid date format. Please use YYYY-MM-DD. Details: {str(e)}"}),
                    status_code=400,
                    mimetype="application/json"
                )
        else:
            selected_date = pendulum.now().format('YYYY-MM-DD')
        start_date = pendulum.parse(selected_date).start_of('day')
        end_date = pendulum.parse(selected_date).end_of('day')
        mode = "single"
   
    try:
        # Get organization_id from users container
        user_query = "SELECT c.organization_id FROM c WHERE c.azure_b2c_id = @user_id"
        user_params = [{"name": "@user_id", "value": user_id}]
       
        user_items = list(users_container.query_items(
            query=user_query,
            parameters=user_params,
            enable_cross_partition_query=True
        ))
       
        organization_id = user_items[0]['organization_id'] if user_items and 'organization_id' in user_items[0] else user_id
 
        # Query to get logs and manual_adjustments from user_logs table
        logs_query = """
        SELECT c.logs, c.manual_adjustments
        FROM c
        WHERE c.user_id = @organization_id
        """
        parameters = [{"name": "@organization_id", "value": organization_id}]
       
        logs_items = list(user_logs_container.query_items(
            query=logs_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        # Initialize response data
        log_entries = 0
        log_exits = 0
        manual_entries = 0
        manual_exits = 0
        camera_entry_counts = defaultdict(int)
        camera_exit_counts = defaultdict(int)
        all_cameras = set()
        manual_adjustments_data = []
 
        if logs_items and "logs" in logs_items[0]:
            # Process logs
            logs = logs_items[0].get("logs", [])
            for log in logs:
                timestamp = log.get("timestamp")
                camera_id = log.get("camera_id")
                event_type = log.get("event_type")
 
                if timestamp and camera_id and event_type:
                    try:
                        log_datetime = pendulum.parse(timestamp)
                        if start_date <= log_datetime <= end_date:
                            all_cameras.add(camera_id)
                            if event_type == "person_entry":
                                camera_entry_counts[camera_id] += 1
                            elif event_type == "person_exit":
                                camera_exit_counts[camera_id] += 1
                    except Exception as parse_error:
                        logging.warning(f"Failed to parse timestamp {timestamp}: {str(parse_error)}")
                        continue
           
            # Calculate log-based totals
            log_entries = sum(camera_entry_counts.values())
            log_exits = sum(camera_exit_counts.values())
       
        # Process manual_adjustments
        if logs_items and "manual_adjustments" in logs_items[0]:
            manual_adjustments = logs_items[0].get("manual_adjustments", [])
            for adjustment in manual_adjustments:
                adjustment_date = adjustment.get("date")
                try:
                    adjustment_datetime = pendulum.parse(adjustment_date).start_of('day')
                    if start_date <= adjustment_datetime <= end_date:
                        adjustment_entries = adjustment.get("entries", 0)
                        adjustment_exits = adjustment.get("exits", 0)
                        manual_entries += adjustment_entries
                        manual_exits += adjustment_exits
                        manual_adjustments_data.append({
                            "date": adjustment_date,
                            "updated_at": adjustment.get("updated_at", ""),
                            "entries": adjustment_entries,
                            "exits": adjustment_exits,
                            "net_count": adjustment_entries - adjustment_exits
                        })
                except Exception as parse_error:
                    logging.warning(f"Failed to parse manual adjustment date {adjustment_date}: {str(parse_error)}")
                    continue
 
        # Calculate combined totals
        total_entries = log_entries + manual_entries
        total_exits = log_exits + manual_exits
        total_count = total_entries - total_exits
        log_net_count = log_entries - log_exits
        manual_adjustments_net_count = manual_entries - manual_exits
       
        # Prepare camera-specific data
        camera_data = []
        for camera_id in all_cameras:
            entries = camera_entry_counts[camera_id]
            exits = camera_exit_counts[camera_id]
            net_count = entries - exits
            camera_data.append({
                "camera_id": camera_id,
                "entries": entries,
                "exits": exits,
                "net_count": net_count
            })
       
        # Sort camera data by camera_id
        camera_data.sort(key=lambda x: x["camera_id"])
       
        # Sort manual adjustments by date
        manual_adjustments_data.sort(key=lambda x: x["date"])
       
        # Prepare the response
        response_data = {
            "data": {
                "total_entries": total_entries,
                "total_exits": total_exits,
                "total_count": total_count,
                "log_entries": log_entries,
                "log_exits": log_exits,
                "log_net_count": log_net_count,
                "manual_entries": manual_entries,
                "manual_exits": manual_exits,
                "manual_adjustments_net_count": manual_adjustments_net_count,
                "camera_data": camera_data,
                "manual_adjustments": manual_adjustments_data
            }
        }
        if mode == "single":
            response_data["data"]["date"] = selected_date
        else:
            response_data["data"]["date_range"] = {
                "start_date": start_date.format('YYYY-MM-DD'),
                "end_date": end_date.format('YYYY-MM-DD')
            }
       
        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )
 
    except Exception as e:
        logging.error(f"Unexpected error in getPersonCountByDate: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": f"An unexpected error occurred: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )
    

@app.route(route="update_organization_camera_data", methods=["PUT"])
async def update_organization_camera_data(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        organization_data = req_body.get("organizationData")
        camera_data = req_body.get("cameraData")

        if not organization_data or not camera_data:
            return func.HttpResponse(
                json.dumps({"warn": "Both organizationData and cameraData are required."}),
                status_code=400,
                mimetype="application/json"
            )

        # Validate mandatory fields
        mandatory_org_fields = [
            "organizationId", "organizationName", "phoneNumber",
            "websiteUrl"
        ]
        mandatory_cam_fields = ["organizationId", "email", "cameraDetails"]

        for field in mandatory_org_fields:
            if field not in organization_data:
                return func.HttpResponse(f"warn: Missing mandatory field in organizationData: {field}", status_code=400)

        for field in mandatory_cam_fields:
            if field not in camera_data:
                return func.HttpResponse(f"warn: Missing mandatory field in cameraData: {field}", status_code=400)

        # Convert workTiming to an integer if it exists
        if "workTiming" in organization_data:
            try:
                organization_data["workTiming"] = int(organization_data["workTiming"])
            except ValueError:
                return func.HttpResponse("warn: Invalid workTiming value. Must be a number.", status_code=400)

        # Upsert (Insert or Update) organization data
        organization_container_name.upsert_item(organization_data)

        # Upsert (Insert or Update) camera data
        camera_urls_container.upsert_item(camera_data)

        return func.HttpResponse("Organization and camera data updated successfully", status_code=200)

    except exceptions.CosmosHttpResponseError as e:
        return func.HttpResponse(f"warn:" "Cosmos DB Error: {str(e)}", status_code=500)
    except Exception as e:
        return func.HttpResponse(f"warn: {str(e)}", status_code=500)





# GRAPH_API_URL = "https://graph.microsoft.com/v1.0"
# GRAPH_SCOPE = "https://graph.microsoft.com/.default"





# def get_graph_access_token():
#     """Authenticate and get access token for Microsoft Graph."""
#     try:
#         logging.info(f"TENANT_ID: {TENANT_ID}, CLIENT_ID: {CLIENT_ID}, CLIENT_SECRET: {CLIENT_SECRET}, GRAPH_SCOPE: {GRAPH_SCOPE}")
#         credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
#         token = credential.get_token(GRAPH_SCOPE)
#         logging.info("Access token fetched successfully.")
#         return token.token
#     except Exception as e:
#         logging.error(f"Error getting access token: {e}")
#         raise



# def get_user_data(object_id, token):
#     """Fetch user data from Microsoft Graph."""
#     try:
#         url = f"{GRAPH_API_URL}/users/{object_id}"
#         headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
#         response = requests.get(url, headers=headers)
#         response.raise_for_status()
#         return response.json()
#     except requests.exceptions.HTTPError as err:
#         logging.error(f"Failed to fetch user data: {err}")
#         raise


# def update_user_job_title(object_id, job_title, token):
#     """Update user jobTitle in Azure AD B2C."""
#     try:
#         url = f"{GRAPH_API_URL}/users/{object_id}"
#         headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
#         payload = {"jobTitle": job_title}
#         response = requests.patch(url, headers=headers, data=json.dumps(payload))
#         response.raise_for_status()
#         logging.info(f"Successfully updated job title for user {object_id} to '{job_title}'")
#         return response.status_code == 204
#     except requests.exceptions.HTTPError as err:
#         logging.error(f"Failed to update user job title: {err}")
#         raise



# @app.function_name(name="AssignAdminJobTitle")
# @app.route(route="assign-admin-job-title", methods=[func.HttpMethod.POST])
# async def assign_admin_job_title(req: func.HttpRequest) -> func.HttpResponse:
#     """Handle admin job title assignment with improved performance and reliability."""
#     # Always prepare a valid B2C response
#     b2c_response = {
#         "version": "1.0.0",
#         "action": "Continue",
#         "jobTitle": "admin"
#     }
    
#     try:
#         # Extract object ID with minimal processing
#         body = req.get_json()
#         object_id = body.get("oid")

#         if not object_id:
#             logging.warning("Missing oid in request, returning default response")
#             return func.HttpResponse(json.dumps(b2c_response), 
#                                     status_code=200, 
#                                     mimetype="application/json")

#         # Start a background task to update the job title
#         # This allows B2C to continue without waiting for the update to complete
#         background_task = asyncio.create_task(
#             update_job_title_background(object_id, "admin")
#         )
        
#         # Return immediately with the response B2C needs
#         logging.info(f"Returning response to B2C: {b2c_response}")
#         return func.HttpResponse(json.dumps(b2c_response), 
#                                 status_code=200, 
#                                 mimetype="application/json")

#     except Exception as e:
#         logging.error(f"Error in assign_admin_job_title: {str(e)}")
#         # Always return a valid response for B2C
#         return func.HttpResponse(json.dumps(b2c_response), 
#                                 status_code=200, 
#                                 mimetype="application/json")

# async def update_job_title_background(object_id, job_title):
#     """Update job title in the background after responding to B2C."""
#     try:
#         token = get_graph_access_token()
#         if not token:
#             logging.error("Failed to get access token for background update")
#             return
            
#         user_data = get_user_data(object_id, token)
#         if not user_data:
#             logging.error(f"Failed to get user data for {object_id}")
#             return
            
#         if not user_data.get("jobTitle"):
#             update_success = update_user_job_title(object_id, job_title, token)
#             if update_success:
#                 logging.info(f"Job title updated successfully for {object_id}")
#             else:
#                 logging.warning(f"Failed to update job title for {object_id}")
#     except Exception as e:
#         logging.error(f"Error in background job title update: {str(e)}")

# firstly used

# @app.function_name(name="AssignEmployeeJobTitle")
# @app.route(route="assign-employee-job-title", methods=[func.HttpMethod.POST])
# async def assign_employee_job_title(req: func.HttpRequest) -> func.HttpResponse:
#     """Handle employee job title assignment with improved performance and reliability."""
#     # Always prepare a valid B2C response
#     b2c_response = {
#         "version": "1.0.0",
#         "action": "Continue",
#         "jobTitle": "employee"
#     }
    
#     try:
#         # Extract object ID with minimal processing
#         body = req.get_json()
#         object_id = body.get("oid")

#         if not object_id:
#             logging.warning("Missing oid in request, returning default response")
#             return func.HttpResponse(json.dumps(b2c_response), 
#                                     status_code=200, 
#                                     mimetype="application/json")

#         # Start a background task to update the job title
#         # This allows B2C to continue without waiting for the update to complete
#         background_task = asyncio.create_task(
#             update_job_title_background(object_id, "employee")
#         )
        
#         # Return immediately with the response B2C needs
#         logging.info(f"Returning response to B2C: {b2c_response}")
#         return func.HttpResponse(json.dumps(b2c_response), 
#                                 status_code=200, 
#                                 mimetype="application/json")

#     except Exception as e:
#         logging.error(f"Error in assign_employee_job_title: {str(e)}")
#         # Always return a valid response for B2C
#         return func.HttpResponse(json.dumps(b2c_response), 
#                                 status_code=200, 
#                                 mimetype="application/json")

@app.function_name(name="AssignAdminJobTitle")
@app.route(route="assign-admin-job-title", methods=[func.HttpMethod.POST])
async def assign_admin_job_title(req: func.HttpRequest) -> func.HttpResponse:
    """Handle admin job title assignment if jobTitle is empty, return what happened."""
    # Base B2C response without default jobTitle
    b2c_response = {
        "version": "1.0.0",
        "action": "Continue"
    }
    
    try:
        # Extract object ID from request body
        body = req.get_json()
        object_id = body.get("objectId")
        
        if not object_id:
            logging.warning("Missing objectId in request")
            b2c_response["error"] = "Missing objectId"
            return func.HttpResponse(
                json.dumps(b2c_response),
                status_code=200,  # Still 200 for B2C compatibility
                mimetype="application/json"
            )
        
        # Get Microsoft Graph API token
        token = get_graph_access_token()
        if not token:
            logging.error("Failed to get access token")
            b2c_response["error"] = "Failed to authenticate with Graph API"
            return func.HttpResponse(
                json.dumps(b2c_response),
                status_code=200,
                mimetype="application/json"
            )
        
        # Fetch user data
        user_data = get_user_data(object_id, token)
        if not user_data:
            logging.error(f"Failed to get user data for {object_id}")
            b2c_response["error"] = "Failed to retrieve user data"
            return func.HttpResponse(
                json.dumps(b2c_response),
                status_code=200,
                mimetype="application/json"
            )
        
        # Check and update jobTitle
        current_job_title = user_data.get("jobTitle")
        if not current_job_title:
            update_success = update_user_job_title(object_id, "Admin", token)
            if update_success:
                logging.info(f"Job title updated to 'Admin' for {object_id}")
                b2c_response["jobTitle"] = "Admin"
                b2c_response["message"] = "Job title updated to 'Admin'"
            else:
                logging.warning(f"Failed to update job title for {object_id}")
                b2c_response["error"] = "Failed to update job title"
        else:
            logging.info(f"Job title is not empty for {object_id}, current value: '{current_job_title}', skipping update")
            b2c_response["jobTitle"] = current_job_title
            b2c_response["message"] = f"Job title already set to '{current_job_title}'"
        
        # Return the response with what happened
        logging.info(f"Returning response to B2C for {object_id}: {b2c_response}")
        return func.HttpResponse(
            json.dumps(b2c_response),
            status_code=200,
            mimetype="application/json"
        )
    
    except Exception as e:
        logging.error(f"Error in assign_admin_job_title: {str(e)}")
        b2c_response["error"] = f"Unexpected error: {str(e)}"
        return func.HttpResponse(
            json.dumps(b2c_response),
            status_code=200,
            mimetype="application/json"
        )

# Helper functions for Microsoft Graph API
def get_graph_access_token():
    """Retrieve a Microsoft Graph API token using client credentials."""
    client_id = os.getenv("AZURE_B2C_CLIENT_ID")
    client_secret = os.getenv("AZURE_B2C_CLIENT_SECRET")
    tenant_name = os.getenv("AZURE_B2C_TENANT_NAME")
    token_url = f"https://login.microsoftonline.com/{tenant_name}.onmicrosoft.com/oauth2/v2.0/token"
    
    token_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials"
    }
    
    response = requests.post(token_url, data=token_data, headers={"Content-Type": "application/x-www-form-urlencoded"})
    if response.status_code == 200:
        return response.json().get("access_token")
    logging.error(f"Token request failed: {response.text}")
    return None

def get_user_data(object_id, token):
    """Fetch user data from Microsoft Graph API."""
    url = f"https://graph.microsoft.com/v1.0/users/{object_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    logging.error(f"Failed to fetch user data: {response.text}")
    return None

def update_user_job_title(object_id, job_title, token):
    """Update the user's jobTitle in Azure AD."""
    url = f"https://graph.microsoft.com/v1.0/users/{object_id}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    payload = {
        "jobTitle": job_title
    }
    response = requests.patch(url, headers=headers, json=payload)
    if response.status_code == 204:
        return True
    logging.error(f"Failed to update jobTitle: {response.text}")
    return False


# Get individual user by sub ID (userId) with optional date filter
@app.function_name(name="get_user_attendance")
@app.route(route='api/attendance', methods=[func.HttpMethod.GET])
@require_auth
async def get_user_attendance(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Extract userId from token (sub claim)
        user_id = req.user_info.get('sub')

        if not user_id:
            logging.error("Invalid token: userId (sub) missing")
            return func.HttpResponse(
                json.dumps({"error": "Invalid token: userId (sub) missing"}),
                status_code=401,
                mimetype="application/json"
            )

        # Extract optional date parameter from query
        date_filter = req.params.get("date")

        # Define query based on the presence of the date filter
        if date_filter:
            query = "SELECT * FROM c WHERE c.userId = @userId AND c.date = @date ORDER BY c.date DESC"
            parameters = [
                {"name": "@userId", "value": user_id},
                {"name": "@date", "value": date_filter}
            ]
        else:
            query = "SELECT * FROM c WHERE c.userId = @userId ORDER BY c.date DESC"
            parameters = [{"name": "@userId", "value": user_id}]

        # Fetch attendance records for the user
        user_attendance = list(attendance_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        if not user_attendance:
            logging.warning(f"No attendance found for userId: {user_id} on date: {date_filter}" if date_filter else f"No attendance found for userId: {user_id}")
            return func.HttpResponse(
                json.dumps([]),
                status_code=200,
                mimetype="application/json"
            )

        return func.HttpResponse(
            json.dumps(user_attendance),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error fetching attendance for userId {user_id}: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Internal server error"}),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name(name="editUser")
@app.route(route='api/editUser', methods=[func.HttpMethod.PUT])
@require_auth
async def edit_user(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    organization_id = user_info['sub']
   
    logging.info(f"Attempting to edit user for organization {organization_id}")
   
    try:
        # Get request body
        req_body = req.get_json()
       
        # Get user_id from body
        user_id = req_body.get('user_id')
       
        # Validate that user_id is provided
        if not user_id:
            return func.HttpResponse(
                json.dumps({"warn": "User ID is required."}),
                mimetype="application/json",
                status_code=400
            )
       
        # Validate that at least one field to update is provided
        if 'role' not in req_body and 'name' not in req_body:
            return func.HttpResponse(
                json.dumps({"warn": "At least one of 'role' or 'name' is required."}),
                mimetype="application/json",
                status_code=400
            )
       
        # Validate role if provided
        if 'role' in req_body and req_body['role'] not in ['Admin', 'User']:
            return func.HttpResponse(
                json.dumps({"warn": "Role must be either 'Admin' or 'User'."}),
                mimetype="application/json",
                status_code=400
            )
       
        # Validate name if provided
        if 'name' in req_body:
            if not isinstance(req_body['name'], str) or len(req_body['name'].strip()) == 0:
                return func.HttpResponse(
                    json.dumps({"warn": "Name must be a non-empty string."}),
                    mimetype="application/json",
                    status_code=400
                )
            if len(req_body['name'].strip()) > 256:  # Azure AD B2C displayName limit
                return func.HttpResponse(
                    json.dumps({"warn": "Name must be 256 characters or less."}),
                    mimetype="application/json",
                    status_code=400
                )
       
        # Retrieve existing user from database
        try:
            user_document = users_container.read_item(
                item=user_id,
                partition_key=user_id
            )
        except Exception as e:
            logging.error(f"Error reading user from database: {str(e)}")
            return func.HttpResponse(
                json.dumps({"warn": "User not found.", "error": str(e)}),
                mimetype="application/json",
                status_code=404
            )
       
        # Verify the user belongs to the same organization
        if user_document['organization_id'] != organization_id:
            logging.warning(f"Organization mismatch: document {user_document['organization_id']} vs auth {organization_id}")
            return func.HttpResponse(
                json.dumps({"warn": "Unauthorized to modify this user."}),
                mimetype="application/json",
                status_code=403
            )
       
        # Azure AD B2C Configuration
        client_id = os.getenv("AZURE_B2C_CLIENT_ID")
        client_secret = os.getenv("AZURE_B2C_CLIENT_SECRET")
        tenant_name = os.getenv("AZURE_B2C_TENANT_NAME")
        tenant_domain = os.getenv("AZURE_B2C_DOMAIN", f"{tenant_name}.onmicrosoft.com")
       
        # Get Microsoft Graph token
        token_url = f"https://login.microsoftonline.com/{tenant_name}.onmicrosoft.com/oauth2/v2.0/token"
        token_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
       
        token_response = requests.post(token_url, data=token_data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
       
        if token_response.status_code != 200:
            logging.error(f"Token request failed: {token_response.text}")
            return func.HttpResponse(
                json.dumps({"warn": "Failed to authenticate with Azure AD"}),
                mimetype="application/json",
                status_code=500
            )
           
        token_result = token_response.json()
        access_token = token_result.get('access_token')
       
        if not access_token:
            return func.HttpResponse(
                json.dumps({"warn": "Failed to obtain access token"}),
                mimetype="application/json",
                status_code=500
            )
       
        # Update user in Azure AD B2C
        graph_url = f"https://graph.microsoft.com/v1.0/users/{user_document['azure_b2c_id']}"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
       
        # Get extension app ID for role (if updating role)
        extension_app_id = None
        if 'role' in req_body:
            apps_url = "https://graph.microsoft.com/v1.0/applications"
            apps_response = requests.get(apps_url, headers=headers, params={'$filter': 'displayName eq \'b2c-extensions-app\''})
           
            if apps_response.status_code == 200:
                apps_data = apps_response.json()
                if apps_data.get('value') and len(apps_data['value']) > 0:
                    extension_app_id = apps_data['value'][0]['appId'].replace('-', '')
       
        # Prepare update payload
        update_payload = {}
       
        if 'role' in req_body:
            update_payload["jobTitle"] = req_body['role']
            if extension_app_id:
                update_payload[f"extension_{extension_app_id}_Role"] = req_body['role']
       
        if 'name' in req_body:
            update_payload["displayName"] = req_body['name'].strip()
            # Split name for givenName and surname
            name_parts = req_body['name'].strip().split()
            update_payload["givenName"] = name_parts[0] if name_parts else req_body['name'].strip()
            # Only include surname if there are multiple parts and the last part is non-empty
            if len(name_parts) > 1 and name_parts[-1]:
                update_payload["surname"] = name_parts[-1][:64]  # Ensure surname is within 64 chars
       
        # Update in Azure AD B2C
        if update_payload:
            b2c_response = requests.patch(graph_url, headers=headers, json=update_payload)
           
            if b2c_response.status_code >= 400:
                logging.error(f"Error updating B2C user: {b2c_response.text}")
                return func.HttpResponse(
                    json.dumps({"warn": "Failed to update user in Azure AD B2C", "error": b2c_response.text}),
                    mimetype="application/json",
                    status_code=500
                )
       
        # Update in database
        if 'role' in req_body:
            user_document['role'] = req_body['role']
        if 'name' in req_body:
            user_document['name'] = req_body['name'].strip()
       
        users_container.replace_item(
            item=user_document['id'],
            body=user_document
        )
       
        # Prepare response
        response_data = {
            "user_id": user_id,
            "message": "User updated successfully"
        }
        if 'role' in req_body:
            response_data["role"] = req_body['role']
        if 'name' in req_body:
            response_data["name"] = req_body['name'].strip()
       
        return func.HttpResponse(
            json.dumps({"data": response_data}),
            mimetype="application/json",
            status_code=200
        )
       
    except Exception as e:
        logging.error(f"Error updating user: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": f"An error occurred while updating the user: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )
   

@app.function_name(name="deleteUser")
@app.route(route='api/deleteUser', methods=[func.HttpMethod.DELETE])
@require_auth
async def delete_user(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    try:
        # Parse request body
        req_body = req.get_json()
        
        # Validate user_id is provided in the request body
        if not req_body or 'user_id' not in req_body:
            return func.HttpResponse(
                json.dumps({"warn": "User ID is required in the request body."}),
                mimetype="application/json",
                status_code=400
            )
        
        organization_id = user_info['sub']
        user_id = req_body['user_id']

        # Query for the user with the given ID and organization_id
        query = "SELECT * FROM c WHERE c.id = @user_id AND c.organization_id = @organization_id"
        parameters = [
            {"name": "@user_id", "value": user_id},
            {"name": "@organization_id", "value": organization_id}
        ]
        
        user_items = list(users_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        if not user_items:
            return func.HttpResponse(
                json.dumps({"warn": "User not found or you don't have permission to delete this user."}),
                mimetype="application/json",
                status_code=404
            )

        user_document = user_items[0]

        # Check if user has an Azure B2C ID for deletion
        if 'azure_b2c_id' in user_document:
            # Azure AD B2C Configuration
            client_id = os.getenv("AZURE_B2C_CLIENT_ID")
            client_secret = os.getenv("AZURE_B2C_CLIENT_SECRET")
            tenant_name = os.getenv("AZURE_B2C_TENANT_NAME")
            
            # Get Microsoft Graph token
            token_url = f"https://login.microsoftonline.com/{tenant_name}.onmicrosoft.com/oauth2/v2.0/token"
            token_data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': 'https://graph.microsoft.com/.default',
                'grant_type': 'client_credentials'
            }
            
            # Get access token
            token_response = requests.post(
                token_url,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )
            
            if token_response.status_code != 200:
                logging.error(f"Token request failed: {token_response.text}")
                return func.HttpResponse(
                    json.dumps({"warn": "Failed to authenticate for user deletion."}),
                    mimetype="application/json",
                    status_code=500
                )
            
            token_result = token_response.json()
            
            # Delete from Azure AD B2C
            graph_url = f"https://graph.microsoft.com/v1.0/users/{user_document['azure_b2c_id']}"
            headers = {
                "Authorization": f"Bearer {token_result['access_token']}",
                "Content-Type": "application/json"
            }
            
            b2c_delete_response = requests.delete(graph_url, headers=headers)
            
            if b2c_delete_response.status_code >= 400:
                logging.error(f"Failed to delete from Azure AD B2C: {b2c_delete_response.text}")
                return func.HttpResponse(
                    json.dumps({"warn": "Failed to delete user from Azure AD B2C."}),
                    mimetype="application/json",
                    status_code=500
                )

        # Delete from local database
        users_container.delete_item(
            item=user_document['id'],
            partition_key=user_document.get('partition_key', user_document['id'])
        )
        
        return func.HttpResponse(
            json.dumps({"message": "User deleted successfully."}),
            mimetype="application/json",
            status_code=200
        )

    except Exception as e:
        logging.error(f"Error deleting user: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": "An error occurred during user deletion."}),
            mimetype="application/json",
            status_code=500
        )
    

@app.function_name(name="addUser")
@app.route(route='api/addUser', methods=[func.HttpMethod.POST])
@require_auth
async def add_user(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    organization_id = user_info['sub']
   
    try:
        req_body = req.get_json()
       
        if not all(field in req_body for field in ['name', 'email', 'role']):
            return func.HttpResponse(
                json.dumps({"warn": "Missing required fields. Name, email, and role are required."}),
                mimetype="application/json",
                status_code=400
            )
       
        if req_body['role'] not in ['Admin', 'User']:
            return func.HttpResponse(
                json.dumps({"warn": "Role must be either 'Admin' or 'User'."}),
                mimetype="application/json",
                status_code=400
            )
       
        email = req_body['email']
        query = f"SELECT * FROM c WHERE c.email = '{email}'"
        existing_users = list(users_container.query_items(query=query, enable_cross_partition_query=True))
        if existing_users:
            return func.HttpResponse(
                json.dumps({"warn": f"Email '{email}' already exists."}),
                mimetype="application/json",
                status_code=409
            )
       
        user_id = str(uuid.uuid4())
        user_document = {
            'id': user_id,
            'user_id': user_id,
            'organization_id': organization_id,
            'name': req_body['name'],
            'email': email,
            'role': req_body['role'],
            'created_at': pendulum.now().isoformat()
        }
       
        def generate_secure_password():
            chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
            special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            while True:
                password = ''.join(random.choice(chars) for _ in range(10)) + \
                          random.choice(special_chars) + random.choice(special_chars)
                password_list = list(password)
                random.shuffle(password_list)
                password = ''.join(password_list)
                email_parts = email.lower().split('@')
                if (email_parts[0] not in password.lower() and
                    (len(email_parts) < 2 or email_parts[1] not in password.lower())):
                    return password
       
        password = generate_secure_password()
       
        client_id = os.getenv("AZURE_B2C_CLIENT_ID")
        client_secret = os.getenv("AZURE_B2C_CLIENT_SECRET")
        tenant_name = os.getenv("AZURE_B2C_TENANT_NAME")
        tenant_domain = os.getenv("AZURE_B2C_DOMAIN", f"{tenant_name}.onmicrosoft.com")
        mail_nickname = email.split('@')[0]
       
        token_url = f"https://login.microsoftonline.com/{tenant_name}.onmicrosoft.com/oauth2/v2.0/token"
        token_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
       
        token_response = requests.post(token_url, data=token_data, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        token_result = token_response.json()
        if token_response.status_code != 200 or "access_token" not in token_result:
            raise Exception(f"Failed to authenticate with Azure AD: {token_result.get('error', 'Unknown error')}")
       
        graph_url = "https://graph.microsoft.com/v1.0/users"
        headers = {
            "Authorization": f"Bearer {token_result['access_token']}",
            "Content-Type": "application/json"
        }
       
        display_name = req_body['name']
        unique_id = user_id.split('-')[0]
        user_principal_name = f"{mail_nickname}_{unique_id}@{tenant_domain}"
       
        extension_app_id = None
        apps_url = "https://graph.microsoft.com/v1.0/applications"
        apps_response = requests.get(apps_url, headers=headers, params={'$filter': 'displayName eq \'b2c-extensions-app\''})
        if apps_response.status_code == 200:
            apps_data = apps_response.json()
            if apps_data.get('value') and len(apps_data['value']) > 0:
                extension_app_id = apps_data['value'][0]['appId'].replace('-', '')
       
        user_payload = {
            "accountEnabled": True,
            "displayName": display_name,
            "mailNickname": f"{mail_nickname}_{unique_id}",
            "userPrincipalName": user_principal_name,
            "passwordProfile": {"forceChangePasswordNextSignIn": False, "password": password},
            "passwordPolicies": "DisablePasswordExpiration",
            "mail": email,
            "otherMails": [email],
            "identities": [
                {"signInType": "emailAddress", "issuer": tenant_domain, "issuerAssignedId": email},
                {"signInType": "userPrincipalName", "issuer": tenant_domain, "issuerAssignedId": user_principal_name}
            ],
            "jobTitle": req_body['role']
        }
        if extension_app_id:
            user_payload[f"extension_{extension_app_id}_Role"] = req_body['role']
            user_payload[f"extension_{extension_app_id}_Email"] = email
            user_payload[f"extension_{extension_app_id}_SignInWithEmail"] = "true"
       
        sendgrid_api_key = os.getenv("SENDGRID_API_KEY")
        sendgrid_template_id = os.getenv("SENDGRID_TEMPLATE_ID_TRACKER")
        sender_email = os.getenv("EMAIL_SENDER", os.getenv("FROM_EMAIL"))
        if not all([sendgrid_api_key, sendgrid_template_id, sender_email]):
            raise Exception("Missing SendGrid configuration")
       
        sg = SendGridAPIClient(sendgrid_api_key)
        message = Mail(from_email=From(sender_email, "Yectra"), to_emails=To(email))
        message.template_id = sendgrid_template_id
        message.dynamic_template_data = {"name": req_body['name'], "email": email, "password": password}
       
        try:
            # Step 1: Create database entry
            users_container.create_item(body=user_document)
            logging.info(f"Created database entry for user_id: {user_id}")
           
            # Step 2: Create Azure AD B2C user
            b2c_response = requests.post(graph_url, headers=headers, json=user_payload)
            b2c_response.raise_for_status()
            b2c_user = b2c_response.json()
            b2c_user_id = b2c_user.get('id')
            logging.info(f"Created Azure B2C user: {b2c_user_id}")
           
            # Step 3: Verify and update email identity
            user_get_url = f"https://graph.microsoft.com/v1.0/users/{b2c_user_id}"
            user_get_response = requests.get(user_get_url, headers=headers)
            user_get_response.raise_for_status()
            current_user = user_get_response.json()
           
            email_identity_exists = any(
                identity.get('signInType') == 'emailAddress' and identity.get('issuerAssignedId') == email
                for identity in current_user.get('identities', [])
            )
           
            if not email_identity_exists:
                current_identities = current_user.get('identities', [])
                current_identities.append({
                    "signInType": "emailAddress",
                    "issuer": tenant_domain,
                    "issuerAssignedId": email
                })
                identity_payload = {"identities": current_identities}
                identity_response = requests.patch(user_get_url, headers=headers, json=identity_payload)
                if identity_response.status_code >= 400:
                    error_detail = identity_response.json().get('error', {}).get('message', 'Unknown error')
                    logging.error(f"Failed to update identity: {identity_response.status_code} - {error_detail}")
                    logging.error(f"Payload sent: {json.dumps(identity_payload, indent=2)}")
                    identity_response.raise_for_status()
                logging.info(f"Updated email identity for user: {b2c_user_id}")
           
            # Step 4: Send email
            email_response = sg.send(message)
            logging.info(f"Email sent to: {email}")
           
            # Update user document with Azure B2C ID
            user_document['azure_b2c_id'] = b2c_user_id
            users_container.replace_item(item=user_document['id'], body=user_document)
           
            return func.HttpResponse(
                json.dumps({
                    "data": {
                        "user_id": user_id,
                        "azure_b2c_id": b2c_user_id,
                        "credentials": {"email": email, "password": password},
                        "message": "User added successfully to database and Azure AD B2C, email sent successfully"
                    }
                }),
                mimetype="application/json",
                status_code=201
            )
           
        except Exception as e:
            # Enhanced rollback with retry for database
            for attempt in range(3):
                try:
                    users_container.delete_item(item=user_id, partition_key=organization_id)
                    logging.info(f"Rolled back database entry for user_id: {user_id}")
                    break
                except Exception as db_err:
                    logging.warning(f"Attempt {attempt + 1} failed to rollback database entry: {str(db_err)}")
                    if attempt == 2:
                        logging.error(f"Failed to rollback database entry after 3 attempts: {str(db_err)}")
                time.sleep(1)  # Wait between retries
           
            if 'b2c_user_id' in locals():
                try:
                    requests.delete(f"https://graph.microsoft.com/v1.0/users/{b2c_user_id}", headers=headers)
                    logging.info(f"Rolled back Azure B2C user: {b2c_user_id}")
                except Exception as b2c_err:
                    logging.warning(f"Failed to rollback Azure B2C user: {b2c_user_id} - {str(b2c_err)}")
           
            raise e
           
    except Exception as e:
        error_message = str(e)
        logging.error(f"Error adding user: {error_message}")
        return func.HttpResponse(
            json.dumps({"warn": f"Failed to add user: {error_message}"}),
            mimetype="application/json",
            status_code=500
        )
 
   

@app.function_name(name="getAllUsers")
@app.route(route='api/getAllUsers', methods=[func.HttpMethod.GET])
@require_auth
async def get_all_users(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    organization_id = user_info['sub']
   
    try:
        # Debug logging
        logging.info(f"Fetching users for organization_id: {organization_id}")
       
        # Get pagination parameters from query string
        page_size = int(req.params.get('page_size', 10))  # Default to 10 if not provided
        page_no = int(req.params.get('page_no', 1))       # Default to page 1 if not provided
       
        if page_size <= 0 or page_no <= 0:
            return func.HttpResponse(
                json.dumps({"detail": "page_size and page_no must be positive integers"}),
                mimetype="application/json",
                status_code=400
            )
       
        # Calculate offset and limit for pagination
        offset = (page_no - 1) * page_size
        limit = page_size
       
        # Query to get users for the organization
        query = "SELECT * FROM c WHERE c.organization_id = @org_id OFFSET @offset LIMIT @limit"
       
        # Query parameters
        query_params = [
            {"name": "@org_id", "value": organization_id},
            {"name": "@offset", "value": offset},
            {"name": "@limit", "value": limit}
        ]
       
        # Query options with cross-partition query explicitly enabled
        query_options = {
            'enable_cross_partition_query': True
        }
       
        # Query users container
        try:
            items = list(users_container.query_items(
                query=query,
                parameters=query_params,
                **query_options
            ))
           
            # Debug logging
            logging.info(f"Query returned {len(items)} items for page_no: {page_no}, page_size: {page_size}")
           
            # Get total count of users for the organization (for pagination metadata)
            count_query = "SELECT VALUE COUNT(1) FROM c WHERE c.organization_id = @org_id"
            count_params = [{"name": "@org_id", "value": organization_id}]
            total_count = list(users_container.query_items(
                query=count_query,
                parameters=count_params,
                enable_cross_partition_query=True
            ))[0]
           
            # If no items, log all users to understand why
            if not items:
                # Try a query without filtering to see all users
                all_users = list(users_container.query_items(
                    query="SELECT * FROM c",
                    enable_cross_partition_query=True
                ))
                logging.info(f"Total users in container: {len(all_users)}")
               
                # Log details of all users
                for user in all_users:
                    logging.info(f"User: {user.get('id')} - Org ID: {user.get('organization_id')}")
           
            # Process users to remove sensitive information
            users = []
            for user in items:
                # Remove sensitive fields
                if 'passwordHash' in user:
                    del user['passwordHash']
               
                # Clean other sensitive fields if needed
                clean_user = {
                    'id': user.get('id'),
                    'name': user.get('name'),
                    'email': user.get('email'),
                    'role': user.get('role'),
                    'created_at': user.get('created_at'),
                    'updated_at': user.get('updated_at', user.get('created_at')),
                    'organization_id': user.get('organization_id')  # Add this for debugging
                }
               
                users.append(clean_user)
               
        except exceptions as e:
            logging.error(f"Cosmos DB Error: {str(e)}")
            return func.HttpResponse(
                json.dumps({"detail": f"Database error: {str(e)}"}),
                mimetype="application/json",
                status_code=500
            )
       
        # Prepare response with pagination metadata
        response = {
            "data": {
                "users": users,
                "count": len(users),
                "total_count": total_count,
                "page_no": page_no,
                "page_size": page_size,
                "total_pages": (total_count + page_size - 1) // page_size,  # Ceiling division
                "organization_id": organization_id  # Add this for debugging
            }
        }
       
        return func.HttpResponse(
            json.dumps(response),
            mimetype="application/json",
            status_code=200
        )
       
    except Exception as e:
        logging.error(f"Error getting users: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": f"An error occurred while getting users: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )
 
   

#    # Microsoft Graph API Endpoints
# TOKEN_URL = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
# GRAPH_API_URL = "https://graph.microsoft.com/v1.0/users"

# Allowed image formats
# ALLOWED_IMAGE_FORMATS = (".jpg", ".jpeg", ".png")

# # Function to generate a secure password
# def generate_password():
#     import string, random
#     characters = string.ascii_letters + string.digits + "!@#$%^&*"
#     return "".join(random.choice(characters) for _ in range(12))

# # Function to get Azure AD B2C access token
# def get_access_token():
#     payload = {
#         "client_id": CLIENT_ID,
#         "client_secret": CLIENT_SECRET,
#         "scope": "https://graph.microsoft.com/.default",
#         "grant_type": "client_credentials",
#     }
#     response = requests.post(TOKEN_URL, data=payload)
    
#     if response.status_code == 200:
#         return response.json().get("access_token")
    
#     logging.error(f"Failed to get Azure AD token: {response.text}")
#     raise Exception("Failed to retrieve Azure AD token")

# # Function to create a user in Azure AD B2C
# def create_azure_b2c_user(employee_name, email, role):
#     password = generate_password()
#     access_token = get_access_token()

#     headers = {
#         "Authorization": f"Bearer {access_token}",
#         "Content-Type": "application/json",
#     }

#     user_data = {
#         "accountEnabled": True,
#         "displayName": employee_name,
#         "givenName": employee_name.split()[0],
#         "surname": employee_name.split()[-1],
#         "mail": email,
#         "userPrincipalName": email,
#         "mailNickname": email.split("@")[0],
#         "passwordProfile": {
#             "forceChangePasswordNextSignIn": False,
#             "password": password,
#         },
#         "identities": [
#             {
#                 "signInType": "emailAddress",
#                 "issuer": TENANT_NAME,
#                 "issuerAssignedId": email,
#             }
#         ],
#         "jobTitle": role,
#     }

#     response = requests.post(GRAPH_API_URL, headers=headers, json=user_data)
    
#     if response.status_code == 201:
#         return response.json()["id"]
    
#     logging.error(f"Azure AD B2C user creation failed: {response.text}")
#     raise Exception(f"Azure AD B2C user creation failed: {response.text}")

# # Azure Function - Add Employee
# @app.function_name(name="add_employee")
# @app.route(route="employee", methods=[func.HttpMethod.POST])
# @require_auth
# async def add_employee(req: func.HttpRequest) -> func.HttpResponse:
#     try:
#         logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")
#         logging.info(f"User Info: {req.user_info}")

#         # Extract JSON data from the request body
#         json_data = req.get_json()

#         if not json_data:
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'JSON data is required in the request body'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Extract fields from the JSON data
#         employee_id = json_data.get("employeeId")
#         name = json_data.get("employeeName")
#         role = json_data.get("role")
#         email = json_data.get("email")
#         image_name = json_data.get("imageName")

#         # Validate required fields
#         if not all([employee_id, name, role, email]):
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'All fields except image are required'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Validate email format
#         EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
#         if not re.match(EMAIL_REGEX, email):
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'Invalid email format'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Validate image format if provided
#         if image_name and not image_name.lower().endswith(ALLOWED_IMAGE_FORMATS):
#             return func.HttpResponse(
#                 body=json.dumps({'error': f'Invalid image format. Allowed formats: {ALLOWED_IMAGE_FORMATS}'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Get `organizationId` from token
#         organization_id = req.user_info.get("user_id")

#         if not organization_id:
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'Invalid token: organizationId (sub) missing'}),
#                 status_code=401,
#                 mimetype="application/json"
#             )

#         # Check if employeeId already exists in Cosmos DB
#         query = f"SELECT * FROM c WHERE c.employeeId = '{employee_id}'"
#         existing_employees = list(employee_container.query_items(query=query, enable_cross_partition_query=True))

#         if existing_employees:
#             return func.HttpResponse(
#                 body=json.dumps({'warn': f'Employee with employeeId {employee_id} already exists'}),
#                 status_code=409,  # Conflict status code
#                 mimetype="application/json"
#             )

#         # Create user in Azure AD B2C
#         azure_b2c_id = create_azure_b2c_user(name, email, role)

#         # Upload image if provided
#         image_url = json_data.get("imageBase64")  # Assuming image is base64-encoded and handled separately

#         # Create employee record
#         employee_record = {
#             "id": str(uuid.uuid4()),
#             "employeeId": employee_id,
#             "employeeName": name,
#             "role": role,
#             "email": email,
#             "imageUrl": image_url,
#             "organizationId": organization_id,
#             "userId": organization_id,
#             "azure_b2c_id": azure_b2c_id
#         }

#         # Save employee record in Cosmos DB
#         employee_container.create_item(body=employee_record)

#         return func.HttpResponse(
#             body=json.dumps({'message': 'Employee added successfully', 'data': employee_record}),
#             status_code=201,
#             mimetype="application/json"
#         )

#     except Exception as e:
#         logging.error(f"Error adding employee: {str(e)}")
#         return func.HttpResponse(
#             body=json.dumps({'error': str(e)}),
#             status_code=500,
#             mimetype="application/json"
#         )



    
ALLOWED_IMAGE_FORMATS = (".jpg", ".jpeg", ".png")


@app.function_name(name="add_employee")
@app.route(route='employee', methods=[func.HttpMethod.POST])
@require_auth
async def add_employee(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")
        logging.info(f"User Info: {req.user_info}")
        
        # Get organization_id from token
        organization_id = req.user_info.get('user_id')
        if not organization_id:
            return func.HttpResponse(
                body=json.dumps({'warn': 'Invalid token: organizationId (sub) missing'}),
                status_code=401,
                mimetype="application/json"
            )

        # Extract JSON data from the request body
        json_data = req.get_json()

        if not json_data:
            return func.HttpResponse(
                body=json.dumps({'warn': 'JSON data is required in the request body'}),
                status_code=400,
                mimetype="application/json"
            )

        # Extract fields from the JSON data
        name = json_data.get('employeeName')
        role = json_data.get('role')
        email = json_data.get('email')
        image_name = json_data.get('imageName')

        # Generate employeeId from email and organization_id
        email_prefix = email.split('@')[0]
        org_suffix = ''.join(filter(str.isdigit, organization_id))[-4:].zfill(4)  # Ensure 4 digits

        # Initial candidate employee ID
        employee_id_candidate = f"{email_prefix}_{org_suffix}"
        employee_id = employee_id_candidate

        # Ensure uniqueness in Cosmos DB (in case multiple with same email prefix in the same org)
        counter = 1
        while True:
            query = f"SELECT * FROM c WHERE c.organizationId = '{organization_id}' AND c.employeeId = '{employee_id}'"
            existing = list(employee_container.query_items(query=query, enable_cross_partition_query=True))
            if not existing:
                break
            employee_id = f"{employee_id_candidate}_{counter}"
            counter += 1

        # Check if required fields are provided
        if not employee_id or not name or not role or not email:
            return func.HttpResponse(
                body=json.dumps({'warn': 'All fields except image are required'}),
                status_code=400,
                mimetype="application/json"
            )

        # Validate email format using regex
        EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(EMAIL_REGEX, email):
            return func.HttpResponse(
                body=json.dumps({'warn': 'Invalid email format'}),
                status_code=400,
                mimetype="application/json"
            )

        # Validate role format
        if role not in ['Admin', 'User', 'Employee']:
            return func.HttpResponse(
                body=json.dumps({'warn': 'Role must be either Admin, User, or Employee'}),
                status_code=400,
                mimetype="application/json"
            )
            
        # Check if email already exists in Cosmos DB
        email_query = f"SELECT * FROM c WHERE c.email = '{email}'"
        existing_email = list(employee_container.query_items(query=email_query, enable_cross_partition_query=True))

        if existing_email:
            return func.HttpResponse(
                body=json.dumps({'warn': f'Email {email} is already in use'}),
                status_code=409,  # Conflict
                mimetype="application/json"
            )

        # Validate image format if image is provided
        if image_name:
            if not image_name.lower().endswith(ALLOWED_IMAGE_FORMATS):
                return func.HttpResponse(
                    body=json.dumps({'warn': f'Invalid image format. Allowed formats: {ALLOWED_IMAGE_FORMATS}'}),
                    status_code=400,
                    mimetype="application/json"
                )

        # Check if employeeId already exists in Cosmos DB
        query = f"SELECT * FROM c WHERE c.employeeId = '{employee_id}'"
        existing_employees = list(employee_container.query_items(query=query, enable_cross_partition_query=True))

        if existing_employees:
            return func.HttpResponse(
                body=json.dumps({'warn': f'Employee with employeeId {employee_id} already exists'}),
                status_code=409,  # Conflict status code
                mimetype="application/json"
            )

        # Generate a unique user ID for the employee
        user_id = str(uuid.uuid4())
        
        # Upload the image if provided
        image_url = upload_image_to_blob(json_data.get('imageBase64'), employee_id) if json_data.get('imageBase64') else None

        # FIRST, CREATE THE USER IN AZURE AD B2C
        # Azure AD B2C Configuration
        client_id = os.getenv("AZURE_B2C_CLIENT_ID")
        client_secret = os.getenv("AZURE_B2C_CLIENT_SECRET")
        tenant_name = os.getenv("AZURE_B2C_TENANT_NAME")
        tenant_domain = os.getenv("AZURE_B2C_DOMAIN", f"{tenant_name}.onmicrosoft.com")
        
        # Get mail nickname from email
        mail_nickname = email.split('@')[0]
        
        # Generate a secure random password
        def generate_secure_password():
            chars = string.ascii_lowercase + string.ascii_uppercase + string.digits
            special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
            
            while True:
                password = ''.join(random.choice(chars) for _ in range(10))
                password += random.choice(special_chars)
                password += random.choice(special_chars)
                
                password_list = list(password)
                random.shuffle(password_list)
                password = ''.join(password_list)
                
                email_parts = email.lower().split('@')
                username_part = email_parts[0]
                domain_part = email_parts[1] if len(email_parts) > 1 else ""
                
                if (username_part not in password.lower() and
                    domain_part not in password.lower()):
                    return password
        
        password = generate_secure_password()
        
        # Use the standard Azure AD endpoint for client credentials flow
        token_url = f"https://login.microsoftonline.com/{tenant_name}.onmicrosoft.com/oauth2/v2.0/token"
        
        # Get Microsoft Graph token using client credentials flow
        token_data = {
            'client_id': client_id,
            'client_secret': client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }
        
        logging.info(f"Requesting token from: {token_url}")
        
        token_response = requests.post(
            token_url,
            data=token_data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        if token_response.status_code != 200:
            logging.error(f"Token request failed with status {token_response.status_code}")
            logging.error(f"Response body: {token_response.text}")
            return func.HttpResponse(
                body=json.dumps({
                    'warn': f"Failed to authenticate with Azure AD: {token_response.text}",
                }),
                status_code=500,
                mimetype="application/json"
            )
            
        token_result = token_response.json()
        
        if "access_token" not in token_result:
            logging.error(f"Unable to get token: {token_result.get('error')}")
            return func.HttpResponse(
                body=json.dumps({
                    'warn': 'Failed to authenticate with Azure AD',
                }),
                status_code=500,
                mimetype="application/json"
            )
        
        # Check if email already exists in Azure AD B2C
        check_user_url = f"https://graph.microsoft.com/v1.0/users?$filter=identities/any(id:id/issuerAssignedId eq '{email}' and id/issuer eq '{tenant_domain}')"
        check_user_response = requests.get(check_user_url, headers={
            "Authorization": f"Bearer {token_result['access_token']}",
            "Content-Type": "application/json"
        })

        if check_user_response.status_code == 200:
            user_data = check_user_response.json()
            if user_data.get("value"):
                return func.HttpResponse(
                    body=json.dumps({'warn': f'Email {email} already exists in Azure AD B2C'}),
                    status_code=409,
                    mimetype="application/json"
                )
        else:
            logging.warning(f"Failed to check existing B2C user: {check_user_response.text}")

        # Create user in Azure AD B2C
        graph_url = "https://graph.microsoft.com/v1.0/users"
        headers = {
            "Authorization": f"Bearer {token_result['access_token']}",
            "Content-Type": "application/json"
        }
       
        # Prepare the user payload for Azure AD B2C
        display_name = name
        
        # Use the verified tenant domain for userPrincipalName with a unique identifier
        unique_id = user_id.split('-')[0]
        user_principal_name = f"{mail_nickname}_{unique_id}@{tenant_domain}"
        
        # Get the extension app ID for custom attributes
        extension_app_id = None
        try:
            apps_url = "https://graph.microsoft.com/v1.0/applications"
            apps_response = requests.get(
                apps_url,
                headers=headers,
                params={'$filter': 'displayName eq \'b2c-extensions-app\''}
            )
            
            if apps_response.status_code == 200:
                apps_data = apps_response.json()
                
                if apps_data.get('value') and len(apps_data['value']) > 0:
                    app_id = apps_data['value'][0]['appId']
                    extension_app_id = app_id.replace('-', '')
                    logging.info(f"Found extension app ID: {extension_app_id}")
            
        except Exception as e:
            logging.warning(f"Could not retrieve extension app ID: {str(e)}")
        
        # Create user payload with identities included directly
        user_payload = {
            "accountEnabled": True,
            "displayName": display_name,
            "mailNickname": f"{mail_nickname}_{unique_id}",
            "userPrincipalName": user_principal_name,
            "passwordProfile": {
                "forceChangePasswordNextSignIn": False,
                "password": password
            },
            "passwordPolicies": "DisablePasswordExpiration",
            "mail": email,  # Set primary email attribute
            "otherMails": [email],
            # Include identities directly in initial creation
            "identities": [
                {
                    "signInType": "emailAddress",
                    "issuer": tenant_domain,
                    "issuerAssignedId": email
                },
                {
                    "signInType": "userPrincipalName",
                    "issuer": tenant_domain,
                    "issuerAssignedId": user_principal_name
                }
            ],
            "jobTitle": role
        }
        
        # Add role, email, and employeeId as custom attributes
        if extension_app_id:
            user_payload[f"extension_{extension_app_id}_Role"] = role
            user_payload[f"extension_{extension_app_id}_Email"] = email
            user_payload[f"extension_{extension_app_id}_EmployeeId"] = employee_id
            user_payload[f"extension_{extension_app_id}_SignInWithEmail"] = "true"
        
        # Create the user in Azure AD B2C
        try:
            logging.info(f"Creating user in B2C with email {email} and UPN {user_principal_name}")
            b2c_response = requests.post(graph_url, headers=headers, json=user_payload)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error creating user in B2C: {str(e)}")
            return func.HttpResponse(
                json.dumps({"warn": f"Failed to create user in Azure AD B2C: {str(e)}"}),
                status_code=500,
                mimetype="application/json"
            )
        
        if b2c_response.status_code >= 400:
            logging.error(f"Error creating B2C user: Status {b2c_response.status_code}")
            logging.error(f"Response: {b2c_response.text}")
            
            # Return error since we're doing Azure first approach
            return func.HttpResponse(
                body=json.dumps({
                    'error': f"Failed to create user in Azure AD B2C: {b2c_response.text}"
                }),
                status_code=500,
                mimetype="application/json"
            )
        
        b2c_response.raise_for_status()
       
        # Get the Azure AD B2C user ID
        b2c_user = b2c_response.json()
        b2c_user_id = b2c_user.get('id')
       
        # Verify that identities were properly set - if not, update them
        user_get_url = f"https://graph.microsoft.com/v1.0/users/{b2c_user_id}"
        user_get_response = requests.get(user_get_url, headers=headers)
        current_user = user_get_response.json()
       
        # Check if email identity exists
        email_identity_exists = False
        if 'identities' in current_user:
            for identity in current_user['identities']:
                if (identity.get('signInType') == 'emailAddress' and
                    identity.get('issuerAssignedId') == email):
                    email_identity_exists = True
                    break
        
        # If email identity doesn't exist, add it
        if not email_identity_exists:
            logging.info(f"Email identity not found, adding it explicitly for user {b2c_user_id}")
            
            # Get current identities
            current_identities = current_user.get('identities', [])
            
            # Add email identity
            current_identities.append({
                "signInType": "emailAddress",
                "issuer": tenant_name,
                "issuerAssignedId": email
            })
            
            # Update with combined identities
            identity_payload = {
                "identities": current_identities
            }
            
            identity_response = requests.patch(
                user_get_url,
                headers=headers,
                json=identity_payload
            )
            
            if identity_response.status_code >= 400:
                logging.warning(f"Could not add email identity: {identity_response.status_code}")
                logging.warning(f"Response: {identity_response.text}")
            else:
                logging.info(f"Successfully added email identity for user {b2c_user_id}")
        
        # NOW THAT AZURE CREATION IS SUCCESSFUL, CREATE THE EMPLOYEE RECORD
        # Create the employee record with the Azure B2C ID
        employee_record = {
            'id': b2c_user_id,
            'employeeId': employee_id,
            'employeeName': name,
            'role': role,
            'email': email,
            'imageUrl': image_url,
            'organizationId': organization_id,
            'userId': organization_id,
            'azure_b2c_id': b2c_user_id,
            'created_at': pendulum.now().isoformat()
        }

        # Save the employee record in Cosmos DB
        employee_container.create_item(body=employee_record)

        # Send credentials email
        try:
            # Get email configuration from environment variables
            sendgrid_api_key = os.getenv("SENDGRID_API_KEY")
            sender_email = os.getenv("EMAIL_SENDER", os.getenv("FROM_EMAIL"))
            template_id = os.getenv("EMAIL_TEMPLATE_ID", os.getenv("SENDGRID_TEMPLATE_ID"))
            
            if not sendgrid_api_key or not sender_email or not template_id:
                logging.error("Missing email configuration. Check environment variables.")
                raise ValueError("Email configuration incomplete")
            
            logging.info(f"Sending credentials email to {email}")
            
            # Create and send email
            message = Mail(
                from_email=From(sender_email),
                to_emails=To(email)
            )
            
            # Prepare dynamic data for the template
            message.dynamic_template_data = {
                "name": name,
                "employeeName": name,
                "email": email,
                "password": password,
                "otp": password[:6]  # example: sending first 6 characters as OTP
            }
            
            message.template_id = template_id
            
            sg = SendGridAPIClient(sendgrid_api_key)
            response = sg.send(message)
            
            logging.info(f"Email sent to {email}. Status code: {response.status_code}")
            
        except Exception as email_error:
            # Log error but don't fail the request
            logging.error(f"Failed to send email to {email}: {str(email_error)}")
            logging.error(f"SendGrid API Key (first 5 chars): {sendgrid_api_key[:5] if sendgrid_api_key else 'None'}...")
            logging.error(f"Template ID: {template_id}")
            logging.error(f"From Email: {sender_email}")

        # Return the user credentials in the response
        return func.HttpResponse(
            body=json.dumps({
                'message': 'Employee added successfully to Azure AD B2C and database',
            }),
            status_code=201,
            mimetype="application/json"
        )
        
    except Exception as e:
        logging.error(f"Error in add_employee function: {str(e)}")
        import traceback
        logging.error(f"Traceback: {traceback.format_exc()}")
        return func.HttpResponse(
            body=json.dumps({'warn': f'Failed to add employee: {str(e)}'}),
            status_code=500,
            mimetype="application/json"
        )
    

@app.function_name(name="delete_employee")
@app.route(route="employee/{employee_id}", methods=[func.HttpMethod.DELETE])
async def delete_employee(req: func.HttpRequest) -> func.HttpResponse:
    # Validate and decode the token
    try:
        user_info = validate_and_decode_token(req)
        logging.info(f"Token validated for user: {user_info.get('email', 'unknown')}")
    except Exception as e:
        logging.error(f"Unauthorized Request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": "Unauthorized: Missing or Invalid Token"}),
            status_code=401,
            mimetype="application/json"
        )

    logging.info('Processing delete employee request.')

    try:
        # Get the employee ID from the route parameters
        employee_id = req.route_params.get('employee_id')

        # Query to fetch the employee record by id
        query = f"SELECT * FROM c WHERE c.employeeId = '{employee_id}'"
        logging.info(f"Query: {query}")
        items = list(employee_container.query_items(query=query, enable_cross_partition_query=True))
        logging.info(f"Items found: {items}")

        if items:
            item = items[0]  # Get the first (and expected only) result

            # Get the Azure AD B2C ID (assuming it's stored as 'azure_b2c_id')
            b2c_user_id = item.get('azure_b2c_id')
            if not b2c_user_id:
                return func.HttpResponse(
                    body=json.dumps({'warn': 'Employee does not have an Azure B2C ID'}),
                    status_code=400,
                    mimetype="application/json"
                )

            # Azure AD B2C Configuration
            client_id = os.getenv("AZURE_B2C_CLIENT_ID")
            client_secret = os.getenv("AZURE_B2C_CLIENT_SECRET")
            tenant_name = os.getenv("AZURE_B2C_TENANT_NAME")
            tenant_domain = os.getenv("AZURE_B2C_DOMAIN", f"{tenant_name}.onmicrosoft.com")

            # Get Microsoft Graph token using client credentials flow
            token_url = f"https://login.microsoftonline.com/{tenant_name}.onmicrosoft.com/oauth2/v2.0/token"
            token_data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': 'https://graph.microsoft.com/.default',
                'grant_type': 'client_credentials'
            }

            token_response = requests.post(
                token_url,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            if token_response.status_code != 200:
                logging.error(f"Token request failed with status {token_response.status_code}")
                logging.error(f"Response body: {token_response.text}")
                return func.HttpResponse(
                    body=json.dumps({
                        'warn': f"Failed to authenticate with Azure AD: {token_response.text}",
                    }),
                    status_code=500,
                    mimetype="application/json"
                )

            token_result = token_response.json()
            if "access_token" not in token_result:
                logging.error(f"Unable to get token: {token_result.get('error')}")
                return func.HttpResponse(
                    body=json.dumps({
                        'warn': 'Failed to authenticate with Azure AD',
                    }),
                    status_code=500,
                    mimetype="application/json"
                )

            # Delete user from Azure AD B2C
            graph_url = f"https://graph.microsoft.com/v1.0/users/{b2c_user_id}"
            headers = {
                "Authorization": f"Bearer {token_result['access_token']}",
                "Content-Type": "application/json"
            }

            delete_response = requests.delete(graph_url, headers=headers)

            if delete_response.status_code >= 400:
                logging.error(f"Error deleting B2C user: Status {delete_response.status_code}")
                logging.error(f"Response: {delete_response.text}")
                return func.HttpResponse(
                    body=json.dumps({
                        'warn': f"Failed to delete user from Azure AD B2C: {delete_response.text}"
                    }),
                    status_code=500,
                    mimetype="application/json"
                )

            logging.info(f"Employee {employee_id} deleted successfully from Azure AD B2C.")

            # Delete the employee record from Cosmos DB
            # Use the partition key and document id for deletion
            employee_container.delete_item(item=item['id'], partition_key=item['id'])

            logging.info(f"Employee {employee_id} deleted successfully from Cosmos DB.")

            return func.HttpResponse(
                body=json.dumps({'warn': 'Employee deleted successfully from Azure AD B2C and database'}),
                status_code=200,
                mimetype="application/json"
            )

        return func.HttpResponse(
            body=json.dumps({'warn': 'Employee not found'}),
            status_code=404,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error deleting employee: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'warn': str(e)}),
            status_code=500,
            mimetype="application/json"
        )
    


@app.function_name(name="update_employee")
@app.route(route="update-employee/{employee_id}", methods=[func.HttpMethod.PUT])
@require_auth
async def update_employee(req: func.HttpRequest) -> func.HttpResponse:
    logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")
    logging.info('Processing update employee request.')

    try:
        # Get employee ID from the route and validate
        employee_id = str(req.route_params.get('employee_id'))
        if not employee_id:
            return func.HttpResponse(
                json.dumps({'warn': 'Employee ID is required'}), 
                status_code=400, 
                mimetype="application/json"
            )

        # Parse request body to get the update data
        try:
            data = req.get_json()
        except ValueError:
            return func.HttpResponse(
                json.dumps({'error': 'Invalid JSON in request body'}), 
                status_code=400, 
                mimetype="application/json"
            )

        logging.info(f"Processing update for employee ID: {employee_id}")

        # Fetch the existing employee record from Cosmos DB
        query = "SELECT * FROM c WHERE c.employeeId = @employeeId"
        parameters = [{"name": "@employeeId", "value": employee_id}]
        items = list(employee_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        if not items:
            return func.HttpResponse(
                json.dumps({'warn': 'Employee not found'}), 
                status_code=404, 
                mimetype="application/json"
            )

        item = items[0]  # Existing employee record

        # Handle image upload if new image is provided
        new_image_base64 = data.get('newImageBase64')
        if new_image_base64:  # Only process if a new image is provided
            try:
                # Upload the new image and get its URL
                new_image_url = upload_image_to_blob(new_image_base64, employee_id)

                if new_image_url:
                    # If there was a previous image, delete it
                    if item.get('imageUrl'):
                        delete_image_from_blob(item['imageUrl'])

                    # Update the image URL in the employee record
                    item['imageUrl'] = new_image_url
                    logging.info(f"Updated image URL for employee {employee_id}: {new_image_url}")
            except Exception as e:
                logging.error(f"Error handling image upload: {e}")
                return func.HttpResponse(
                    json.dumps({'warn': f'Error processing image: {str(e)}'}), 
                    status_code=500, 
                    mimetype="application/json"
                )
        else:
            logging.info(f"No new image provided. Keeping existing image URL: {item.get('imageUrl')}")

        # Define the allowed fields
        allowed_fields = {
            "employeeName", "role", "email", "organizationId", "userId"
        }
        # Remove protected fields from the update data
        protected_fields = {'id', '_rid', '_self', '_etag', '_attachments', '_ts', 'employeeId', 'newImageBase64'}
        update_data = {k: v for k, v in data.items() if k in allowed_fields and k not in protected_fields}

        # Update the existing employee record with new data
        item.update(update_data)

        # Azure AD B2C Update Logic
        b2c_user_id = item.get('azure_b2c_id')
        if b2c_user_id:
            # Update user information in Azure AD B2C
            client_id = os.getenv("AZURE_B2C_CLIENT_ID")
            client_secret = os.getenv("AZURE_B2C_CLIENT_SECRET")
            tenant_name = os.getenv("AZURE_B2C_TENANT_NAME")
            tenant_domain = os.getenv("AZURE_B2C_DOMAIN", f"{tenant_name}.onmicrosoft.com")

            # Get Microsoft Graph token using client credentials flow
            token_url = f"https://login.microsoftonline.com/{tenant_name}.onmicrosoft.com/oauth2/v2.0/token"
            token_data = {
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': 'https://graph.microsoft.com/.default',
                'grant_type': 'client_credentials'
            }

            token_response = requests.post(
                token_url,
                data=token_data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            )

            if token_response.status_code != 200:
                logging.error(f"Token request failed with status {token_response.status_code}")
                logging.error(f"Response body: {token_response.text}")
                return func.HttpResponse(
                    body=json.dumps({
                        'warn': f"Failed to authenticate with Azure AD: {token_response.text}",
                    }),
                    status_code=500,
                    mimetype="application/json"
                )

            token_result = token_response.json()
            if "access_token" not in token_result:
                logging.error(f"Unable to get token: {token_result.get('error')}")
                return func.HttpResponse(
                    body=json.dumps({
                        'warn': 'Failed to authenticate with Azure AD',
                    }),
                    status_code=500,
                    mimetype="application/json"
                )

            graph_url = f"https://graph.microsoft.com/v1.0/users/{b2c_user_id}"
            headers = {
                "Authorization": f"Bearer {token_result['access_token']}",
                "Content-Type": "application/json"
            }

            # Make PATCH request to update the user in Azure AD B2C
            update_data_b2c = {
                "displayName": item.get("employeeName"),
                "givenName": item.get("employeeName"),
                "jobTitle": item.get("role")
                }

            

            update_response = requests.patch(graph_url, headers=headers, json=update_data_b2c)

            if update_response.status_code not in [200, 204]:
                logging.error(f"Error updating Azure AD B2C user: Status {update_response.status_code}")
                logging.error(f"Response: {update_response.text}")
                return func.HttpResponse(
                    body=json.dumps({
                        'warn': f"Failed to update user in Azure AD B2C: {update_response.text}"
                    }),
                    status_code=500,
                    mimetype="application/json"
                )

            logging.info(f"Employee {employee_id} updated successfully in Azure AD B2C.")

        # Replace the employee record in Cosmos DB
        try:
            employee_container.replace_item(
                item=item['id'],
                body=item
            )
            logging.info(f"Employee {employee_id} updated successfully in Cosmos DB.")
        except exceptions.CosmosHttpResponseError as e:
            logging.error(f"Error updating employee in Cosmos DB: {e}")

            # Clean up the newly uploaded image in case of an error
            if new_image_base64 and 'new_image_url' in locals():
                delete_image_from_blob(new_image_url)

            return func.HttpResponse(
                json.dumps({'error': 'Failed to update employee record'}), 
                status_code=500, 
                mimetype="application/json"
            )

        # Return the updated employee data as the response
        return func.HttpResponse(
            json.dumps({
                'message': 'Employee updated successfully',
                'data': item
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Unexpected error in update_employee: {e}")
        return func.HttpResponse(
            json.dumps({'warn': str(e)}),
            status_code=500,
            mimetype="application/json"
        )


# search user-Tracker
@app.function_name(name="searchUsers")
@app.route(route='api/searchUsers', methods=[func.HttpMethod.GET])
@require_auth
async def search_users(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    organization_id = user_info['sub']
   
    try:
        # Get single search parameter
        search_term = req.params.get('search', '').lower().strip()
       
        # Debug logging
        logging.info(f"Searching users for organization_id: {organization_id}, search_term: {search_term}")
       
        # Base query with organization filter
        query = "SELECT * FROM c WHERE c.organization_id = @org_id"
        query_params = [{"name": "@org_id", "value": organization_id}]
       
        valid_roles = ['user', 'admin']
       
        # Apply search term to both name and role
        if search_term:
            # Search for name with partial match
            query += " AND (LOWER(c.name) LIKE @name"
            query_params.append({"name": "@name", "value": f"%{search_term}%"})
           
            # Search for role with partial match
            query += " OR LOWER(c.role) LIKE @role)"
            query_params.append({"name": "@role", "value": f"%{search_term}%"})
       
        query_options = {
            'enable_cross_partition_query': True
        }
       
        # Inner try block for database query
        try:
            items = list(users_container.query_items(
                query=query,
                parameters=query_params,
                **query_options
            ))
           
            logging.info(f"Query returned {len(items)} items")
           
            if not items:
                logging.info("No matching users found with specified criteria")
           
            # Process users
            users = []
            for user in items:
                if 'passwordHash' in user:
                    del user['passwordHash']
               
                clean_user = {
                    'id': user.get('id'),
                    'name': user.get('name'),
                    'email': user.get('email'),
                    'role': user.get('role'),
                    'created_at': user.get('created_at'),
                    'updated_at': user.get('updated_at', user.get('created_at')),
                    'organization_id': user.get('organization_id')
                }
                users.append(clean_user)
               
        except exceptions as e:
            logging.error(f"Cosmos DB Error: {str(e)}")
            return func.HttpResponse(
                json.dumps({"detail": f"Database error: {str(e)}"}),
                mimetype="application/json",
                status_code=500
            )
       
        # Prepare response
        response = {
            "data": {
                "users": users,
                "count": len(users),
                "search_criteria": {
                    "search_term": search_term if search_term else None,
                    "organization_id": organization_id
                }
            }
        }
       
        return func.HttpResponse(
            json.dumps(response),
            mimetype="application/json",
            status_code=200
        )
   
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": f"An unexpected error occurred: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )
 
# getall employees organization(id) based

@app.function_name(name="get_all_employees")
@app.route(route='employees', methods=[func.HttpMethod.GET])
@require_auth
async def get_all_employees(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")

        # Extract organizationId (sub) from token
        organization_id = req.user_info.get('sub')

        if not organization_id:
            logging.error("Invalid token: organizationId (sub) missing")
            return func.HttpResponse(
                json.dumps({"warn": "Invalid token: organizationId (sub) missing"}),
                status_code=401,
                mimetype="application/json"
            )

        # Pagination parameters
        page_number = int(req.params.get('page_number', 1))
        page_size = int(req.params.get('page_size', 10))
        offset = (page_number - 1) * page_size

        # Query employees based on organizationId
        query = "SELECT * FROM c WHERE c.organizationId = @organizationId"
        parameters = [{"name": "@organizationId", "value": organization_id}]

        employees = list(employee_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))

        total_records = len(employees)
        paginated_items = employees[offset:offset + page_size]

        response_body = {
            "page_number": page_number,
            "page_size": page_size,
            "total_records": total_records,
            "employees": paginated_items
        }

        return func.HttpResponse(
            body=json.dumps(response_body),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error fetching employees for organizationId {organization_id}: {str(e)}")
        return func.HttpResponse(
            json.dumps({'warn': "Internal server error"}),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name(name="checkUserExists")
@app.route(route='api/checkUserExists', methods=[func.HttpMethod.GET])
@require_auth
async def check_user_exists(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    organization_id = user_info['sub']
   
    try:
        # Query for setup-details container (using organizationId)
        setup_query = "SELECT VALUE COUNT(1) FROM c WHERE c.organization_id = @organization_id"
        # Query for cameraUrls container (using organization_id)
        camera_query = "SELECT VALUE COUNT(1) FROM c WHERE c.organizationId = @organization_id"
       
        parameters = [{"name": "@organization_id", "value": organization_id}]
       
        # Query setup-details container
        setup_items = list(setup_container.query_items(
            query=setup_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
       
        # Query cameraUrls container
        camera_items = list(camera_urls_container.query_items(
            query=camera_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
       
        # Check existence in each container
        occupancy_exists = setup_items[0] > 0
        attendance_exists = camera_items[0] > 0
       
        return func.HttpResponse(
            json.dumps({
                "data": {
                    "occupancy": occupancy_exists,
                    "attendance": attendance_exists,
                    "message": "Checked organization ID in both containers"
                }
            }),
            mimetype="application/json",
            status_code=200
        )
    except Exception as e:
        logging.error(f"Error checking if user exists: {str(e)}")
        return func.HttpResponse(
            json.dumps({"warn": "An error occurred while checking if the user exists."}),
            mimetype="application/json",
            status_code=500
        )
    


def send_credentials_email(to_email: str, name: str, email: str, password: str):
    sendgrid_api_key = os.getenv("SENDGRID_API_KEY")
    sender_email = os.getenv("EMAIL_SENDER", os.getenv("FROM_EMAIL")) # Fallback if EMAIL_SENDER not found
    template_id = os.getenv("EMAIL_TEMPLATE_ID", os.getenv("SENDGRID_TEMPLATE_ID")) # Fallback
    
    message = Mail(
        from_email=From(sender_email, "Yectra"),
        to_emails=To(to_email)
    )
    
    message.dynamic_template_data = {
        "name": name,
        "email": email,
        "password": password,
        "employeeName": name,  # Adding these to match your original code
        "otp": password[:6]    # Adding these to match your original code
    }

    message.template_id = template_id

    try:
        sg = SendGridAPIClient(sendgrid_api_key)
        response = sg.send(message)
        logging.info(f"Dynamic template email sent to {to_email}. Status code: {response.status_code}")
        return True
    except Exception as e:
        logging.error(f"Error sending email to {to_email}: {str(e)}")
        return False


def get_alert_info(
    organization_id: str,
    total_current_count: int,
    setup_container: ContainerProxy
) -> Tuple[bool, int, int, float]:
    """
    Calculate alert flag and related metrics for an organization.
   
    Args:
        organization_id: The ID of the organization.
        total_current_count: Sum of current counts across cameras.
        setup_container: Cosmos DB container client for setup-details.
   
    Returns:
        Tuple of (alert_flag, capacity, alert_message, occupancy_percentage).
    """
    try:
        # Query capacity and alertMessage
        setup_query = "SELECT c.capacityOfPeople, c.alertMessage FROM c WHERE c.organization_id = @org_id"
        parameters = [{"name": "@org_id", "value": organization_id}]
        setup_items = list(setup_container.query_items(
            query=setup_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        capacity = setup_items[0].get("capacityOfPeople", 0) if setup_items else 0
        alert_message_str = setup_items[0].get("alertMessage", "0") if setup_items else "0"
 
        if capacity == 0:
            logging.warning(f"No capacity defined for organization_id: {organization_id}")
 
        # Parse alertMessage
        try:
            alert_message = int(float(alert_message_str.replace('%', '').strip()))
        except (ValueError, AttributeError) as e:
            logging.error(f"Failed to parse alertMessage '{alert_message_str}': {str(e)}")
            alert_message = 0
 
        # Calculate occupancy percentage
        occupancy_percentage = (total_current_count / capacity * 100) if capacity > 0 else 0
 
        # Determine alert flag
        alert_flag = occupancy_percentage >= alert_message
 
        return alert_flag, capacity, alert_message, round(occupancy_percentage, 2)
 
    except Exception as e:
        logging.error(f"Error calculating alert info: {type(e).__name__}: {str(e)}")
        return False, 0, 0, 0.0
    
@app.function_name(name="getFailedCameraStatus")
@app.route(route='api/getAllCameraStatus', methods=[func.HttpMethod.GET])
@require_auth
async def get_failed_camera_status(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    if not user_info or 'sub' not in user_info:
        logging.error("Missing or invalid user_info in request")
        return func.HttpResponse(
            json.dumps({"status": "error", "detail": "Unauthorized: Missing user information"}),
            mimetype="application/json",
            status_code=401
        )
 
    organization_id = user_info['sub']
    logging.info(f"Fetching failed camera statuses for organization_id: {organization_id}")
 
    try:
        # Initialize containers
 
        # Query failed camera statuses
        query = "SELECT * FROM c WHERE c.user_id = @org_id AND c.status = 'failed'"
        query_params = [{"name": "@org_id", "value": organization_id}]
        items = list(camera_status_container.query_items(
            query=query,
            parameters=query_params,
            enable_cross_partition_query=True
        ))
        logging.info(f"Query returned {len(items)} failed camera statuses")
 
        # Get total count
        count_query = "SELECT VALUE COUNT(1) FROM c WHERE c.user_id = @org_id AND c.status = 'failed'"
        total_count = list(camera_status_container.query_items(
            query=count_query,
            parameters=query_params,
            enable_cross_partition_query=True
        ))[0]
 
        if not items:
            logging.info(f"No failed camera statuses found for organization_id: {organization_id}")
 
        # Process camera statuses
        camera_statuses = []
        for status in items:
            timestamp = status.get('timestamp')
            try:
                if isinstance(timestamp, str):
                    dt = isodate.parse_datetime(timestamp)
                elif isinstance(timestamp, (int, float)):
                    dt = datetime.fromtimestamp(timestamp)
                else:
                    raise ValueError("Invalid timestamp format")
                readable_date = dt.strftime("%Y-%m-%d")
                readable_time = dt.strftime("%H:%M:%S")
            except Exception as e:
                logging.warning(f"Error parsing timestamp {timestamp}: {str(e)}")
                readable_date = "Unknown"
                readable_time = "Unknown"
 
            camera_statuses.append({
                'id': status.get('id'),
                'user_id': status.get('user_id'),
                'camera_id': status.get('camera_id'),
                'videoUrl': status.get('videoUrl'),
                'status': status.get('status'),
                'date': readable_date,
                'time': readable_time
            })
 
        # Get counts
        counts_query = "SELECT c.cameras FROM c WHERE c.user_id = @org_id"
        count_items = list(user_counts_container.query_items(
            query=counts_query,
            parameters=query_params,
            enable_cross_partition_query=True
        ))
 
        total_current_count = 0
        if count_items:
            cameras_data = count_items[0].get("cameras", {})
            for camera_id, camera_data in cameras_data.items():
                entry = camera_data.get("entry_count", 0)
                exit = camera_data.get("exit_count", 0)
                total_current_count += entry - exit
 
        # Get alert info
        alert_flag, capacity, alert_message, occupancy_percentage = get_alert_info(
            organization_id, total_current_count, setup_container
        )
 
        # Prepare response
        response = {
            "data": {
                "camera_statuses": camera_statuses,
                "total_count": total_count,
                "alert": alert_flag,
                "capacity": capacity,
                "alert_message": alert_message,
                "total_current_count": total_current_count,
                "occupancy_percentage": occupancy_percentage
            }
        }
        return func.HttpResponse(
            json.dumps(response),
            mimetype="application/json",
            status_code=200
        )
 
    except Exception as e:
        logging.error(f"Error getting failed camera statuses: {type(e).__name__}: {str(e)}")
        return func.HttpResponse(
            json.dumps({"status": "error", "detail": f"An error occurred: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )


@app.function_name(name="editPersonCountByDate")
@app.route(route='api/editPersonCountByDate', methods=[func.HttpMethod.PUT])
@require_auth
async def edit_person_count_by_date(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Get user info and ID
        user_info = req.user_info
        user_id = user_info['sub']
       
        # Initialize containers
        users_container = database.get_container_client(USERS)
        user_logs_container = database.get_container_client(USER_LOGS)
       
        # Get request body
        try:
            req_body = req.get_json()
        except ValueError:
            return func.HttpResponse(
                json.dumps({"error": "Invalid JSON in request body"}),
                status_code=400,
                mimetype="application/json"
            )
       
        # Validate required parameters
        date_param = req_body.get('date')
        new_entries = req_body.get('entries')
        new_exits = req_body.get('exits')
       
        if not date_param:
            return func.HttpResponse(
                json.dumps({"error": "Missing required parameter: date"}),
                status_code=400,
                mimetype="application/json"
            )
       
        if new_entries is None and new_exits is None:
            return func.HttpResponse(
                json.dumps({"error": "At least one of entries or exits must be provided"}),
                status_code=400,
                mimetype="application/json"
            )
       
        # Validate date format
        try:
            selected_date = pendulum.parse(date_param).format('YYYY-MM-DD')
        except Exception as e:
            return func.HttpResponse(
                json.dumps({"error": f"Invalid date format. Please use YYYY-MM-DD. Details: {str(e)}"}),
                status_code=400,
                mimetype="application/json"
            )
       
        # Validate count value
        try:
            if new_entries is not None:
                new_entries = int(new_entries)
                if new_entries < 0:
                    return func.HttpResponse(
                        json.dumps({"error": "Entries must be non-negative integer"}),
                        status_code=400,
                        mimetype="application/json"
                    )
            if new_exits is not None:
                new_exits = int(new_exits)
                if new_exits < 0:
                    return func.HttpResponse(
                        json.dumps({"error": "Exits must be non-negative integer"}),
                        status_code=400,
                        mimetype="application/json"
                    )
        except (ValueError, TypeError):
            return func.HttpResponse(
                json.dumps({"error": "Entries or exits must be valid integers"}),
                status_code=400,
                mimetype="application/json"
            )
       
        # Get organization_id from users container
        user_query = "SELECT c.organization_id FROM c WHERE c.azure_b2c_id = @user_id"
        user_params = [{"name": "@user_id", "value": user_id}]
       
        user_items = list(users_container.query_items(
            query=user_query,
            parameters=user_params,
            enable_cross_partition_query=True
        ))
       
        organization_id = user_items[0]['organization_id'] if user_items and 'organization_id' in user_items[0] else user_id
       
        # Query existing logs for the organization
        logs_query = """
        SELECT * FROM c
        WHERE c.user_id = @organization_id
        """
        parameters = [{"name": "@organization_id", "value": organization_id}]
       
        logs_items = list(user_logs_container.query_items(
            query=logs_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
       
        # Prepare the updated document
        if logs_items:
            doc = logs_items[0]
            logs = doc.get("logs", [])
            manual_adjustments = doc.get("manual_adjustments", [])
        else:
            doc = {
                "id": organization_id,
                "user_id": organization_id,
                "logs": [],
                "manual_adjustments": []
            }
            logs = []
            manual_adjustments = []
       
        # Check if there's an existing manual adjustment for this date
        existing_adjustment_index = next(
            (i for i, adjustment in enumerate(manual_adjustments)
             if adjustment.get("date") == selected_date),
            None
        )
       
        # Prepare the new manual adjustment entry
        if existing_adjustment_index is not None:
            # Use existing values for unchanged field
            existing_entry = manual_adjustments[existing_adjustment_index]
            current_entries = existing_entry.get("entries", 0)
            current_exits = existing_entry.get("exits", 0)
           
            new_adjustment_entry = {
                "date": selected_date,
                "entries": new_entries if new_entries is not None else current_entries,
                "exits": new_exits if new_exits is not None else current_exits,
                "updated_at": pendulum.now().to_iso8601_string()
            }
            manual_adjustments[existing_adjustment_index] = new_adjustment_entry
        else:
            # New entry, set default 0 for unchanged field
            new_adjustment_entry = {
                "date": selected_date,
                "entries": new_entries if new_entries is not None else 0,
                "exits": new_exits if new_exits is not None else 0,
                "updated_at": pendulum.now().to_iso8601_string()
            }
            manual_adjustments.append(new_adjustment_entry)
       
        # Update the document with new manual adjustments
        doc["manual_adjustments"] = manual_adjustments
       
        # Upsert the document
        user_logs_container.upsert_item(doc)
       
        # Prepare response
        response_data = {
            "date": selected_date,
            "updated_at": new_adjustment_entry["updated_at"],
            "entries": new_adjustment_entry["entries"],
            "exits":new_adjustment_entry["exits"]
        }
       
        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )
   
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Cosmos DB error in putPersonCountByDate: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Database error: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Unexpected error in putPersonCountByDate: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"An unexpected error occurred: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name(name="getFailedCameraStatusAttendance")
@app.route(route='api/getFailedCameraStatusAttendance', methods=[func.HttpMethod.GET])
@require_auth
async def get_failed_camera_status(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    if not user_info or 'sub' not in user_info:
        logging.error("Missing or invalid user_info in request")
        return func.HttpResponse(
            json.dumps({"status": "error", "detail": "Unauthorized: Missing user information"}),
            mimetype="application/json",
            status_code=401
        )
 
    organization_id = user_info['sub']
    logging.info(f"Fetching failed camera statuses for organization_id: {organization_id}")
 
    try:
        # Query failed camera statuses
        query = "SELECT * FROM c WHERE c.organizationId = @org_id AND c.status = 'offline'"
        query_params = [{"name": "@org_id", "value": organization_id}]
        items = list(camera_status_container_attendance.query_items(
            query=query,
            parameters=query_params,
            enable_cross_partition_query=True
        ))
        logging.info(f"Query returned {len(items)} failed camera statuses")
 
        if not items:
            logging.info(f"No failed camera statuses found for organization_id: {organization_id}")
 
        # Process camera statuses
        camera_statuses = []
        for status in items:
            # Map status: "offline" to "failed"
            display_status = "failed" if status.get('status') == "offline" else status.get('status')
           
            timestamp = status.get('lastUpdated')
            try:
                if isinstance(timestamp, str):
                    dt = isodate.parse_datetime(timestamp)
                elif isinstance(timestamp, (int, float)):
                    dt = datetime.fromtimestamp(timestamp)
                else:
                    raise ValueError("Invalid timestamp format")
                readable_date = dt.strftime("%Y-%m-%d")
                readable_time = dt.strftime("%H:%M:%S")
            except Exception as e:
                logging.warning(f"Error parsing timestamp {timestamp}: {str(e)}")
                readable_date = "Unknown"
                readable_time = "Unknown"
 
            # Determine camera direction (punchinCamera or punchoutCamera)
            camera_direction = status.get('punchinCamera') or status.get('punchoutCamera') or "Unknown"
 
            camera_statuses.append({
                'id': status.get('id'),
                'user_id': status.get('organizationId'),
                'camera_id': status.get('cameraId'),
                'videoUrl': status.get('url'),
                'status': display_status,
                'camera_type': status.get('cameraType'),
                'date': readable_date,
                'time': readable_time,
                'camera_name': camera_direction  # Add camera direction
            })
 
        # Prepare response
        response = {
            "data": {
                "camera_statuses": camera_statuses,
                "total_count": len(items)
            }
        }
        return func.HttpResponse(
            json.dumps(response),
            mimetype="application/json",
            status_code=200
        )
 
    except Exception as e:
        logging.error(f"Error getting failed camera statuses: {type(e).__name__}: {str(e)}")
        return func.HttpResponse(
            json.dumps({"status": "error", "detail": f"An error occurred: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )
 
 

@app.function_name(name="resetManualAdjustments")
@app.route(route='api/resetManualAdjustments', methods=[func.HttpMethod.POST])
@require_auth
async def reset_manual_adjustments(req: func.HttpRequest) -> func.HttpResponse:
    try:
        user_info = req.user_info
        user_id = user_info['sub']
       
        # Initialize containers
        users_container = database.get_container_client(USERS)
        user_logs_container = database.get_container_client(USER_LOGS)
       
        # Get request body
        try:
            req_body = req.get_json()
        except ValueError:
            return func.HttpResponse(
                json.dumps({"error": "Invalid JSON in request body"}),
                status_code=400,
                mimetype="application/json"
            )
       
        # Extract date parameters from the request body
        date_param = req_body.get('date')
        start_date_param = req_body.get('start_date')
        end_date_param = req_body.get('end_date')
       
        # Validate that at least one date parameter is provided
        if not (date_param or (start_date_param and end_date_param)):
            return func.HttpResponse(
                json.dumps({"error": "Either 'date' or both 'start_date' and 'end_date' must be provided in the request body"}),
                status_code=400,
                mimetype="application/json"
            )
       
        # Determine reset mode (single date or range)
        if start_date_param and end_date_param:
            try:
                start_date = pendulum.parse(start_date_param).start_of('day')
                end_date = pendulum.parse(end_date_param).end_of('day')
                if start_date > end_date:
                    return func.HttpResponse(
                        json.dumps({"error": "start_date cannot be after end_date"}),
                        status_code=400,
                        mimetype="application/json"
                    )
                mode = "range"
            except Exception as e:
                return func.HttpResponse(
                    json.dumps({"error": f"Invalid date format for start_date or end_date. Please use YYYY-MM-DD. Details: {str(e)}"}),
                    status_code=400,
                    mimetype="application/json"
                )
        elif date_param:
            try:
                selected_date = pendulum.parse(date_param).start_of('day')
                start_date = selected_date
                end_date = selected_date.end_of('day')
                mode = "single"
            except Exception as e:
                return func.HttpResponse(
                    json.dumps({"error": f"Invalid date format. Please use YYYY-MM-DD. Details: {str(e)}"}),
                    status_code=400,
                    mimetype="application/json"
                )
       
        # Get organization_id from users container
        user_query = "SELECT c.organization_id FROM c WHERE c.organization_id = @user_id"
        user_params = [{"name": "@user_id", "value": user_id}]
       
        user_items = list(users_container.query_items(
            query=user_query,
            parameters=user_params,
            enable_cross_partition_query=True
        ))
       
        if not user_items or 'organization_id' not in user_items[0]:
            return func.HttpResponse(
                json.dumps({"error": "User or organization not found"}),
                status_code=404,
                mimetype="application/json"
            )
       
        organization_id = user_items[0]['organization_id']
       
        # Find the user_logs document for the organization
        logs_query = "SELECT * FROM c WHERE c.user_id = @organization_id"
        logs_params = [{"name": "@organization_id", "value": organization_id}]
       
        log_items = list(user_logs_container.query_items(
            query=logs_query,
            parameters=logs_params,
            enable_cross_partition_query=True
        ))
       
        if not log_items:
            return func.HttpResponse(
                json.dumps({"error": "No logs found for the organization"}),
                status_code=404,
                mimetype="application/json"
            )
       
        # Update the document by filtering manual_adjustments
        log_document = log_items[0]
        manual_adjustments = log_document.get('manual_adjustments', [])
       
        filtered_adjustments = []
        for adjustment in manual_adjustments:
            try:
                adjustment_date = pendulum.parse(adjustment.get("date")).start_of('day')
                if not (start_date <= adjustment_date <= end_date):
                    filtered_adjustments.append(adjustment)
            except Exception as parse_error:
                logging.warning(f"Failed to parse manual adjustment date {adjustment.get('date')}: {str(parse_error)}")
                filtered_adjustments.append(adjustment)  # Keep invalid dates
        log_document['manual_adjustments'] = filtered_adjustments
       
        # Replace the document in the container
        user_logs_container.replace_item(
            item=log_document['id'],
            body=log_document
        )
       
        # Prepare response message
        response_data = {
            "message": "Manual adjustments successfully reset",
            "organization_id": organization_id
        }
        if mode == "single":
            response_data["date"] = start_date.format('YYYY-MM-DD')
        elif mode == "range":
            response_data["date_range"] = {
                "start_date": start_date.format('YYYY-MM-DD'),
                "end_date": end_date.format('YYYY-MM-DD')
            }
       
        return func.HttpResponse(
            json.dumps(response_data),
            status_code=200,
            mimetype="application/json"
        )
   
    except Exception as e:
        logging.error(f"Unexpected error in resetManualAdjustments: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"An unexpected error occurred: {str(e)}"}),
            status_code=500,
            mimetype="application/json"
        )