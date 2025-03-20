import asyncio
import functools
import json
import logging
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
from datetime import datetime,date
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
import jwt
from jwt.exceptions import InvalidTokenError
import requests
import azure.functions as func
from typing import Dict, Any, Callable
from collections import defaultdict
from urllib.parse import quote
from azure.identity import ClientSecretCredential
from azure.core.exceptions import HttpResponseError
import urllib.parse

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
CLIENT_ID = os.getenv("AZURE_B2C_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_B2C_CLIENT_SECRET")
USER_COUNTS=os.getenv('USER_COUNTS')
USER_LOGS=os.getenv('USER_LOGS')
GRAPH_API_URL = os.getenv('GRAPH_API_URL')
GRAPH_SCOPE = os.getenv('GRAPH_SCOPE')

# Configure logging
logging.basicConfig(level=logging.DEBUG)  # Set the logging level to DEBUG

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
  # Define attendance_container

setup_container_name = database.get_container_client(SETUP_CONTAINER_NAME)
counts_container = database.get_container_client(COUNTS_CONTAINER)
person_features =database.get_container_client(PERSON_FEATURE_CONTAINER)
user_counts_container = database.get_container_client(USER_COUNTS)
user_logs_container = database.get_container_client(USER_LOGS)
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
            issuer=B2C_ISSUER
        )

        # Log the expected vs actual issuer
        logging.info(f"Expected Issuer: {B2C_ISSUER}")
        logging.info(f"Actual Issuer in Token: {decoded_token.get('iss')}")

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
            json.dumps({"error": "Employee ID missing in request"}),
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
            json.dumps({'message': 'Employee not found'}),
            status_code=404,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error fetching employee with ID {employee_id}: {str(e)}")
        return func.HttpResponse(
            json.dumps({'error': "Internal server error"}),
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
@app.function_name(name="get_all_employees")
@app.route(route='employees', methods=[func.HttpMethod.GET])
@require_auth
async def get_all_employees(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")

        # Proceed with the rest of the logic
        page_number = int(req.params.get('page_number', 1))
        page_size = int(req.params.get('page_size', 10))
        offset = (page_number - 1) * page_size

        query = "SELECT * FROM c"
        all_items = list(employee_container.query_items(query=query, enable_cross_partition_query=True))
        paginated_items = all_items[offset:offset + page_size]

        return func.HttpResponse(
            body=json.dumps(paginated_items),
            status_code=200,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Error fetching employees: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': str(e)}),
            status_code=500,
            mimetype="application/json"
        )






                                           # Search bar Attendance

@app.function_name(name="search_bar_attendance")
@app.route(route='attendance/search', methods=[func.HttpMethod.GET])
@require_auth
async def search_attendance(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")

        # Retrieve query parameters
        employee_id = req.params.get('employeeId')
        employee_name = req.params.get('employeeName')
        date = req.params.get('date')
        page_number = req.params.get('page_number', 1)
        page_size = req.params.get('page_size', 10)

        logging.info(f"Search Parameters - employee_id: {employee_id}, employee_name: {employee_name}, date: {date}, page_number: {page_number}, page_size: {page_size}")

        # Validate pagination parameters
        try:
            page_number = int(page_number)
            page_size = int(page_size)
            if page_number < 1 or page_size < 1:
                return func.HttpResponse(
                    body=json.dumps({'error': 'page_number and page_size must be positive integers'}),
                    status_code=400,
                    mimetype="application/json"
                )
        except ValueError:
            return func.HttpResponse(
                body=json.dumps({'error': 'Invalid page_number or page_size. They must be integers.'}),
                status_code=400,
                mimetype="application/json"
            )

        if not (employee_id or employee_name or date):
            return func.HttpResponse(
                body=json.dumps({'error': 'At least one search parameter (employeeId, employeeName, or date) is required'}),
                status_code=400,
                mimetype="application/json"
            )

        # Construct query conditions
        query_conditions = []
        parameters = []

        if employee_id:
            query_conditions.append("c.employeeId = @employee_id")
            parameters.append({"name": "@employee_id", "value": int(employee_id)})

        if employee_name:
            query_conditions.append("STARTSWITH(LOWER(c.employeeName), LOWER(@employee_name))")
            parameters.append({"name": "@employee_name", "value": employee_name.lower()})

        if date:
            query_conditions.append("c.date = @date")
            parameters.append({"name": "@date", "value": date})

        # Construct the query with pagination
        query = "SELECT * FROM c WHERE " + " AND ".join(query_conditions)
        query += " ORDER BY c.employeeId ASC"
        query += f" OFFSET {(page_number - 1) * page_size} LIMIT {page_size}"

        logging.info(f"Constructed query: {query}")

        # Execute query
        items = list(attendance_container.query_items(query=query, parameters=parameters, enable_cross_partition_query=True))

        if items:
            return func.HttpResponse(
                body=json.dumps(items),
                status_code=200,
                mimetype="application/json"
            )

        return func.HttpResponse(
            body=json.dumps({'message': 'No matching attendance records found'}),
            status_code=404,
            mimetype="application/json"
        )

    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Failed to search attendance records: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': f'Failed to search attendance records: {e.message}'}),
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






# # Define the Azure Function for adding an employee      -post
@app.function_name(name="add_employee")
@app.route(route='employee', methods=[func.HttpMethod.POST])
@require_auth
async def add_employee(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")
        logging.info(f"User Info: {req.user_info}")  # Debugging log

        # Extract JSON data from the request body
        json_data = req.get_json()

        if not json_data:
            return func.HttpResponse(
                body=json.dumps({'error': 'JSON data is required in the request body'}),
                status_code=400,
                mimetype="application/json"
            )

        # Extract fields from the JSON data
        employee_id = json_data.get('employeeId')
        name = json_data.get('employeeName')
        role = json_data.get('role')
        email = json_data.get('email')
        base64_image = json_data.get('imageBase64')  # Base64-encoded image
    

        # Check if required fields are provided
        if not employee_id or not name or not role or not email:
            return func.HttpResponse(
                body=json.dumps({'error': 'All fields except image are required'}),
                status_code=400,
                mimetype="application/json"
            )

        # Validate email format using regex
        EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zAZ0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(EMAIL_REGEX, email):
            return func.HttpResponse(
                body=json.dumps({'error': 'Invalid email format'}),
                status_code=400,
                mimetype="application/json"
            )

        # Get `organizationId` from token (same as `sub`)
        organization_id = req.user_info.get('user_id')  # Fix applied here

        if not organization_id:
            return func.HttpResponse(
                body=json.dumps({'error': 'Invalid token: organizationId (sub) missing'}),
                status_code=401,
                mimetype="application/json"
            )

        # Check if employeeId already exists in Cosmos DB
        query = f"SELECT * FROM c WHERE c.employeeId = '{employee_id}'"
        existing_employees = list(employee_container.query_items(query=query, enable_cross_partition_query=True))

        if existing_employees:
            return func.HttpResponse(
                body=json.dumps({'Warn': f'Employee with employeeId {employee_id} already exists'}),
                status_code=409,  # Conflict status code
                mimetype="application/json"
            )

        # Upload the image if provided
        image_url = upload_image_to_blob(base64_image, employee_id) if base64_image else None

        # Create the employee record
        employee_record = {
            'id': str(uuid.uuid4()),
            'employeeId': employee_id,
            'employeeName': name,
            'role': role,
            'email': email,
            'imageUrl': image_url,
            'organizationId': organization_id  # Map employee to the organization
        }

        # Save the employee record in Cosmos DB
        employee_container.create_item(body=employee_record)

        return func.HttpResponse(
            body=json.dumps({'message': 'Employee added successfully', 'data': employee_record}),
            status_code=201,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error adding employee: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': str(e)}),
            status_code=500,
            mimetype="application/json"
        )



                                                    # put function
# Update Employee function (for PUT requests)
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
                json.dumps({'error': 'Employee not found'}), 
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
                    json.dumps({'error': f'Error processing image: {str(e)}'}), 
                    status_code=500, 
                    mimetype="application/json"
                )
        else:
            logging.info(f"No new image provided. Keeping existing image URL: {item.get('imageUrl')}")

        # Define the allowed fields
        allowed_fields = {
            "employeeName", "role", "email", "organizationId"
        }
        # Remove protected fields from the update data
        protected_fields = {'id', '_rid', '_self', '_etag', '_attachments', '_ts', 'employeeId', 'newImageBase64'}
        update_data = {k: v for k, v in data.items() if k in allowed_fields and k not in protected_fields}

        # Update the existing employee record with new data
        item.update(update_data)

        # Replace the employee record in Cosmos DB
        try:
            employee_container.replace_item(
                item=item['id'],
                body=item
            )
            logging.info(f"Employee {employee_id} updated successfully.")
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
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype="application/json"
        )


    
                    # Define the Azure Function for delete an employee

@app.function_name(name="delete_employee")
@app.route(route="employee/{employee_id}", methods=[func.HttpMethod.DELETE])
def delete_employee(req: func.HttpRequest) -> func.HttpResponse:
    # Validate and decode the token
    try:
        user_info = validate_and_decode_token(req)
        logging.info(f"Token validated for user: {user_info.get('email', 'unknown')}")
    except Exception as e:
        logging.error(f"Unauthorized Request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": "Unauthorized: Missing or Invalid Token"}),
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

            # Delete the employee record from Cosmos DB
            # Use the partition key and document id for deletion
            employee_container.delete_item(item=item['id'], partition_key=item['id'])
            return func.HttpResponse(
                body=json.dumps({'message': 'Employee deleted successfully'}),
                status_code=200,
                mimetype="application/json"
            )

        return func.HttpResponse(
            body=json.dumps({'message': 'Employee not found'}),
            status_code=404,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Error deleting employee: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': str(e)}),
            status_code=500,
            mimetype="application/json"
        )

    

    
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
    Retrieve attendance records with optional filtering by employeeId and date.
    Includes pagination and sorting by date (latest first).
    """
    logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")

    try:
        # Extract pagination parameters (default: page 1, size 10)
        page_number = int(req.params.get('page_number', 1))
        page_size = int(req.params.get('page_size', 10))
        offset = (page_number - 1) * page_size

        # Get optional filters
        employee_id = req.params.get('employeeId')
        attendance_date = req.params.get('date')  # Expected format: YYYY-MM-DD

        # Base query
        query = "SELECT * FROM c WHERE 1=1"
        parameters = []

        # Apply employeeId filter if provided
        if employee_id:
            query += " AND c.employeeId = @employeeId"
            parameters.append({"name": "@employeeId", "value": employee_id})

        # Apply date filter if provided
        if attendance_date:
            query += " AND c.date = @attendanceDate"
            parameters.append({"name": "@attendanceDate", "value": attendance_date})

        # Sort by date (descending) so latest records appear first
        query += " ORDER BY c.date DESC"

        # Execute query
        all_items = list(attendance_container.query_items(
            query=query, parameters=parameters, enable_cross_partition_query=True
        ))

        # Apply pagination
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
    Search for employees by employeeId or name
    
    Query parameters:
    - search: Search term (can be employeeId or partial name)
    """
    # Log incoming request parameters for debugging
    search = req.params.get('search')
    logging.info(f"Received search parameter: {search}")

    # Ensure that the search parameter is provided
    if not search:
        return func.HttpResponse(
            body=json.dumps({
                'error': 'A search parameter is required'
            }),
            status_code=400,
            mimetype="application/json"
        )

    try:
        # Initialize query conditions and parameters
        query_conditions = []
        parameters = []

        # Determine search type and construct appropriate query
        if search.isnumeric():
            # Exact match for employeeId
            query_conditions.append("c.employeeId = @employee_id")
            parameters.append({"name": "@employee_id", "value": search})
        else:
            # Partial match for employeeName (case-insensitive)
            # Use multiple conditions to search across different name fields
            name_search_conditions = [
                "CONTAINS(LOWER(c.employeeName), LOWER(@employee_name))",
                "CONTAINS(LOWER(c.firstName), LOWER(@employee_name))",
                "CONTAINS(LOWER(c.lastName), LOWER(@employee_name))"
            ]
            
            # Combine name search conditions
            query_conditions.append(f"({' OR '.join(name_search_conditions)})")
            parameters.append({"name": "@employee_name", "value": search.strip().lower()})

        # Construct the full query with selected fields
        query = "SELECT c.employeeId, c.employeeName, c.role, c.email, c.dateOfJoining, c.imageUrl FROM c WHERE " + " OR ".join(query_conditions)

        logging.info(f"Constructed query: {query}")

        # Perform the query to Cosmos DB
        items = list(employee_container.query_items(
            query=query, 
            parameters=parameters, 
            enable_cross_partition_query=True
        ))

        # Handle query results
        if items:
            return func.HttpResponse(
                body=json.dumps(items),
                status_code=200,
                mimetype="application/json"
            )

        # If no items found, return a 404 response
        return func.HttpResponse(
            body=json.dumps({
                'message': 'No employees found matching the search criteria'
            }),
            status_code=404,
            mimetype="application/json"
        )

    except exceptions.CosmosHttpResponseError as e:
        # Handle Cosmos DB specific errors
        logging.error(f"Failed to search employee records: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({
                'error': f'Failed to search employee records: {str(e)}'
            }),
            status_code=500,
            mimetype="application/json"
        )
    except Exception as e:
        # Catch any unexpected errors
        logging.error(f"Unexpected error in search_employee: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({
                'error': 'An unexpected error occurred during employee search'
            }),
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

# attendance camera
@app.function_name(name="saveattendanceCameraUrl")
@app.route(route='api/cameraUrl', methods=[func.HttpMethod.POST])
@require_auth
async def saveCameraUrls(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info(f"Token validated for user: {req.user_info.get('email', 'unknown')}")
        logging.info(f"User Info: {req.user_info}")  # Debugging log

        # Extract organizationId (same as sub/user_id)
        organization_id = req.user_info.get('user_id')

        if not organization_id:
            return func.HttpResponse(
                json.dumps({'error': 'Invalid token: organizationId (sub) missing'}),
                status_code=401,
                mimetype="application/json"
            )

        # Parse the incoming JSON data
        req_body = req.get_json()

        # Extract email from request body or fallback to req.user_info
        email = req_body.get("email") or req.user_info.get("email", "")

        # Ensure email is not empty
        if not email:
            return func.HttpResponse(
                json.dumps({"error": "Email is missing in both request body and token."}),
                status_code=400
            )

        # Extract and validate `cameraDetails1`
        camera_details = req_body.get("cameraDetails", [])
        if not camera_details or not isinstance(camera_details, list):
            return func.HttpResponse(
                json.dumps({"detail": "Missing or invalid field: 'cameraDetails'."}),
                status_code=400
            )

        validated_camera_details = []
        for detail in camera_details:
            if not all(key in detail for key in ["punchinCamera", "punchinUrl", "punchoutCamera", "punchoutUrl"]):
                return func.HttpResponse(
                    json.dumps({"detail": "Each item in 'cameraDetails' must contain 'punchinCamera', 'punchinUrl', 'punchoutCamera', and 'punchoutUrl'."}),
                    status_code=400
                )

            validated_camera_details.append({
                "punchinCamera": detail["punchinCamera"],
                "punchinUrl": detail["punchinUrl"],
                "punchoutCamera": detail["punchoutCamera"],
                "punchoutUrl": detail["punchoutUrl"]
            })

        # Check if a record already exists for this organization
        query = f"SELECT * FROM c WHERE c.organizationId = '{organization_id}'"
        existing_records = list(camera_urls_container.query_items(query=query, enable_cross_partition_query=True))

        if existing_records:
            # Update the existing record
            existing_record = existing_records[0]
            existing_record["email"] = email  # Update email at root level
            existing_record["cameraDetails"] = validated_camera_details
            upsert_camera_urls(existing_record)  # Update record in Cosmos DB
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
            upsert_camera_urls(camera_data)  # Insert new record into Cosmos DB
            response_message = {"message": "Camera URLs saved successfully.", "id": camera_id}

        return func.HttpResponse(json.dumps(response_message), status_code=200)

    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An error occurred during processing."}),
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
            json.dumps({"error": "Unauthorized: Missing or Invalid Token"}),
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
                json.dumps({"detail": "Missing required field: 'id'."}),
                status_code=400
            )
        
        # Extract new camera details
        camera_details = req_body.get("cameraDetails", [])

        if not camera_details:
            return func.HttpResponse(
                json.dumps({"detail": "Missing required field: 'cameraDetails'."}),
                status_code=400
            )

        # Fetch existing camera data
        existing_data = get_camera_data_by_id(camera_id)

        if not existing_data:
            return func.HttpResponse(
                json.dumps({"detail": f"No camera data found for ID: {camera_id}."}),
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
                    json.dumps({"detail": "Invalid format in 'cameraDetails'. Expected list of objects."}),
                    status_code=400
                )

            # Filter only allowed fields
            filtered_detail = {key: value for key, value in detail.items() if key in allowed_fields}

            # Ensure all required fields exist
            if set(filtered_detail.keys()) != allowed_fields:
                return func.HttpResponse(
                    json.dumps({"detail": "Invalid or missing fields in 'cameraDetails'. Only specific fields are allowed."}),
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
            json.dumps({"detail": "Invalid JSON format."}),
            status_code=400
        )
    except Exception as e:
        return func.HttpResponse(
            json.dumps({"detail": str(e)}),
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
                json.dumps({"detail": "Missing required parameter: 'id'."}),
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
            json.dumps({"detail": "Camera details not found for the provided ID."}),
            status_code=404
        )
    except Exception as e:
        logging.error(f"Error retrieving camera details: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An error occurred while retrieving the data."}),
            status_code=500
        )

# Fetch the camera data from Cosmos DB by ID
def get_camera_by_id(camera_id):
    return camera_urls_container.read_item(item=camera_id, partition_key=camera_id)





# Define the Azure Function for adding an organization - POST
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
                json.dumps({'error': 'JSON data is required in the request body'}),
                status_code=400,
                mimetype="application/json"
            )

        # Extract organization details
        organization_name = json_data.get('organizationName')
        phone_number = json_data.get('phoneNumber')
        website_url = json_data.get('websiteUrl')
        domain_name = json_data.get('domainName')
        address = json_data.get('address')

        if not organization_name:
            return func.HttpResponse(
                json.dumps({'error': 'Organization name is mandatory'}),
                status_code=400,
                mimetype="application/json"
            )

        # Validate website URL format
        valid_domain_pattern = r'^(https?://)?(www\.)?[\w-]+\.(com|net|org|io|co|edu|gov|info|biz|dev|app)$'
        if website_url and not re.match(valid_domain_pattern, website_url):
            return func.HttpResponse(
                json.dumps({'error': 'Invalid website URL format. Must be like https://example.com'}),
                status_code=400,
                mimetype="application/json"
            )

        # Use `sub` (user_id) as the `id` and `organizationId`
        organization_id = req.user_info.get('user_id')
        if not organization_id:
            return func.HttpResponse(
                json.dumps({'error': 'Invalid token: user ID (sub) missing'}),
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
                json.dumps({'error': 'Organization name already exists'}),
                status_code=409,
                mimetype="application/json"
            )

        # Create or update organization record
        organization_record = {
            'id': organization_id,  # Ensure `id` is the `sub` (user_id)
            'organizationId': organization_id,
            'organizationName': organization_name,
            'phoneNumber': phone_number,
            'websiteUrl': website_url,
            'domainName': domain_name,
            'address': address,
            'createdAt': datetime.utcnow().isoformat(),
        }

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
            json.dumps({'error': 'Internal Server Error'}),
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
                json.dumps({"detail": "Authorization token is required."}),
                status_code=401
            )
 
        try:
            if not auth_header.startswith('Bearer '):
                return HttpResponse(
                    json.dumps({"detail": "Invalid authorization header format. Must start with 'Bearer'."}),
                    status_code=401
                )
 
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
                    "message": "Data already exists. Use the edit API to update.",
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
            json.dumps({"detail": f"An error occurred during processing: {str(e)}"}),
            status_code=500
        )
 
 
 
 
# Adding missing functions:
 
@app.function_name(name="getCameraUrlsTracker")
@app.route(route='api/getCameraUrls', methods=[func.HttpMethod.GET])
@require_auth
async def getCameraUrls(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    organization_id = user_info['sub']
 
    try:
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
           
            # Check if 'c' key exists in the document (based on your original data structure)
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
            json.dumps({"detail": "An error occurred while retrieving the data."}),
            status_code=500
        )
   
 
@app.function_name(name="getPersonDetectionOverTime")
@app.route(route='api/getPersonDetectionOverTime', methods=[func.HttpMethod.GET])
@require_auth
async def get_person_detection_over_time(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    user_id = user_info['sub']
 
    try:
        # Query to get capacity from setup container
        capacity_query = """
        SELECT c.capacityOfPeople
        FROM c
        WHERE c.user_id = @user_id
        """
        parameters = [{"name": "@user_id", "value": user_id}]
       
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
 
        # Query to get person logs from user_logs table
        logs_query = """
        SELECT c.logs
        FROM c
        WHERE c.user_id = @user_id
        """
       
        logs_items = list(user_logs_container.query_items(
            query=logs_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        if not logs_items or "logs" not in logs_items[0]:
            return func.HttpResponse(
                json.dumps({"data": []}),
                status_code=200
            )
 
        # Dictionary to count entries and exits per hour per camera
        entry_counts_by_hour = defaultdict(lambda: defaultdict(int))
        exit_counts_by_hour = defaultdict(lambda: defaultdict(int))
       
        # Process logs and group by hour
        logs = logs_items[0].get("logs", [])
        for log in logs:
            timestamp = log.get("timestamp")
            camera_id = log.get("camera_id")
            event_type = log.get("event_type")
 
            if timestamp and camera_id and event_type:
                # Convert timestamp to pendulum and truncate to hour
                dt = pendulum.parse(timestamp)
                # Reset minutes and seconds to get exact hour
                dt = dt.start_of('hour')
                hour_key = dt.format('YYYY-MM-DD HH')
               
                if event_type == "person_entry":
                    entry_counts_by_hour[hour_key][camera_id] += 1
                elif event_type == "person_exit":
                    exit_counts_by_hour[hour_key][camera_id] += 1
 
        # Get a set of all hour keys from both entries and exits
        all_hour_keys = set(entry_counts_by_hour.keys()) | set(exit_counts_by_hour.keys())
       
        # Create time series data with hourly counts and percentages
        time_series_data = []
       
        for hour_key in sorted(all_hour_keys):
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
            percentage = (total_count / capacity * 100) if capacity > 0 else 0
           
            # Parse the hour key and create hour range
            dt = pendulum.from_format(hour_key, 'YYYY-MM-DD HH')
            next_hour = dt.add(hours=1)
           
            hour_range = f"{dt.format('h:mm A')} - {next_hour.format('h:mm A')}"
           
            time_series_data.append({
                "date": dt.format('YYYY-MM-DD'),
                "hour_range": hour_range,
                "total_person_count": total_count,
                "camera_counts": camera_counts,
                "percentage": round(percentage, 2)
            })
 
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
async def getAllCounts(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    user_id = user_info['sub']
   
    try:
        # Query to get capacity from setup container
        capacity_query = """
        SELECT c.capacityOfPeople
        FROM c
        WHERE c.user_id = @user_id
        """
        parameters = [{"name": "@user_id", "value": user_id}]
       
        setup_items = list(setup_container.query_items(
            query=capacity_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
       
        capacity = setup_items[0].get("capacityOfPeople", 0) if setup_items else 0
       
        # Query to get counts from user_counts table
        counts_query = """
        SELECT c.cameras, c.last_updated
        FROM c
        WHERE c.user_id = @user_id
        """
       
        count_items = list(user_counts_container.query_items(
            query=counts_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
       
        if not count_items and not setup_items:
            return func.HttpResponse(
                json.dumps({
                    "camera_counts": {},
                    "total": {
                        "current_count": 0,
                        "percentage": 0
                    }
                }),
                status_code=200
            )
       
        # Calculate counts for each camera
        camera_counts = {}
        total_current_count = 0
       
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
       
        # Calculate occupancy percentage
        occupancy_percentage = (total_current_count / capacity * 100) if capacity > 0 else 0
       
        response_data = {
            "camera_counts": camera_counts,
            "total": {
                "current_count": total_current_count,
                "percentage": round(occupancy_percentage, 2)
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
                json.dumps({"detail": "No data found for this organization."}),
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
            json.dumps({"detail": f"An error occurred during processing: {str(e)}"}),
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
                json.dumps({"detail": "No data found for this organization."}),
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
            json.dumps({"detail": f"An error occurred during processing: {str(e)}"}),
            status_code=500
        )
    


@app.function_name(name="checkUserExists")
@app.route(route='api/checkUserExists', methods=[func.HttpMethod.GET])
@require_auth
async def check_user_exists(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    organization_id = user_info['sub']
   
    try:
        # Query the setup-details container to check if the organization ID exists
        query = "SELECT VALUE COUNT(1) FROM c WHERE c.organization_id = @organization_id"
        parameters = [{"name": "@organization_id", "value": organization_id}]
       
        items = list(setup_container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
       
        # items[0] will contain the count (0 if not found, ≥1 if found)
        user_exists = items[0] > 0
       
        return func.HttpResponse(
            json.dumps({
                "data": {
                    "exists": user_exists,
                    "message": "User exists" if user_exists else "User does not exist"
                }
            }),
            mimetype="application/json",
            status_code=200
        )
    except Exception as e:
        logging.error(f"Error checking if user exists: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An error occurred while checking if the user exists."}),
            mimetype="application/json",
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
                json.dumps({"error": "Invalid token: organizationId (sub) missing"}),
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
            json.dumps({"error": "Internal server error"}),
            status_code=500,
            mimetype="application/json"
        )

@app.function_name(name="getPersonCountByDate")
@app.route(route='api/getPersonCountByDate', methods=[func.HttpMethod.GET])
@require_auth
async def get_person_count_by_date(req: func.HttpRequest) -> func.HttpResponse:
    user_info = req.user_info
    user_id = user_info['sub']
   
    # Get the date parameter from the request query string
    # If not provided, use current date
    date_param = req.params.get('date')
    if not date_param:
        # Use current date if no date parameter is provided
        selected_date = pendulum.now().format('YYYY-MM-DD')
    else:
        # Parse and validate the date format (YYYY-MM-DD)
        try:
            selected_date = pendulum.parse(date_param).format('YYYY-MM-DD')
        except Exception as e:
            return func.HttpResponse(
                json.dumps({"error": f"Invalid date format. Please use YYYY-MM-DD. Details: {str(e)}"}),
                status_code=400
            )
   
    try:
        # Query to get person logs from user_logs table
        logs_query = """
        SELECT c.logs
        FROM c
        WHERE c.user_id = @user_id
        """
        parameters = [{"name": "@user_id", "value": user_id}]
       
        logs_items = list(user_logs_container.query_items(
            query=logs_query,
            parameters=parameters,
            enable_cross_partition_query=True
        ))
 
        if not logs_items or "logs" not in logs_items[0]:
            # Return empty data with the simplified structure
            return func.HttpResponse(
                json.dumps({
                    "data": {
                        "date": selected_date,
                        "total_entries": 0,
                        "total_exits": 0,
                        "total_count": 0,
                        "camera_data": []
                    }
                }),
                status_code=200,
                mimetype="application/json"
            )
 
        # Dictionary to count entries and exits per camera
        camera_entry_counts = defaultdict(int)
        camera_exit_counts = defaultdict(int)
        all_cameras = set()
       
        # Process logs and filter by selected date
        logs = logs_items[0].get("logs", [])
        for log in logs:
            timestamp = log.get("timestamp")
            camera_id = log.get("camera_id")
            event_type = log.get("event_type")
 
            if timestamp and camera_id and event_type:
                # Parse timestamp and check if it's on the selected date
                log_date = pendulum.parse(timestamp).format('YYYY-MM-DD')
               
                if log_date == selected_date:
                    all_cameras.add(camera_id)
                   
                    if event_type == "person_entry":
                        camera_entry_counts[camera_id] += 1
                    elif event_type == "person_exit":
                        camera_exit_counts[camera_id] += 1
       
        # Calculate totals
        total_entries = sum(camera_entry_counts.values())
        total_exits = sum(camera_exit_counts.values())
        total_count = total_entries - total_exits
       
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
           
        # Sort camera data by camera_id for consistency
        camera_data.sort(key=lambda x: x["camera_id"])
       
        # Prepare the response with the simplified format
        return func.HttpResponse(
            json.dumps({
                "data": {
                    "date": selected_date,
                    "total_entries": total_entries,
                    "total_exits": total_exits,
                    "total_count": total_count,
                    "camera_data": camera_data
                }
            }),
            status_code=200,
            mimetype="application/json"
        )
 
    except Exception as e:
        logging.error(f"Unexpected error in getPersonCountByDate: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": f"An unexpected error occurred: {str(e)}"}),
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
            return func.HttpResponse("Both organizationData and cameraData are required.", status_code=400)

        # Validate mandatory fields
        mandatory_org_fields = [
            "organizationId", "organizationName", "phoneNumber",
            "websiteUrl", "domainName", "address"
        ]
        mandatory_cam_fields = ["organizationId", "email", "cameraDetails"]

        for field in mandatory_org_fields:
            if field not in organization_data:
                return func.HttpResponse(f"Missing mandatory field in organizationData: {field}", status_code=400)

        for field in mandatory_cam_fields:
            if field not in camera_data:
                return func.HttpResponse(f"Missing mandatory field in cameraData: {field}", status_code=400)

        # Upsert (Insert or Update) organization data
        organization_container_name.upsert_item(organization_data)

        # Upsert (Insert or Update) camera data
        camera_urls_container.upsert_item(camera_data)

        return func.HttpResponse("Organization and camera data updated successfully", status_code=200)

    except exceptions.CosmosHttpResponseError as e:
        return func.HttpResponse(f"Cosmos DB Error: {str(e)}", status_code=500)
    except Exception as e:
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)




# GRAPH_API_URL = "https://graph.microsoft.com/v1.0"
# GRAPH_SCOPE = "https://graph.microsoft.com/.default"





def get_graph_access_token():
    """Authenticate and get access token for Microsoft Graph."""
    try:
        logging.info(f"TENANT_ID: {TENANT_ID}, CLIENT_ID: {CLIENT_ID}, CLIENT_SECRET: {CLIENT_SECRET}, GRAPH_SCOPE: {GRAPH_SCOPE}")
        credential = ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
        token = credential.get_token(GRAPH_SCOPE)
        logging.info("Access token fetched successfully.")
        return token.token
    except Exception as e:
        logging.error(f"Error getting access token: {e}")
        raise



def get_user_data(object_id, token):
    """Fetch user data from Microsoft Graph."""
    try:
        url = f"{GRAPH_API_URL}/users/{object_id}"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as err:
        logging.error(f"Failed to fetch user data: {err}")
        raise


def update_user_job_title(object_id, job_title, token):
    """Update user jobTitle in Azure AD B2C."""
    try:
        url = f"{GRAPH_API_URL}/users/{object_id}"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {"jobTitle": job_title}
        response = requests.patch(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        logging.info(f"Successfully updated job title for user {object_id} to '{job_title}'")
        return response.status_code == 204
    except requests.exceptions.HTTPError as err:
        logging.error(f"Failed to update user job title: {err}")
        raise



@app.function_name(name="AssignAdminJobTitle")
@app.route(route="assign-admin-job-title", methods=[func.HttpMethod.POST])
async def assign_admin_job_title(req: func.HttpRequest) -> func.HttpResponse:
    """Handle admin job title assignment with improved performance and reliability."""
    # Always prepare a valid B2C response
    b2c_response = {
        "version": "1.0.0",
        "action": "Continue",
        "jobTitle": "admin"
    }
    
    try:
        # Extract object ID with minimal processing
        body = req.get_json()
        object_id = body.get("oid")

        if not object_id:
            logging.warning("Missing oid in request, returning default response")
            return func.HttpResponse(json.dumps(b2c_response), 
                                    status_code=200, 
                                    mimetype="application/json")

        # Start a background task to update the job title
        # This allows B2C to continue without waiting for the update to complete
        background_task = asyncio.create_task(
            update_job_title_background(object_id, "admin")
        )
        
        # Return immediately with the response B2C needs
        logging.info(f"Returning response to B2C: {b2c_response}")
        return func.HttpResponse(json.dumps(b2c_response), 
                                status_code=200, 
                                mimetype="application/json")

    except Exception as e:
        logging.error(f"Error in assign_admin_job_title: {str(e)}")
        # Always return a valid response for B2C
        return func.HttpResponse(json.dumps(b2c_response), 
                                status_code=200, 
                                mimetype="application/json")

async def update_job_title_background(object_id, job_title):
    """Update job title in the background after responding to B2C."""
    try:
        token = get_graph_access_token()
        if not token:
            logging.error("Failed to get access token for background update")
            return
            
        user_data = get_user_data(object_id, token)
        if not user_data:
            logging.error(f"Failed to get user data for {object_id}")
            return
            
        if not user_data.get("jobTitle"):
            update_success = update_user_job_title(object_id, job_title, token)
            if update_success:
                logging.info(f"Job title updated successfully for {object_id}")
            else:
                logging.warning(f"Failed to update job title for {object_id}")
    except Exception as e:
        logging.error(f"Error in background job title update: {str(e)}")


@app.function_name(name="AssignEmployeeJobTitle")
@app.route(route="assign-employee-job-title", methods=[func.HttpMethod.POST])
async def assign_employee_job_title(req: func.HttpRequest) -> func.HttpResponse:
    """Handle employee job title assignment with improved performance and reliability."""
    # Always prepare a valid B2C response
    b2c_response = {
        "version": "1.0.0",
        "action": "Continue",
        "jobTitle": "employee"
    }
    
    try:
        # Extract object ID with minimal processing
        body = req.get_json()
        object_id = body.get("oid")

        if not object_id:
            logging.warning("Missing oid in request, returning default response")
            return func.HttpResponse(json.dumps(b2c_response), 
                                    status_code=200, 
                                    mimetype="application/json")

        # Start a background task to update the job title
        # This allows B2C to continue without waiting for the update to complete
        background_task = asyncio.create_task(
            update_job_title_background(object_id, "employee")
        )
        
        # Return immediately with the response B2C needs
        logging.info(f"Returning response to B2C: {b2c_response}")
        return func.HttpResponse(json.dumps(b2c_response), 
                                status_code=200, 
                                mimetype="application/json")

    except Exception as e:
        logging.error(f"Error in assign_employee_job_title: {str(e)}")
        # Always return a valid response for B2C
        return func.HttpResponse(json.dumps(b2c_response), 
                                status_code=200, 
                                mimetype="application/json")

async def update_job_title_background(object_id, job_title):
    """Update job title in the background after responding to B2C."""
    try:
        token = get_graph_access_token()
        if not token:
            logging.error("Failed to get access token for background update")
            return
            
        user_data = get_user_data(object_id, token)
        if not user_data:
            logging.error(f"Failed to get user data for {object_id}")
            return
            
        if not user_data.get("jobTitle"):
            update_success = update_user_job_title(object_id, job_title, token)
            if update_success:
                logging.info(f"Job title updated successfully for {object_id}")
            else:
                logging.warning(f"Failed to update job title for {object_id}")
    except Exception as e:
        logging.error(f"Error in background job title update: {str(e)}")