import json
import logging
import azure.functions as func
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
from datetime import datetime
import re
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Load environment variables from .env file
load_dotenv()

# Azure Cosmos DB configuration
COSMOS_CONNECTION_STRING = os.getenv('COSMOS_CONNECTION_STRING')
DATABASE_NAME = os.getenv('DATABASE_NAME')
EMPLOYEE_CONTAINER_NAME = os.getenv('EMPLOYEE_CONTAINER_NAME')
ATTENDANCE_CONTAINER_NAME = os.getenv('ATTENDANCE_CONTAINER_NAME')
ORGANIZATION_CONTAINER_NAME = os.getenv('ORGANIZATION_CONTAINER_NAME')


CAMERA_URLS_CONTAINER_NAME = os.getenv('CAMERA_URLS_CONTAINER_NAME')

# Azure Blob Storage configuration
BLOB_CONNECTION_STRING = os.getenv('STORAGE_CONNECTION_STRING')
BLOB_CONTAINER_NAME = os.getenv('STORAGE_CONTAINER_NAME')


COUNTS_CONTAINER = os.getenv('COUNTS_CONTAINER')
SETUP_CONTAINER_NAME=os.getenv('SETUP_CONTAINER_NAME')
PERSON_FEATURE_CONTAINER=os.getenv('PERSON_FEATURE_CONTAINER')

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
  # Define attendance_container

setup_container_name = database.get_container_client(SETUP_CONTAINER_NAME)
counts_container = database.get_container_client(COUNTS_CONTAINER)
person_features =database.get_container_client(PERSON_FEATURE_CONTAINER)

# Initialize the Blob Service Client
blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)
blob_container_client = blob_service_client.get_container_client(BLOB_CONTAINER_NAME)

print('Successfully connected all the strings')

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



                                # get employee by ID

@app.function_name(name="get_employee")
@app.route(route='employee/{employee_id}', methods=[func.HttpMethod.GET])
def get_employee(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Extract employee_id from the route parameters
        employee_id = req.route_params.get('employee_id')

        # Convert employee_id to string (since it's stored as an string in the database)
        employee_id = str(employee_id)

        # Query to fetch employee record by employeeId
        query = "SELECT * FROM c WHERE c.employeeId = @employee_id"
        parameters = [{"name": "@employee_id", "value": employee_id}]
        items = list(employee_container.query_items(
            query=query, 
            parameters=parameters, 
            enable_cross_partition_query=True
        ))

        # Check if an employee record is found
        if items:
            return func.HttpResponse(
                body=json.dumps(items[0]),  # Return the first matching employee
                status_code=200,
                mimetype="application/json"
            )

        # If no record is found, return a 404 response
        return func.HttpResponse(
            body=json.dumps({'message': 'Employee not found'}),
            status_code=404,
            mimetype="application/json"
        )

    except ValueError:
        # If employee_id is not a valid String
        logging.error("Invalid employee_id. It should be an String.")
        return func.HttpResponse(
            body=json.dumps({'error': 'Invalid employee ID. It should be an String.'}),
            status_code=400,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error fetching employee: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': str(e)}),
            status_code=500,
            mimetype="application/json"
        )

    
                                # Fetch all employee records -getall
@app.function_name(name="get_all_employees")
@app.route(route='employees', methods=[func.HttpMethod.GET])
def get_all_employees(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Get pagination parameters from the query string, if they exist
        page_number = req.params.get('page_number')
        page_size = req.params.get('page_size')
        
        # Set default page_number and page_size if not provided
        page_number = int(page_number) if page_number else 1
        page_size = int(page_size) if page_size else 10

        # Calculate offset
        offset = (page_number - 1) * page_size

        # Base query (without sorting)
        query = "SELECT * FROM c"

        # Fetch all employee records from the container
        all_items = list(employee_container.query_items(query=query, enable_cross_partition_query=True))

        # Sorting using Python's natural sorting (to handle alphanumeric employeeIds)
       
        sorted_items = natsorted(all_items, key=lambda x: x['employeeId'])

        # Apply pagination to the sorted items
        paginated_items = sorted_items[offset:offset + page_size]
        logging.info(f"Paginated items count: {len(paginated_items)}")

        # If no items found, return an empty response
        if not paginated_items:
            return func.HttpResponse(
                body=json.dumps([]),
                status_code=200,
                mimetype="application/json"
            )

        # Return paginated results
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
def search_attendance(req: func.HttpRequest) -> func.HttpResponse:
    # Retrieve parameters using 'employeeId' and 'employeeName'
    employee_id = req.params.get('employeeId')
    employee_name = req.params.get('employeeName')
    date = req.params.get('date')

    # Ensure that at least one search parameter is provided
    if not (employee_id or employee_name or date):
        return func.HttpResponse(
            body=json.dumps({'error': 'At least one search parameter (employeeId, employeeName, or date) is required'}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        # Build the query dynamically based on the provided parameters
        query_conditions = []
        parameters = []

        if employee_id:
            query_conditions.append("c.employeeId = @employee_id")
            parameters.append({"name": "@employee_id", "value": int(employee_id)})

        if employee_name:
            # Modify the condition to be case insensitive
            query_conditions.append("STARTSWITH(LOWER(c.employeeName), LOWER(@employee_name))")
            parameters.append({"name": "@employee_name", "value": employee_name.lower()})

        if date:
            query_conditions.append("c.date = @date")
            parameters.append({"name": "@date", "value": date})

        # Combine conditions with AND
        query = "SELECT * FROM c WHERE " + " AND ".join(query_conditions)

        logging.info(f"Constructed query: {query}")  # Debugging line to ensure the query is constructed correctly

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






# Define the Azure Function for adding an employee      -post
@app.function_name(name="add_employee")
@app.route(route='employee', methods=[func.HttpMethod.POST])
def add_employee(req: func.HttpRequest) -> func.HttpResponse:
    try:
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
        date_of_joining = json_data.get('dateOfJoining')  # New field

        # Check if required fields are provided
        if not employee_id or not name or not role or not email or not date_of_joining:
            return func.HttpResponse(
                body=json.dumps({'error': 'All fields except image are required'}),
                status_code=400,
                mimetype="application/json"
            )

        # Validate email format using regex
        EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(EMAIL_REGEX, email):
            return func.HttpResponse(
                body=json.dumps({'error': 'Invalid email format'}),
                status_code=400,
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
            'dateOfJoining': date_of_joining,  # Add dateOfJoining field
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

#                                                     # put function
# Update Employee function (for PUT requests)
@app.function_name(name="update_employee")
@app.route(route="update-employee/{employee_id}", methods=[func.HttpMethod.PUT])
def update_employee(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing update employee request.')

    try:
        # Get employee ID from the route and validate
        employee_id = str(req.route_params.get('employee_id'))
        if not employee_id:
            return func.HttpResponse(
                json.dumps({'error': 'Employee ID is required'}), 
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
        new_image_base64 = data.get('newImageBase64')  # New field for image upload
        if new_image_base64:
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

        # Remove protected fields from the update data
        protected_fields = {'id', '_rid', '_self', '_etag', '_attachments', '_ts', 'employeeId', 'newImageBase64'}
        update_data = {k: v for k, v in data.items() if k not in protected_fields}

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

@app.function_name(name="get_attendance_byfilter")
@app.route(route="attendance/all", methods=[func.HttpMethod.GET])
def get_all_attendance(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing request to get attendance records.')

    try:
        date_param = req.params.get('date')
        
        # Validate the date format
        if date_param:
            try:
                input_date = datetime.strptime(date_param, '%Y-%m-%d').date()
                if input_date > datetime.today().date():
                    return func.HttpResponse(
                        body=json.dumps({'error': f'The date {date_param} is in the future. Please provide a valid date.'}),
                        status_code=400,
                        mimetype="application/json"
                    )
            except ValueError:
                return func.HttpResponse(
                    body=json.dumps({'error': 'Invalid date format. Use YYYY-MM-DD.'}),
                    status_code=400,
                    mimetype="application/json"
                )
        else:
            input_date = None

        employee_id_param = req.params.get('employeeId')
        page_number = int(req.params.get('page_number', 1))
        page_size = int(req.params.get('page_size', 10))

        offset = (page_number - 1) * page_size

        # Base query to fetch attendance records
        query = "SELECT * FROM c WHERE STARTSWITH(c.id, 'attendance_')"

        if input_date:
            query += f" AND c.date = '{date_param}'"
        if employee_id_param:
            query += f" AND c.employeeId = '{employee_id_param}'"

        query += " ORDER BY c.employeeId ASC"
        query += f" OFFSET {offset} LIMIT {page_size}"

        logging.info(f"Generated query: {query}")

        # Fetch paginated attendance records from the container
        paginated_items = list(attendance_container.query_items(query=query, enable_cross_partition_query=True))
        logging.info(f"Paginated items count: {len(paginated_items)}")

        # If no items are found, return an appropriate message
        if not paginated_items:
            return func.HttpResponse(
                body=json.dumps([]),
                status_code=200,
                mimetype="application/json"
            )

        # Fetch image URLs for each attendance record
        for item in paginated_items:
            employee_id = item.get('employeeId')
            # Fetch the employee image URL based on employeeId
            image_url = fetch_employee_image(employee_id)
            if image_url:
                item['imageUrl'] = image_url  # Add the image URL to the attendance record

        # Return paginated attendance records
        return func.HttpResponse(
            body=json.dumps(paginated_items),
            status_code=200,
            mimetype="application/json"
        )

    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Failed to fetch attendance records: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': f'Failed to fetch attendance records: {e.message}'}),
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
 
# Azure function to save data(tracker)
@app.function_name(name="saveData")
@app.route(route='api/saveData', methods=[func.HttpMethod.POST])
async def saveData(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Parse the incoming JSON data
        req_body = req.get_json()
        data = PageData(**req_body)
       
        if not data.cameraDetails:
            return func.HttpResponse(
                json.dumps({"detail": "Camera details must be provided."}),
                status_code=400
            )
 
        if data.documentId:
            try:
                item = setup_container_name.read_item(item=data.documentId, partition_key=data.documentId)
                item["capacityOfPeople"] = data.capacityOfPeople
                item["alertMessage"] = data.alertMessage
                item["cameraDetails"] = [camera.dict() for camera in data.cameraDetails]
 
                upsert_document(item)
                return func.HttpResponse(
                    json.dumps({"message": "Data updated successfully."}),
                    status_code=200
                )
            except exceptions.CosmosResourceNotFoundError:
                documentId = str(uuid.uuid4())
                document = {
                    "id": documentId,
                    "camera": documentId,
                    "capacityOfPeople": data.capacityOfPeople,
                    "alertMessage": data.alertMessage,
                    "cameraDetails": [camera.dict() for camera in data.cameraDetails]
                }
                upsert_document(document)
                return func.HttpResponse(
                    json.dumps({"message": "Data saved successfully as new document.", "documentId": documentId}),
                    status_code=201
                )
            except exceptions.CosmosHttpResponseError as e:
                logging.error(f"Error updating data: {str(e)}")
                return func.HttpResponse(
                    json.dumps({"detail": str(e)}),
                    status_code=500
                )
            except Exception as e:
                logging.error(f"Unexpected error: {str(e)}")
                return func.HttpResponse(
                    json.dumps({"detail": "An unexpected error occurred."}),
                    status_code=500
                )
        else:
            documentId = str(uuid.uuid4())
            document = {
                "id": documentId,
                "camera": documentId,
                "capacityOfPeople": data.capacityOfPeople,
                "alertMessage": data.alertMessage,
                "cameraDetails": [camera.dict() for camera in data.cameraDetails]
            }
            upsert_document(document)
            return func.HttpResponse(
                json.dumps({"message": "Data saved successfully.", "documentId": documentId}),
                status_code=201
            )
 
    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An error occurred during processing."}),
            status_code=500
        )
 
 
# Azure function to get camera URLs(tracker)
@app.function_name(name="getCameraUrlsTracker")
@app.route(route='api/getCameraUrls/{documentId}', methods=[func.HttpMethod.GET])
async def getCameraUrls(req: func.HttpRequest) -> func.HttpResponse:
    # Retrieve the documentId from the URL path
    documentId = req.route_params.get("documentId")
 
    try:
        # Fetch the document from Cosmos DB
        item = setup_container_name.read_item(item=documentId, partition_key=documentId)
        cameraDetails = item.get("cameraDetails", [])
        videoUrls = [camera["videoUrl"] for camera in cameraDetails]
       
        return func.HttpResponse(
            json.dumps({"videoUrls": videoUrls}),
            status_code=200
        )
    except exceptions.CosmosResourceNotFoundError:
        return func.HttpResponse(
            json.dumps({"detail": "Document not found."}),
            status_code=404
        )
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Error retrieving document: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "Failed to retrieve document."}),
            status_code=500
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An unexpected error occurred."}),
            status_code=500
        )
    

    # SEARCH API for Employee


@app.function_name(name="search_employee")
@app.route(route='employees/search', methods=[func.HttpMethod.GET])
def search_employee(req: func.HttpRequest) -> func.HttpResponse:
    # Retrieve the single search parameter
    search = req.params.get('search')

    # Ensure that the search parameter is provided
    if not search:
        return func.HttpResponse(
            body=json.dumps({'error': 'A search parameter is required'}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        # Initialize query conditions and parameters
        query_conditions = []
        parameters = []

        # Check if the search input is numeric (indicating employeeId)
        if search.isnumeric():
            # Use an exact match for employeeId
            query_conditions.append("c.employeeId = @employee_id")
            parameters.append({"name": "@employee_id", "value": search})
        else:
            # Use CONTAINS for partial matches in employeeName (case-insensitive)
            query_conditions.append("CONTAINS(LOWER(c.employeeName), LOWER(@employee_name))")
            parameters.append({"name": "@employee_name", "value": search.lower()})

        # Combine conditions with OR for flexibility
        query = "SELECT c.employeeId, c.employeeName, c.role, c.email, c.dateOfJoining, c.imageUrl FROM c WHERE " + " OR ".join(query_conditions)

        logging.info(f"Constructed query: {query}")  # Debugging line to ensure the query is constructed correctly

        # Perform the query to Cosmos DB
        items = list(employee_container.query_items(query=query, parameters=parameters, enable_cross_partition_query=True))

        if items:
            # If there are results, return them
            return func.HttpResponse(
                body=json.dumps(items),
                status_code=200,
                mimetype="application/json"
            )

        # If no items found, return a 404 response
        return func.HttpResponse(
            body=json.dumps({'message': 'Employee not found'}),
            status_code=404,
            mimetype="application/json"
        )

    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Failed to search employee records: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': f'Failed to search employee records: {e.message}'}),
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
async def saveCameraUrls(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Parse the incoming JSON data
        req_body = req.get_json()
        
        # Auto-generate a new unique id
        camera_id = str(uuid.uuid4())

        # Extract and validate `cameraDetails1`
        camera_details = req_body.get("cameraDetails1", [])
        if not camera_details or not isinstance(camera_details, list):
            return func.HttpResponse(
                json.dumps({"detail": "Missing or invalid field: 'cameraDetails1'."}),
                status_code=400
            )
        
        validated_camera_details = []
        for detail in camera_details:
            if not all(key in detail for key in ["email", "cameraI", "punchinUrl", "cameraII", "punchoutUrl"]):
                return func.HttpResponse(
                    json.dumps({"detail": "Each item in 'cameraDetails1' must contain 'email', 'cameraI', 'punchinUrl', 'cameraII', and 'punchoutUrl'."}),
                    status_code=400
                )
            
            # Filter and store only the required keys
            validated_camera_details.append({
                "email": detail["email"],
                "cameraI": detail["cameraI"],
                "punchinUrl": detail["punchinUrl"],
                "cameraII": detail["cameraII"],
                "punchoutUrl": detail["punchoutUrl"]
            })

        # Create camera data with auto-generated id
        camera_data = {
            "id": camera_id,
            "cameraDetails1": validated_camera_details
        }

        # Upsert the camera URLs into Cosmos DB
        upsert_camera_urls(camera_data)

        return func.HttpResponse(
            json.dumps({"message": "Camera URLs saved successfully.", "id": camera_id}),
            status_code=201
        )
    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An error occurred during processing."}),
            status_code=500
        )



def upsert_camera_urls(camera_data):
    # Assuming camera_urls_container is your Cosmos DB container
    # Upsert the item directly as a dictionary
    camera_urls_container.upsert_item(camera_data)

# put method to update cameraurl -attendance
@app.function_name(name="updateCameraUrl")
@app.route(route='api/cameraUrl', methods=[func.HttpMethod.PUT])
async def updateCameraUrls(req: func.HttpRequest) -> func.HttpResponse:
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
        camera_details = req_body.get("cameraDetails1", [])
        
        if not camera_details:
            return func.HttpResponse(
                json.dumps({"detail": "Missing required field: 'cameraDetails1'."}),
                status_code=400
            )

        # Fetch existing camera data
        existing_data = get_camera_data_by_id(camera_id)
        
        if not existing_data:
            return func.HttpResponse(
                json.dumps({"detail": f"No camera data found for ID: {camera_id}."}),
                status_code=404
            )

        # Update the existing camera details with the new details
        existing_data["cameraDetails1"] = camera_details
        
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
async def getCameraUrlById(req: func.HttpRequest) -> func.HttpResponse:
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
def add_organization(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Extract JSON data from the request body
        json_data = req.get_json()

        if not json_data:
            return func.HttpResponse(
                body=json.dumps({'error': 'JSON data is required in the request body'}),
                status_code=400,
                mimetype="application/json"
            )

        # Extract fields from the JSON data
        organization_name = json_data.get('organizationName')
        phone_number = json_data.get('phoneNumber')
        website_url = json_data.get('websiteUrl')
        domain_name = json_data.get('domainName')
        address = json_data.get('address')

        # Validate mandatory field
        if not organization_name:
            return func.HttpResponse(
                body=json.dumps({'error': 'Organization name is mandatory'}),
                status_code=400,
                mimetype="application/json"
            )

        # Create a unique ID for the organization
        organization_id = str(uuid.uuid4())

        # Check for duplicate organization names
        query = f"SELECT * FROM c WHERE c.organizationName = '{organization_name}'"
        existing_organizations = list(organization_container_name.query_items(
            query=query, enable_cross_partition_query=True
        ))

        if existing_organizations:
            return func.HttpResponse(
                body=json.dumps({'warn': f'Organization "{organization_name}" already exists'}),
                status_code=409,  # Conflict status code
                mimetype="application/json"
            )

        # Create the organization record
        organization_record = {
            'id': organization_id,
            'organizationName': organization_name,
            'phoneNumber': phone_number,
            'websiteUrl': website_url,
            'domainName': domain_name,
            'address': address,
            'createdAt': datetime.utcnow().isoformat(),
        }

        # Save the organization record in Cosmos DB
        organization_container_name.create_item(body=organization_record)

        return func.HttpResponse(
            body=json.dumps({'message': 'Organization added successfully', 'data': organization_record}),
            status_code=201,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error adding organization: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': str(e)}),
            status_code=500,
            mimetype="application/json"
        )


@app.function_name(name="getAllPersons")
@app.route(route='api/getAllPersons', methods=[func.HttpMethod.GET])
async def getAllPersons(req: func.HttpRequest) -> func.HttpResponse:
    try:
        query = """
        SELECT VALUE {
            'person_id': c.person_id,
            'camera_id': c.camera_id,
            'timestamp': c.timestamp,
            'last_updated': c.last_updated
        }
        FROM c
        WHERE NOT IS_NULL(c.person_id)
        """
        items = person_features.query_items(query=query, enable_cross_partition_query=True)
        
        persons = [
            {
                "person_id": item["person_id"],
                "camera_id": item["camera_id"],
                "timestamp": item["timestamp"],
                "last_updated": item["last_updated"]
            }
            for item in items
        ]

        return func.HttpResponse(
            json.dumps({"persons": persons}),
            status_code=200,
            mimetype="application/json"
        )
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Failed to retrieve all persons: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "Failed to retrieve all persons."}),
            status_code=500
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An unexpected error occurred."}),
            status_code=500
        )


@app.function_name(name="getAllCounts")
@app.route(route='api/getAllCounts', methods=[func.HttpMethod.GET])
async def getAllCounts(req: func.HttpRequest) -> func.HttpResponse:
    try:
        query = "SELECT * FROM c"
        items = counts_container.query_items(query=query, enable_cross_partition_query=True)
        counts = {
            str(item["camera_id"]): {
                "entry": int(item.get("entry", 0)),
                "exit": int(item.get("exit", 0))
            }
            for item in items
        }

        return func.HttpResponse(
            json.dumps({"counts": counts}),
            status_code=200,
            mimetype="application/json"
        )
    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Failed to retrieve all counts: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "Failed to retrieve all counts."}),
            status_code=500
        )
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"detail": "An unexpected error occurred."}),
            status_code=500
        )
    







# # image validation

# import base64
# import uuid
# import logging
# import json
# import re
# import cv2
# import requests
# import numpy as np
# from insightface.app import FaceAnalysis
# from sklearn.metrics.pairwise import cosine_similarity
# import azure.functions as func

# # Assuming EmployeeRepository class is already defined
# class EmployeeRepository:
#     def __init__(self, container):
#         self.container = container
#         self.employees = {}
#         self.employee_embeddings = {}

#     def fetch_employees(self, face_recognizer):
#         try:
#             employees = list(self.container.read_all_items())
#             logging.info(f"Fetched {len(employees)} employees.")

#             for employee in employees:
#                 name = employee['employeeName']
#                 image_url = employee['imageUrl']

#                 # Download and process image
#                 img = self._download_image(image_url)
#                 if img is not None:
#                     self.employees[name] = img

#                     # Extract face embedding
#                     try:
#                         faces = face_recognizer.get(img)
#                         if faces:
#                             self.employee_embeddings[name] = self._normalize_embedding(faces[0]['embedding'])
#                         else:
#                             logging.warning(f"No face detected for {name}")
#                     except Exception as e:
#                         logging.error(f"Error processing embedding for {name}: {e}")
#         except Exception as e:
#             logging.error(f"Failed to fetch employees: {e}")

#     def _download_image(self, url):
#         try:
#             logging.info(f"Downloading image from URL: {url}")
#             response = requests.get(url, timeout=5)
#             response.raise_for_status()
#             img_array = np.asarray(bytearray(response.content), dtype=np.uint8)
#             img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
#             if img is None:
#                 raise ValueError("Unable to decode the downloaded image.")
#             return img
#         except Exception as e:
#             logging.error(f"Error downloading or decoding image from {url}: {e}")
#             return None

#     def _normalize_embedding(self, embedding):
#         return embedding / np.linalg.norm(embedding)

#     def get_known_faces(self):
#         return self.employees, self.employee_embeddings


# # Function to upload an image to Azure Blob Storage
# def upload_image_to_blob1(base64_image, employee_id):
#     try:
#         # Decode the image
#         image_bytes = base64.b64decode(base64_image)
#         file_name = f"{employee_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.jpg"

#         # Get BlobServiceClient
#         blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)

#         # Get container client
#         container_client = blob_service_client.get_container_client(STORAGE_CONTAINER_NAME)

#         # Verify container exists, or create it
#         if not container_client.exists():
#             logging.warning(f"Container '{STORAGE_CONTAINER_NAME}' not found. Creating it...")
#             container_client.create_container()

#         # Upload the file
#         blob_client = container_client.get_blob_client(file_name)
#         blob_client.upload_blob(image_bytes, overwrite=True)

#         # Construct and return the image URL
#         image_url = f"https://{STORAGE_ACCOUNT_NAME}.blob.core.windows.net/{STORAGE_CONTAINER_NAME}/{file_name}"
#         return image_url

#     except Exception as e:
#         logging.error(f"Error uploading image to Blob: {e}")
#         return None


# # Updated Add Employee Function
# @app.function_name(name="add_employee")
# @app.route(route='employee', methods=[func.HttpMethod.POST])
# def add_employee(req: func.HttpRequest) -> func.HttpResponse:
#     try:
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
#         role = json_data.get('role')
#         email = json_data.get('email')
#         base64_image = json_data.get('imageBase64')  # Base64-encoded image
#         date_of_joining = json_data.get('dateOfJoining')

#         if not base64_image:
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'ImageBase64 is required in the request'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Decode the base64 string into an image
#         try:
#             image_bytes = base64.b64decode(base64_image)
#             img_array = np.frombuffer(image_bytes, np.uint8)
#             img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

#             if img is None:
#                 raise ValueError("Decoded image is None. Invalid or corrupted image data.")

#         except Exception as e:
#             logging.error(f"Error decoding image: {e}")
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'Invalid image data'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Initialize the FaceAnalysis object
#         face_recognizer = FaceAnalysis()
#         face_recognizer.prepare(ctx_id=0)

#         # Fetch all employees to detect duplicate faces
#         employee_repository = EmployeeRepository(employee_container)
#         employee_repository.fetch_employees(face_recognizer)
#         _, known_embeddings = employee_repository.get_known_faces()

#         # Detect faces in the new image
#         new_faces = face_recognizer.get(img)
#         if not new_faces:
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'No face detected in the image'}),
#                 status_code=400,
#                 mimetype="application/json"
#             )

#         # Normalize the new face embedding
#         new_embedding = new_faces[0]['embedding'] / np.linalg.norm(new_faces[0]['embedding'])

#         # Compare with existing embeddings to check for duplicates
#         for name, existing_embedding in known_embeddings.items():
#             similarity = cosine_similarity([new_embedding], [existing_embedding])[0][0]
#             if similarity > 0.7:
#                 return func.HttpResponse(
#                     body=json.dumps({'warn': f'Employee image already exists for {name}'}),
#                     status_code=409,
#                     mimetype="application/json"
#                 )

#         # Upload the image to Blob Storage
#         image_url = upload_image_to_blob1(base64_image, employee_id)
#         if not image_url:
#             return func.HttpResponse(
#                 body=json.dumps({'error': 'Image upload failed. Please try again.'}),
#                 status_code=500,
#                 mimetype="application/json"
#             )

#         # Create and store employee record
#         employee_record = {
#             'id': str(uuid.uuid4()),
#             'employeeId': employee_id,
#             'role': role,
#             'email': email,
#             'imageUrl': image_url,
#             'dateOfJoining': date_of_joining,
#         }

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



# import azure.functions as func
# import json
# import logging
# import uuid
# import re
# from deepface import DeepFace
# import numpy as np
# import cv2
# import base64
# import io
# from PIL import Image

# def convert_base64_to_image(base64_string):
#     """Convert base64 string to image array"""
#     img_data = base64.b64decode(base64_string)
#     img = Image.open(io.BytesIO(img_data))
#     return np.array(img)

# def check_face_exists(new_face_image, container):
#     """
#     Check if the face already exists in the database
#     Returns: (bool, str) - (exists, matching_employee_name)
#     """
#     try:
#         # Convert new face image from base64 to array
#         new_face_array = convert_base64_to_image(new_face_image)
        
#         # Query all employees with images
#         query = "SELECT c.imageBase64, c.employeeName FROM c WHERE c.imageBase64 != null"
#         existing_employees = list(container.query_items(
#             query=query,
#             enable_cross_partition_query=True
#         ))
        
#         # Compare with each existing face
#         for employee in existing_employees:
#             try:
#                 existing_face_array = convert_base64_to_image(employee['imageBase64'])
                
#                 # Use DeepFace to verify faces
#                 result = DeepFace.verify(
#                     img1_path=new_face_array,
#                     img2_path=existing_face_array,
#                     enforce_detection=False,
#                     model_name="VGG-Face"
#                 )
                
#                 # If verified with high confidence
#                 if result["verified"] and result["distance"] < 0.4:  # Adjust threshold as needed
#                     return True, employee['employeeName']
                    
#             except Exception as e:
#                 logging.warning(f"Error comparing with one face: {str(e)}")
#                 continue
                
#         return False, None
        
#     except Exception as e:
#         logging.error(f"Error in face comparison: {str(e)}")
#         raise

