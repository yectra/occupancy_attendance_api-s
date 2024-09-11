import json
import logging
import azure.functions as func
from dotenv import load_dotenv
from azure.cosmos import CosmosClient, exceptions
from azure.storage.blob import BlobServiceClient, ContentSettings
import os
import uuid
import base64

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

# Load environment variables from .env file
load_dotenv()

# Azure Cosmos DB configuration
COSMOS_CONNECTION_STRING = os.getenv('COSMOS_CONNECTION_STRING')
DATABASE_NAME = os.getenv('DATABASE_NAME')
EMPLOYEE_CONTAINER_NAME = os.getenv('EMPLOYEE_CONTAINER_NAME')
ATTENDANCE_CONTAINER_NAME = os.getenv('ATTENDANCE_CONTAINER_NAME')

# Azure Blob Storage configuration
BLOB_CONNECTION_STRING = os.getenv('STORAGE_CONNECTION_STRING')
BLOB_CONTAINER_NAME = os.getenv('STORAGE_CONTAINER_NAME')

# Initialize the Cosmos client
client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
database = client.get_database_client(DATABASE_NAME)
employee_container = database.get_container_client(EMPLOYEE_CONTAINER_NAME)
attendance_container = database.get_container_client(ATTENDANCE_CONTAINER_NAME)  # Define attendance_container

# Initialize the Blob Service Client
blob_service_client = BlobServiceClient.from_connection_string(BLOB_CONNECTION_STRING)
blob_container_client = blob_service_client.get_container_client(BLOB_CONTAINER_NAME)

print('Successfully connected all the strings')
                                        # get employee
@app.function_name(name="get_employee")
@app.route(route='employee/{employee_id}', methods=[func.HttpMethod.GET])
def get_employee(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Extract employee_id from the route parameters
        employee_id = req.route_params.get('employee_id')

        # Ensure employee_id is an integer (if it's numeric)
        employee_id = int(employee_id)

        # Query to fetch employee record by employee_Id
        query = "SELECT * FROM c WHERE c.employee_Id = @employee_id"
        parameters = [{"name": "@employee_id", "value": employee_id}]
        items = list(employee_container.query_items(query=query, parameters=parameters, enable_cross_partition_query=True))

        if items:
            return func.HttpResponse(
                body=json.dumps(items[0]),
                status_code=200,
                mimetype="application/json"
            )

        return func.HttpResponse(
            body=json.dumps({'message': 'Employee not found'}),
            status_code=404,
            mimetype="application/json"
        )

    except Exception as e:
        logging.error(f"Error fetching employee: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': str(e)}),
            status_code=500,
            mimetype="application/json"
        )
    
                                # Fetch all employee records
@app.function_name(name="get_all_employees")
@app.route(route='employees', methods=[func.HttpMethod.GET])
def get_all_employees(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Fetch all employee records
        query = "SELECT * FROM c"
        items = list(employee_container.query_items(query=query, enable_cross_partition_query=True))
        
        return func.HttpResponse(
            body=json.dumps(items),
            status_code=200,
            mimetype="application/json"
        )
    
    except Exception as e:
        logging.error(f"Error fetching all employees: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': str(e)}),
            status_code=500,
            mimetype="application/json"
        )
# search attendance
@app.function_name(name="search_attendance")
@app.route(route='attendance/search', methods=[func.HttpMethod.GET])
def search_attendance(req: func.HttpRequest) -> func.HttpResponse:
    employee_id = req.params.get('employee_id')
    employee_name = req.params.get('employee_name')
    date = req.params.get('date')

    if not (employee_id or employee_name or date):
        return func.HttpResponse(
            body=json.dumps({'error': 'At least one search parameter (employee_id, employee_name, or date) is required'}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        # Build the query dynamically based on the provided parameters
        query_conditions = []

        if employee_id:
            query_conditions.append(f"c['employee_Id'] = {employee_id}")
        if employee_name:
            query_conditions.append(f"c['employee_Name'] = '{employee_name}'")
        if date:
            query_conditions.append(f"c.Date = '{date}'")

        # Combine conditions with AND
        query = "SELECT * FROM c WHERE " + " AND ".join(query_conditions)
        
        logging.info(f"Constructed query: {query}")  # Debugging line to ensure the query is constructed correctly

        items = list(attendance_container.query_items(query=query, enable_cross_partition_query=True))
        
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

def upload_image_to_blob(base64_image, employee_id):
    try:
        # Remove the base64 data URL scheme if present
        if base64_image.startswith('data:image'):
            base64_image = base64_image.split(',')[1]
        
        # Decode the base64 string
        image_data = base64.b64decode(base64_image)
        
        # Generate a unique blob name
        blob_name = f"{employee_id}/{uuid.uuid4()}.jpg"  # Assuming image is in JPEG format
        blob_client = blob_container_client.get_blob_client(blob_name)
        
        # Upload the image
        blob_client.upload_blob(image_data, overwrite=True, content_settings=ContentSettings(content_type='image/jpeg'))
        
        # Construct the URL of the uploaded image
        blob_url = f"https://{blob_service_client.account_name}.blob.core.windows.net/{BLOB_CONTAINER_NAME}/{blob_name}"
        return blob_url
    except Exception as e:
        print(f"Error uploading image to blob: {e}")
        return None
    
def delete_image_from_blob(blob_url):
    try:
        # Extract the blob name from the URL
        blob_name = "/".join(blob_url.split('/')[-2:])
        blob_client = blob_container_client.get_blob_client(blob_name)
        blob_client.delete_blob()
    except Exception as e:
        print(f"Error deleting image from blob: {e}")

                    # Define the Azure Function for adding an employee

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
        employee_id = json_data.get('employee_Id')
        name = json_data.get('employee_Name')
        role = json_data.get('role')
        email = json_data.get('email')
        action = json_data.get('action')
        base64_image = json_data.get('ImageBase64')  # Base64-encoded image
        date_of_joining = json_data.get('date_of_joining')  # New field

        # Check if required fields are provided
        if not employee_id or not name or not role or not email or not action or not date_of_joining:
            return func.HttpResponse(
                body=json.dumps({'error': 'All fields except image are required'}),
                status_code=400,
                mimetype="application/json"
            )

        # Upload the image if provided
        image_url = upload_image_to_blob(base64_image, employee_id) if base64_image else None

        # Create the employee record
        employee_record = {
            'id': str(uuid.uuid4()),
            'employee_Id': employee_id,
            'employee_Name': name,
            'role': role,
            'email': email,
            'action': action,
            'image_Url': image_url,
            'date_of_joining': date_of_joining,  # Add date_of_joining field
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


                        # Define the Azure Function for updating an employee



@app.function_name(name="update_employee")
@app.route(route="update-employee/{employee_id}", methods=[func.HttpMethod.PUT])
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing update employee request.')

    try:
        employee_id = int(req.route_params.get('employee_id'))
        logging.info(f"Employee ID received: {employee_id}")
        data = req.get_json()
        base64_image = data.get('ImageBase64')

        # Fetch the existing employee record
        query = f"SELECT * FROM c WHERE c.employee_Id = {employee_id}"
        logging.info(f"Query: {query}")
        items = list(employee_container.query_items(query=query, enable_cross_partition_query=True))
        logging.info(f"Items found: {items}")
        
        if items:
            item = items[0]

            # Upload new image if provided
            if base64_image:
                image_url = upload_image_to_blob(base64_image, employee_id)
                if item.get('image_Url'):
                    delete_image_from_blob(item['image_Url'])  # Delete the old image from blob storage
                item['image_Url'] = image_url
            
            # Update other fields
            item.update(data)
            employee_container.replace_item(item=item, body=item)
            return func.HttpResponse(
                json.dumps({'message': 'Employee updated successfully', 'data': item}),
                status_code=200,
                mimetype="application/json"
            )
        return func.HttpResponse(
            json.dumps({'message': 'Employee not found'}),
            status_code=404,
            mimetype="application/json"
        )
    except Exception as e:
        logging.error(f"Error updating employee: {str(e)}")
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
        query = f"SELECT * FROM c WHERE c.employee_Id = {employee_id}"
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
    

    # Attendance API's

                                            # 1.get_attendance_emp_id,date


@app.function_name(name="get_attendance")
@app.route(route="attendance", methods=[func.HttpMethod.GET])
def get_attendance(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing attendance request.')

    # Extract employee_id and date from the query parameters
    employee_id = req.params.get('employee_id')
    date = req.params.get('date')

    if not employee_id or not date:
        return func.HttpResponse(
            body=json.dumps({'error': 'Both employee_id and date parameters are required'}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        # Construct the ID for the attendance record
        attendance_id = f"attendance_{employee_id}_{date}"
        
        # Fetch the attendance record from the Cosmos DB
        attendance_record = attendance_container.read_item(item=attendance_id, partition_key=attendance_id)

        # Return the attendance record
        return func.HttpResponse(
            body=json.dumps(attendance_record),
            status_code=200,
            mimetype="application/json"
        )

    except exceptions.CosmosResourceNotFoundError:
        return func.HttpResponse(
            body=json.dumps({'error': f'No attendance record found for Employee ID {employee_id} on {date}'}),
            status_code=404,
            mimetype="application/json"
        )

    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Failed to fetch attendance record: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': f'Failed to fetch attendance record: {e.message}'}),
            status_code=500,
            mimetype="application/json"
        )


                                         # 2.getall_attendance_by_date

@app.function_name(name="get_all_attendance_by_date")
@app.route(route="attendance/all", methods=[func.HttpMethod.GET])
def get_all_attendance_by_date(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing request to get all attendance records by date.')

    # Extract date from the query parameters
    date = req.params.get('date')

    if not date:
        return func.HttpResponse(
            body=json.dumps({'error': 'Date parameter is required'}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        # Query to fetch all attendance records for the specific date
        query = f"SELECT * FROM c WHERE STARTSWITH(c.id, 'attendance_') AND CONTAINS(c.Date, '{date}')"
        items = list(attendance_container.query_items(query=query, enable_cross_partition_query=True))
        
        if items:
            return func.HttpResponse(
                body=json.dumps(items),
                status_code=200,
                mimetype="application/json"
            )
        
        return func.HttpResponse(
            body=json.dumps({'message': f'No attendance records found for the date {date}'}),
            status_code=404,
            mimetype="application/json"
        )

    except exceptions.CosmosHttpResponseError as e:
        logging.error(f"Failed to fetch attendance records: {str(e)}")
        return func.HttpResponse(
            body=json.dumps({'error': f'Failed to fetch attendance records: {e.message}'}),
            status_code=500,
            mimetype="application/json"
        )