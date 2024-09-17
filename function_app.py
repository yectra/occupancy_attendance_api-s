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
# GET Employee
@app.function_name(name="get_employee")
@app.route(route='employee/{employee_id}', methods=[func.HttpMethod.GET])
def get_employee(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Extract employee_id from the route parameters
        employee_id = req.route_params.get('employee_id')

        # Ensure employee_id is an integer (if it's numeric)
        employee_id = int(employee_id)

        # Query to fetch employee record by employee_Id
        query = "SELECT * FROM c WHERE c.employeeId = @employee_id"
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
# Search Attendance
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
            query_conditions.append(f"c.employeeId = {employee_id}")
        if employee_name:
            query_conditions.append(f"c.employeeName = '{employee_name}'")
        if date:
            query_conditions.append(f"c.date = '{date}'")

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
        employee_id = json_data.get('employeeId')
        name = json_data.get('employeeName')
        role = json_data.get('role')
        email = json_data.get('email')
        action = json_data.get('action')
        base64_image = json_data.get('imageBase64')  # Base64-encoded image
        date_of_joining = json_data.get('dateOfJoining')  # New field

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
            'employeeId': employee_id,
            'employeeName': name,
            'role': role,
            'email': email,
            'action': action,
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


                        # Define the Azure Function for updating an employee



@app.function_name(name="update_employee")
@app.route(route="update-employee/{employee_id}", methods=[func.HttpMethod.PUT])
def update_employee(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing update employee request.')

    try:
        employee_id = int(req.route_params.get('employee_id'))
        logging.info(f"Employee ID received: {employee_id}")
        data = req.get_json()
        base64_image = data.get('imageBase64')

        # Fetch the existing employee record
        query = f"SELECT * FROM c WHERE c.employeeId = {employee_id}"
        logging.info(f"Query: {query}")
        items = list(employee_container.query_items(query=query, enable_cross_partition_query=True))
        logging.info(f"Items found: {items}")
        
        if items:
            item = items[0]

            # Upload new image if provided
            if base64_image:
                image_url = upload_image_to_blob(base64_image, employee_id)
                if item.get('imageUrl'):
                    delete_image_from_blob(item['imageUrl'])  # Delete the old image from blob storage
                item['imageUrl'] = image_url
            
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
        query = f"SELECT * FROM c WHERE c.employeeId = {employee_id}"
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

    

    
    # Attendance API's all,date,id





@app.function_name(name="get_attendance")
@app.route(route="getattendance/all", methods=[func.HttpMethod.GET])
def get_all_attendance(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Processing request to get attendance records.')

    try:
        # Fetch optional parameters
        date_param = req.params.get('date')
        employee_id_param = req.params.get('employeeId')

        # Ensure employeeId is stripped of any leading/trailing whitespace and cast to an integer if provided
        if employee_id_param:
            try:
                employee_id_param = int(employee_id_param.strip())
            except ValueError:
                return func.HttpResponse(
                    body=json.dumps({'error': 'Invalid employeeId. It should be an integer.'}),
                    status_code=400,
                    mimetype="application/json"
                )

        # Base query for all attendance records
        query = "SELECT * FROM c WHERE STARTSWITH(c.id, 'attendance_')"

        # Add filter for date if provided
        if date_param:
            query += f" AND c.date = '{date_param}'"

        # Add filter for employeeId if provided
        if employee_id_param:
            query += f" AND c.employeeId = {employee_id_param}"

        # Execute query to fetch attendance records
        items = list(attendance_container.query_items(query=query, enable_cross_partition_query=True))

        if items:
            return func.HttpResponse(
                body=json.dumps(items),
                status_code=200,
                mimetype="application/json"
            )

        return func.HttpResponse(
            body=json.dumps({'message': 'No attendance records found'}),
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



