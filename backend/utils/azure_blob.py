from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv
import os

load_dotenv()
connect_str = os.getenv("conn")
container_name = "photos"
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container_client = blob_service_client.get_container_client(container_name)

def upload_file_to_blob(file, filename):
    blob_client = container_client.get_blob_client(filename)
    blob_client.upload_blob(file, overwrite=True)
    return blob_client.url