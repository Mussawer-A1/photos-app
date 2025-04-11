from flask import Flask, request, jsonify
from flask_cors import CORS
from flask import request, jsonify, g
from azure.storage.blob import BlobServiceClient
import uuid
import pymongo
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import jwt
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# MongoDB setup
client = os.getenv("AZURE_COSMOS_CONNECTIONSTRING")
client = pymongo.MongoClient(client)
db = client['photoapp']
photos = db['photos']
comments = db['comments']
ratings = db['ratings']
users = db['users']  # For storing users

SECRET_KEY = os.getenv("SECRET_KEY")


def upload_file_to_blob(file, filename):
    try:
        connect_str = os.getenv("BLOB_CONN")
        if not connect_str:
            raise ValueError("BLOB_CONN environment variable not set.")

        container_name = "photo-container"
        blob_service_client = BlobServiceClient.from_connection_string(connect_str)
        container_client = blob_service_client.get_container_client(container_name)
        blob_client = container_client.get_blob_client(filename)

        # Upload directly using the FileStorage object
        blob_client.upload_blob(file, overwrite=True)

        return blob_client.url

    except Exception as e:
        print(f"Error during file upload: {e}")
        raise


# Function to generate JWT token
def generate_token(user_id, role):
    payload = {
        "user_id": user_id,
        "role": role,
        "exp": datetime.utcnow() + timedelta(hours=1)  # Token expires in 1 hour
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Middleware to check for valid JWT token
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing"}), 403
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = users.find_one({"_id": data["user_id"]})
            if not current_user:
                return jsonify({"error": "User not found"}), 404
            g.user = current_user
            g.role = data["role"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    
    return decorator

def check_role(required_role):
    def wrapper(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            if not hasattr(g, "role") or g.role != required_role:
                return jsonify({"error": f"Permission denied. {required_role} role required."}), 403
            return f(*args, **kwargs)
        return decorator
    return wrapper




@app.route('/signup', methods=['POST'])
def signup():
    username = request.json.get('username')
    password = request.json.get('password')
    role = request.json.get('role')
    
    if not username or not password or not role:
        return jsonify({"error": "Missing required fields"})

    # Check if the username already exists
    existing_user = users.find_one({"username": username})
    if existing_user:
        return jsonify({"error": "Username already exists"})

    # Save the new user (you should hash the password in a real app)
    new_user = {
        "username": username,
        "password": password,
        "role": role,
        "created_at": datetime.utcnow()
    }
    users.insert_one(new_user)
    
    # Generate JWT token for the new user
    token = generate_token(str(new_user["_id"]), role)
    return jsonify({"message": "User created", "token": token})




@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})




@app.route('/login', methods=['POST'])
def login():
    # Simulating user login
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Find user by username in MongoDB (you should hash passwords in a real app)
    user = users.find_one({"username": username, "password": password})
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Generate JWT token with the user's ID and role
    token = generate_token(str(user["_id"]), user["role"])
    return jsonify({
    "success": True,
    "token": token,
    "role": user["role"]
})

@app.route('/upload', methods=['POST'])
@token_required
@check_role("creator")  # Only creators can upload photos
def upload_photo():
    file = request.files['file']
    metadata = request.form.to_dict()
    
    filename = str(uuid.uuid4()) + "_" + file.filename
    print("About to upload to container")
    blob_url = upload_file_to_blob(file, filename)
    print("Uploaded to container")
    
    metadata.update({
        "blob_url": blob_url,
        "uploaded_at": datetime.utcnow(),
    })
    
    photos.insert_one(metadata)
    return jsonify({"message": "Photo uploaded", "blob_url": blob_url})

@app.route('/photos', methods=['GET'])
@token_required
def list_photos():
    photo_list = list(photos.find({}, {'_id': 0}))
    return jsonify(photo_list)

@app.route('/photos/<title>/comment', methods=['POST'])
@token_required
def comment(title):
    comment_data = request.json
    comment_data["photo_title"] = title
    comment_data["timestamp"] = datetime.utcnow()
    
    comments.insert_one(comment_data)
    return jsonify({"message": "Comment added"})

@app.route('/photos/<title>/rate', methods=['POST'])
@token_required
def rate(title):
    rating_data = request.json
    rating_data["photo_title"] = title
    rating_data["timestamp"] = datetime.utcnow()
    
    ratings.insert_one(rating_data)
    return jsonify({"message": "Rating added"})
