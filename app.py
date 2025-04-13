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
from werkzeug.security import generate_password_hash, check_password_hash
import json
from bson import json_util

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

def parse_json(data):
    return json.loads(json_util.dumps(data))

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
        "exp": datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Middleware to check for valid JWT token
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        # Check for token in Authorization header
        if "Authorization" in request.headers:
            parts = request.headers["Authorization"].split(" ")
            if len(parts) == 2 and parts[0].lower() == "bearer":
                token = parts[1]

        if not token:
            return jsonify({"error": "Authentication required", "message": "No token provided"}), 401
        
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = users.find_one({"_id": data["user_id"]})
            if not current_user:
                return jsonify({"error": "User not found", "message": "User account may have been deleted"}), 404
            g.user = current_user
            g.role = data["role"]
            g.user_id = str(current_user["_id"])  # Store user ID as string
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired", "message": "Please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token", "message": "Authentication failed"}), 401
        except Exception as e:
            return jsonify({"error": "Authentication error", "message": str(e)}), 401

        return f(*args, **kwargs)
    
    return decorator

def check_role(required_role):
    def wrapper(f):
        @wraps(f)
        def decorator(*args, **kwargs):
            if not hasattr(g, "role"):
                return jsonify({"error": "Authorization error", "message": "User role not found"}), 403
            if g.role != required_role:
                return jsonify({
                    "error": "Permission denied",
                    "message": f"Requires {required_role} role",
                    "your_role": g.role
                }), 403
            return f(*args, **kwargs)
        return decorator
    return wrapper

@app.route('/signup', methods=['POST'])
def signup():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing required fields"}), 400

    # Check if the username already exists
    existing_user = users.find_one({"username": username})
    if existing_user:
        return jsonify({"error": "Username already exists"}), 409

    # Only allow consumer signups
    new_user = {
        "username": username,
        "password": generate_password_hash(password),  # Hash the password
        "role": "consumer",    # Force role to consumer
        "created_at": datetime.utcnow()
    }
    result = users.insert_one(new_user)
    
    # Generate JWT token for the new user
    token = generate_token(str(result.inserted_id), "consumer")
    return jsonify({
        "message": "User created successfully",
        "token": token,
        "role": "consumer"
    })

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    # Find user by username
    user = users.find_one({"username": username})
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Check password
    if not check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid credentials"}), 401
    
    # Generate JWT token
    token = generate_token(str(user["_id"]), user["role"])
    return jsonify({
        "success": True,
        "token": token,
        "role": user["role"],
        "message": "Login successful"
    })

@app.route('/upload', methods=['POST'])
@token_required
@check_role("creator")
def upload_photo():
    if 'file' not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    title = request.form.get('title')
    if not title:
        return jsonify({"error": "Title is required"}), 400
    
    try:
        filename = str(uuid.uuid4()) + "_" + file.filename
        blob_url = upload_file_to_blob(file, filename)
        
        photo_data = {
            "title": title,
            "caption": request.form.get('caption', ''),
            "location": request.form.get('location', ''),
            "blob_url": blob_url,
            "uploaded_by": g.user_id,
            "uploaded_at": datetime.utcnow(),
            "username": g.user['username']
        }
        
        photos.insert_one(photo_data)
        
        return jsonify({
            "message": "Photo uploaded successfully",
            "photo": {
                "title": photo_data['title'],
                "blob_url": photo_data['blob_url'],
                "caption": photo_data['caption'],
                "location": photo_data['location']
            }
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/photos', methods=['GET'])
@token_required
def list_photos():
    try:
        photo_list = list(photos.find({}, {'_id': 0}))
        return jsonify(photo_list)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/photos/user', methods=['GET'])
@token_required
def list_user_photos():
    try:
        user_photos = list(photos.find({"uploaded_by": g.user_id}, {'_id': 0}))
        return jsonify(user_photos)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/photos/<photo_title>', methods=['GET'])
@token_required
def get_photo_details(photo_title):
    try:
        photo = photos.find_one({"title": photo_title}, {'_id': 0})
        if not photo:
            return jsonify({"error": "Photo not found"}), 404
        
        # Get comments
        photo_comments = list(comments.find({"photo_title": photo_title}, {'_id': 0}))
        
        # Get average rating
        rating_cursor = ratings.aggregate([
            {"$match": {"photo_title": photo_title}},
            {"$group": {"_id": "$photo_title", "average": {"$avg": "$rating"}}}
        ])
        average_rating = list(rating_cursor)
        
        response = {
            "photo": photo,
            "comments": photo_comments,
            "average_rating": average_rating[0]['average'] if average_rating else 0
        }
        
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/photos/<photo_title>/comment', methods=['POST'])
@token_required
def add_comment(photo_title):
    text = request.json.get('text')
    if not text:
        return jsonify({"error": "Comment text is required"}), 400
    
    try:
        comment_data = {
            "photo_title": photo_title,
            "user_id": g.user_id,
            "username": g.user['username'],
            "text": text,
            "timestamp": datetime.utcnow()
        }
        
        comments.insert_one(comment_data)
        return jsonify({"message": "Comment added successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/photos/<photo_title>/rate', methods=['POST'])
@token_required
def add_rating(photo_title):
    rating = request.json.get('rating')
    if not rating or not isinstance(rating, int) or rating < 1 or rating > 5:
        return jsonify({"error": "Rating must be an integer between 1 and 5"}), 400
    
    try:
        # Check if user already rated this photo
        existing_rating = ratings.find_one({
            "photo_title": photo_title,
            "user_id": g.user_id
        })
        
        if existing_rating:
            ratings.update_one(
                {"_id": existing_rating['_id']},
                {"$set": {"rating": rating}}
            )
            message = "Rating updated successfully"
        else:
            rating_data = {
                "photo_title": photo_title,
                "user_id": g.user_id,
                "username": g.user['username'],
                "rating": rating,
                "timestamp": datetime.utcnow()
            }
            ratings.insert_one(rating_data)
            message = "Rating added successfully"
        
        return jsonify({"message": message})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/photos/search', methods=['GET'])
@token_required
def search_photos():
    query = request.args.get('q', '')
    if not query:
        return jsonify({"error": "Search query is required"}), 400
    
    try:
        regex_query = {'$regex': query, '$options': 'i'}  # 'i' for case insensitive
        results = list(photos.find({
            '$or': [
                {'title': regex_query},
                {'caption': regex_query},
                {'location': regex_query},
                {'username': regex_query}
            ]
        }, {'_id': 0}))
        
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

if __name__ == '__main__':
    app.run(debug=True)