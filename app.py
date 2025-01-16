from dotenv import load_dotenv
import os
load_dotenv()

# Import the 'Flask' class from the 'flask' library.
from flask import Flask, jsonify, request
import jwt

# Initialize Flask
# We'll use the pre-defined global '__name__' variable to tell Flask where it is.
app = Flask(__name__)

# Define our route
# This syntax is using a Python decorator, which is essentially a succinct way to wrap a function in another function.
@app.route('/')
def index():
  return "Hello, world!"

@app.route('/sign-token', methods=['GET'])
def sign_token():
    user = {
        "id": 1,
        "username": "test",
        "password": "test"
    }

    token = jwt.encode(user, os.getenv('JWT_SECRET'), algorithm="HS256")
    return jsonify({"token": token})

@app.route('/verify-token', methods=['POST'])
def verify_token():
    try:
      token = request.headers.get('Authorization').split(' ')[1]
      decoded_token = jwt.decode(token, os.getenv('JWT_SECRET'), algorithms=["HS256"])
      return jsonify({"user": decoded_token})
    except Exception as error:
       return jsonify({"error": "unauthorized" })

# Run our application, by default on port 5000
app.run()
