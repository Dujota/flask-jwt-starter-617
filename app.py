from dotenv import load_dotenv
import os
load_dotenv()

# Import the 'Flask' class from the 'flask' library.
from flask import Flask, jsonify, request
import jwt
import bcrypt
import psycopg2, psycopg2.extras


# Initialize Flask
# We'll use the pre-defined global '__name__' variable to tell Flask where it is.
app = Flask(__name__)

def get_db_connection():
    connection = psycopg2.connect(host='localhost',
                            database='flask_auth_db',)
                            # user=os.getenv('POSTGRES_USERNAME'),
                            # password=os.getenv('POSTGRES_PASSWORD'))
    return connection

# Define our route
# This syntax is using a Python decorator, which is essentially a succinct way to wrap a function in another function.
@app.route('/')
def index():
  return "Hello, world!"

# AUTH ROUTES
@app.route('/auth/signup', methods=['POST'])
def signup():
    try:
      new_user_data = request.get_json()
      #  validate that the passwords match with the confirm password?
      # see if this person exists in the DB
      connection = get_db_connection()
      cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
      cursor.execute("SELECT * FROM users WHERE username = %s;", (new_user_data["username"],))
      existing_user = cursor.fetchone()

      #if the person exists, then we dont allow a new accoutn to be created

      if existing_user:
            cursor.close()
            return jsonify({"error": "Username already taken"}), 400
      #else

      # encrypt the password
      hashed_password = bcrypt.hashpw(bytes(new_user_data["password"], 'utf-8'), bcrypt.gensalt())
      # go ahead and create account - ISERT INTO DB
      cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s) RETURNING username, id", (new_user_data["username"], hashed_password.decode('utf-8')))
      created_user = cursor.fetchone()
      connection.commit()
      connection.close()
      # send success response back to client
      token = jwt.encode(created_user, os.getenv('JWT_SECRET'))
      return jsonify({"token": token, "user": created_user}), 201

    except Exception as error:
       return jsonify({"error": error.message})


@app.route('/auth/signin', methods=["POST"])
def signin():
  try:
    sign_in_form_data = request.get_json()
     # first look up the user in the database from the username
    connection = get_db_connection()
    cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT * FROM users WHERE username = %s;", (sign_in_form_data["username"],))
    existing_user = cursor.fetchone()
     #if the user does not exist in the db, then exit with error
    if existing_user is None:
      return jsonify({"error": "Invalid credentials."}), 401
     #else
     # take the password that was submitted and use bcrypt to verify the password
    password_is_valid = bcrypt.checkpw(bytes(sign_in_form_data["password"], 'utf-8'), bytes(existing_user["password"], 'utf-8'))
     # send error msg - invalid creds
    if not password_is_valid:
            return jsonify({"error": "Invalid credentials."}), 401
     #if the password is good, then we "sign the person in"
     # JWT lib will generate the token (sign token)
    token = jwt.encode({"username": existing_user["username"], "id": existing_user["id"]}, os.getenv('JWT_SECRET'))
    return jsonify({"token": token}), 201

  except Exception as error:
    return jsonify({"error": "Invalid credentials."}), 401


# PROTECTED ROUTES

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

