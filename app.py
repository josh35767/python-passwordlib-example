from passlib.hash import pbkdf2_sha256
import json


# Base Response class for consistency. This allows for a JSON message to be sent out in the end, easily consumed by our webserver.
class Response:
    def __init__(self):
        self.data = {}
        self.error_message = ""

    def jsonify(self):
        response_dict = {"errorMessage": self.error_message, "data": self.data}
        return json.dumps(response_dict)


# Take the plain text password and hash it.
def hash_password(password):
    response = Response()
    if password == "":
        response.error_message = "Password can not be blank."
        return response.jsonify()
    # Does the actual work of hashing the password and will generate a salt automatically.
    hash = pbkdf2_sha256.hash(password) 
    response.data['hashedPassword'] = hash
    return response.jsonify()


# Take a plain text password and a hashed password and verify it's the correct password.
def verify_password(password_to_verify, password_hash):
    response = Response()
    if password_to_verify == "":
        response.error_message = "Must supply password to verify."
        return response.jsonify()
    if password_hash == "":
        response.error_message = "Must supply hashed password to verify with."
        return response.jsonify()
    # The verify function will be able to determine the salt and iterations from the password_hash argument.
    is_valid_password = pbkdf2_sha256.verify(password_to_verify, password_hash)
    response.data['isValidPassword'] = is_valid_password
    return response.jsonify()


# Lambdas uses a single function as a point of entry, so I use this function to mimic the same idea.
def handle_work(action, password_plaintext="", password_hashed=""):
    # I'm using this action variable instead of just assuming based on the arguments passed in so I can do some validation
    if action == "hash":
        return hash_password(password_plaintext)
    elif action == "verify":
        return verify_password(password_plaintext, password_hashed)
    else:
        response = Response()
        response.error_message = "Invalid action."
        return response.jsonify()


# Just some basic tests to see how this all works
# First generate a new password_hash string
hash_password_result = handle_work("hash", "password")
print(hash_password_result)
# The response is in JSON so we need to grab that password from the JSON object
hashedPassword = json.loads(hash_password_result)['data']['hashedPassword']

# Now we call the verify function and the response should return true since we're passing in the same password.
print(handle_work("verify", "password", hashedPassword))


