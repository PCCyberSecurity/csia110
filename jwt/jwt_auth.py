import jwt
import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# Example secret key (in real apps, store securely!)
SECRET_KEY = "super-secret-key-12345"

def log(step, message, color=Fore.WHITE, emoji=""):
    print(f"{color}{emoji} {step}: {message}{Style.RESET_ALL}")

def authenticate_user(user_id):
    log("STEP 1", f"Authenticating user '{user_id}'...", Fore.CYAN, "🔐")
    
    # Simulated authentication
    if user_id == "bobs":
        user = {"user_id": user_id}
        log("SUCCESS", f"User '{user_id}' authenticated!", Fore.GREEN, "✅")
        return user
    else:
        log("FAIL", "Authentication failed!", Fore.RED, "❌")
        return None

def generate_jwt(user):
    log("STEP 2", "Generating JWT token...", Fore.CYAN, "🛠️")
    
    payload = {
        "sub": user["user_id"],
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5),
        "groups": "admin,student"
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    
    log("TOKEN", f"{token}", Fore.YELLOW, "🎟️")
    return token

def verify_jwt(token):
    log("STEP 3", "Verifying JWT token...", Fore.CYAN, "🔍")
    
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        log("VALID", f"Token is valid! Payload: {decoded}", Fore.GREEN, "✅")
    except jwt.ExpiredSignatureError:
        log("ERROR", "Token expired!", Fore.RED, "⏰")
    except jwt.InvalidTokenError:
        log("ERROR", "Invalid token!", Fore.RED, "❌")

# ---- Run the flow ----
user_id = "bobs"

user = authenticate_user(user_id)

if user:
    token = generate_jwt(user)
    verify_jwt(token)