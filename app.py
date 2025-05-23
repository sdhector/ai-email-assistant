import os
import pickle
import base64
import json
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
import google.generativeai as genai
from dotenv import load_dotenv
import datetime # For timestamping

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort

# Attempt to import Google Secret Manager client
try:
    from google.cloud import secretmanager
    print("Google Secret Manager client imported successfully.")
except ImportError:
    secretmanager = None
    print("Google Secret Manager client not available. Ensure 'google-cloud-secret-manager' is installed.")

# Import Firestore client
try:
    from google.cloud import firestore
    print("Google Cloud Firestore client imported successfully.")
    firestore_available = True
except ImportError:
    firestore = None # Ensure firestore is None if import fails. Will be used by linters.
    firestore_available = False
    print("Google Cloud Firestore client not available. Firestore caching will be disabled or use local fallback.")

# --- App Initialization & Configuration Loading ---
app = Flask(__name__)

# Load environment variables from .env file first. 
# These can serve as fallbacks or for non-sensitive configs.
load_dotenv()
print("Loaded .env file (if present).")

# Initialize Firestore DB client
db = None
FIRESTORE_DATABASE_NAME = os.getenv('FIRESTORE_DATABASE_ID') # e.g., 'emails-db' or None for default

if firestore_available:
    try:
        if FIRESTORE_DATABASE_NAME:
            db = firestore.Client(database=FIRESTORE_DATABASE_NAME)
            print(f"Firestore client initialized successfully for database: '{FIRESTORE_DATABASE_NAME}'.")
        else:
            db = firestore.Client() # Connect to (default) database
            print("Firestore client initialized successfully for (default) database.")
    except Exception as e:
        print(f"Error initializing Firestore client (database: '{FIRESTORE_DATABASE_NAME if FIRESTORE_DATABASE_NAME else '(default)'}'): {e}. Firestore caching will be disabled or use local fallback.")
        db = None # Ensure db is None if client init fails
        firestore_available = False # Mark as not available
else:
    print("Firestore client not imported, Firestore features disabled or use local fallback.")

# --- Local Cache Configuration (only for fallback) ---
LOCAL_CACHE_DIR = ".local_cache"
if not os.path.exists(LOCAL_CACHE_DIR):
    try:
        os.makedirs(LOCAL_CACHE_DIR)
        print(f"Created local cache directory: {LOCAL_CACHE_DIR}")
    except OSError as e:
        print(f"Error creating local cache directory {LOCAL_CACHE_DIR}: {e}. Local file caching may fail.")

def is_local_development():
    """Checks if the app is running in a local development environment."""
    # FLASK_DEBUG is set to '1' by `flask run --debug`
    # FLASK_ENV is deprecated but often used.
    return app.debug or os.getenv('FLASK_ENV') == 'development' or os.getenv('FLASK_DEBUG') == '1'

# Function to access secrets from Google Secret Manager
def access_secret_version(project_id, secret_id, version_id="latest"):
    if not secretmanager:
        print(f"Secret Manager client not available. Cannot fetch secret: {secret_id}")
        return None
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        print(f"Attempting to access secret: {name}")
        response = client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8")
        print(f"Successfully accessed secret: {secret_id}")
        return secret_value
    except Exception as e:
        print(f"Error accessing secret {secret_id} from Secret Manager (project: {project_id}): {e}")
        return None

# Configure Flask secret key and Gemini API key, prioritizing Secret Manager
flask_secret_key_val = None
gemini_api_key_val = None
oauth_credentials_json_str = None

# Project ID where secrets are stored
SECRETS_PROJECT_ID = "872125090800" 
FLASK_SECRET_ID = "FLASK_APP_SECRET_KEY"
GEMINI_SECRET_ID = "GEMINI_API_KEY"
OAUTH_CREDENTIALS_SECRET_ID = "ai-email-assistant-credentials" # New secret ID

print(f"Attempting to load secrets from Secret Manager (Project ID: {SECRETS_PROJECT_ID})...")
flask_secret_key_val = access_secret_version(SECRETS_PROJECT_ID, FLASK_SECRET_ID)
gemini_api_key_val = access_secret_version(SECRETS_PROJECT_ID, GEMINI_SECRET_ID)
oauth_credentials_json_str = access_secret_version(SECRETS_PROJECT_ID, OAUTH_CREDENTIALS_SECRET_ID) # Fetch the new secret

# Fallback to .env if Secret Manager failed or values are None
if not flask_secret_key_val:
    print(f"Could not load {FLASK_SECRET_ID} from Secret Manager. Attempting to load from .env or environment variables.")
    flask_secret_key_val = os.getenv('FLASK_SECRET_KEY')
    if flask_secret_key_val:
        print(f"Loaded {FLASK_SECRET_ID} from .env or environment variables.")
    else:
        print(f"CRITICAL ERROR: {FLASK_SECRET_ID} not found in Secret Manager or .env. Sessions will not work.")

if not gemini_api_key_val:
    print(f"Could not load {GEMINI_SECRET_ID} from Secret Manager. Attempting to load from .env or environment variables.")
    gemini_api_key_val = os.getenv('GEMINI_API_KEY')
    if gemini_api_key_val:
        print(f"Loaded {GEMINI_SECRET_ID} from .env or environment variables.")
    else:
        print(f"Warning: {GEMINI_SECRET_ID} not found in Secret Manager or .env. AI features may be disabled.")

if not oauth_credentials_json_str:
    print(f"Could not load {OAUTH_CREDENTIALS_SECRET_ID} from Secret Manager. Will try local credentials.json if present for OAuth flow.")
else:
    print(f"Successfully loaded {OAUTH_CREDENTIALS_SECRET_ID} from Secret Manager.")

app.secret_key = flask_secret_key_val

# --- Gemini AI Setup ---
gemini_model = None
if gemini_api_key_val:
    try:
        genai.configure(api_key=gemini_api_key_val)
        gemini_model = genai.GenerativeModel('gemini-1.5-flash') 
        print("Gemini AI configured successfully.")
    except Exception as e:
        print(f"Error configuring Gemini AI with API key: {e}")
else:
    print("Gemini API key not available. AI features may be limited or disabled.")


# --- Gmail API Setup ---
# Update scopes to include the ones Google automatically adds (OIDC scopes)
# and the gmail.modify scope for full email management including trashing.
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly', 
    'https://www.googleapis.com/auth/gmail.send',
    'https://www.googleapis.com/auth/gmail.modify', # Added for trashing and other modifications
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]
CREDENTIALS_FILE = 'credentials.json'
# Redirect URI is now primarily controlled by app.yaml for GAE, 
# but .env can override for local if GOOGLE_REDIRECT_URI is set there.
REDIRECT_URI = os.getenv('GOOGLE_REDIRECT_URI', 'http://127.0.0.1:5000/oauth2callback')

def get_google_flow():
    """Creates a Google OAuth Flow object for web application flow."""
    global oauth_credentials_json_str # Access the globally loaded secret string

    flow_config = None
    if oauth_credentials_json_str:
        try:
            # Attempt to load config from the fetched JSON string
            client_config = json.loads(oauth_credentials_json_str)
            # Ensure the config is in the expected format (e.g., contains 'web' or 'installed' key)
            if 'web' in client_config or 'installed' in client_config: # Common top-level keys in client secrets
                flow_config = client_config
                print(f"Successfully parsed OAuth client config from Secret Manager for {OAUTH_CREDENTIALS_SECRET_ID}.")
            else:
                print(f"Warning: OAuth client config from Secret Manager ({OAUTH_CREDENTIALS_SECRET_ID}) does not have expected structure ('web' or 'installed' key missing). Will try local file.")
        except json.JSONDecodeError as jde:
            print(f"Error decoding JSON from {OAUTH_CREDENTIALS_SECRET_ID} in Secret Manager: {jde}. Will try local file.")
        except Exception as e:
            print(f"Unexpected error processing OAuth config from Secret Manager ({OAUTH_CREDENTIALS_SECRET_ID}): {e}. Will try local file.")

    if flow_config:
        try:
            flow = Flow.from_client_config(
                flow_config, # Use the parsed config
                scopes=SCOPES,
                redirect_uri=REDIRECT_URI
            )
            print("OAuth flow created using configuration from Secret Manager.")
            return flow
        except Exception as e:
            print(f"ERROR: Failed to create OAuth flow from Secret Manager config: {e}. Will try local file.")


    # Fallback to local credentials.json file if secret not loaded, invalid, or flow creation failed
    print(f"Attempting to create OAuth flow from local file: {CREDENTIALS_FILE}")
    if not os.path.exists(CREDENTIALS_FILE):
        print(f"ERROR: Credentials file {CREDENTIALS_FILE} not found. And no valid config from Secret Manager.")
        raise FileNotFoundError(f"Credentials file not found: {CREDENTIALS_FILE}, and Secret Manager config was not available or failed.")
    try:
        # Load client secrets for web flow
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE, 
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
        print("OAuth flow created using local credentials.json file.")
        return flow
    except ValueError as ve:
        print(f"ERROR: Invalid JSON format or structure in {CREDENTIALS_FILE}. {ve}")
        raise ValueError(f"Invalid JSON in {CREDENTIALS_FILE}") from ve
    except KeyError as ke:
        print(f"ERROR: Missing key {ke} in {CREDENTIALS_FILE}. Ensure it's a valid OAuth Client ID JSON for a WEB application (e.g., contains 'web').")
        raise KeyError(f"Missing key {ke} in {CREDENTIALS_FILE}") from ke
    except Exception as e:
        print(f"ERROR: Unexpected error creating OAuth flow from {CREDENTIALS_FILE}: {e}")
        raise

@app.route('/authorize')
def authorize():
    """Initiates the OAuth 2.0 authorization flow."""
    try:
        flow = get_google_flow()
        # Generate the authorization URL with state for CSRF protection
        authorization_url, state = flow.authorization_url(
            access_type='offline', # Request refresh token
            include_granted_scopes='true',
            prompt='consent'  # Force the consent screen to ensure refresh token issuance
        )
        # Store the state in the session so we can verify it in the callback
        session['oauth_state'] = state
        print(f"Redirecting user to: {authorization_url}")
        return redirect(authorization_url)
    except Exception as e:
        print(f"Error during authorization initiation: {e}")
        return f"Failed to start authorization: {e}", 500

@app.route('/oauth2callback')
def oauth2callback():
    """Handles the redirect from Google after user authorization."""
    state = session.get('oauth_state')
    if not state or state != request.args.get('state'):
        print("Error: State mismatch. Aborting.")
        abort(400, description="State mismatch.")
    try:
        flow = get_google_flow()
        flow.fetch_token(authorization_response=request.url)
        creds = flow.credentials
        
        creds_dict = {
            'token': creds.token, 'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri, 'client_id': creds.client_id,
            'client_secret': creds.client_secret, 'scopes': creds.scopes
        }

        user_id = None
        user_email = None

        # Try to get user info from id_token (preferred)
        # The id_token might be a string JWT or an already-parsed dict by the oauth lib
        parsed_id_token = None
        if hasattr(creds, 'id_token_jwt') and creds.id_token_jwt: # Google library might provide this pre-parsed
             parsed_id_token = creds.id_token_jwt
        elif hasattr(creds, 'id_token') and isinstance(creds.id_token, dict): # Or it might be in creds.id_token as a dict
            parsed_id_token = creds.id_token
        elif hasattr(creds, 'id_token') and isinstance(creds.id_token, str):
            # If it's a string, it's a JWT that needs parsing. 
            # For simplicity here, we'll rely on the library having parsed it or use userinfo endpoint.
            # Decoding JWTs manually requires a library like PyJWT and Google's public keys.
            print("id_token is a string JWT. Will attempt userinfo endpoint if direct parsing fails.")
            # If you have PyJWT and want to decode: 
            # try: import jwt; decoded_token = jwt.decode(creds.id_token, options={"verify_signature": False}); # Insecure for prod
            # except Exception as e_jwt: print(f"JWT decode error: {e_jwt}")

        if parsed_id_token:
            user_id = parsed_id_token.get('sub')
            user_email = parsed_id_token.get('email')
            print(f"User info from parsed id_token: ID={user_id}, Email={user_email}")

        # Fallback or to augment: Use userinfo endpoint if scopes allow (openid, userinfo.email, userinfo.profile)
        if not user_id or not user_email:
            print("User ID or email not found in id_token, trying userinfo endpoint...")
            try:
                # Build a temporary service with the new credentials to call userinfo
                userinfo_service = build('oauth2', 'v2', credentials=creds)
                user_info = userinfo_service.userinfo().get().execute()
                if not user_id and user_info.get('id'): # Google's userinfo endpoint returns 'id' for 'sub'
                    user_id = user_info.get('id')
                    print(f"User ID from userinfo endpoint: {user_id}")
                if not user_email and user_info.get('email'):
                    user_email = user_info.get('email')
                    print(f"User email from userinfo endpoint: {user_email}")
            except Exception as e_userinfo:
                print(f"Error fetching from userinfo endpoint: {e_userinfo}")
        
        if user_id:
            creds_dict['user_id'] = user_id
        else:
            print("CRITICAL: User ID could not be obtained. Login will likely fail or loop.")
            # Potentially abort or redirect to an error page if user_id is essential and not found
            # For now, let it proceed and rely on checks in get_credentials_from_session

        if user_email:
            creds_dict['user_email'] = user_email
        
        session['credentials'] = creds_dict
        session.modified = True # Explicitly mark session as modified
        print(f"OAuth callback processed. Session credentials user_id: {session.get('credentials', {}).get('user_id')}")
        
        # Explicitly redirect to index after setting credentials
        return redirect(url_for('index')) 
        
    except Exception as e:
        print(f"Error during OAuth callback: {e}")
        import traceback
        traceback.print_exc()
        return f"Failed to fetch token or store credentials: {e}", 500

def get_credentials_from_session():
    """Retrieves Google credentials from the session and validates scopes."""
    if 'credentials' not in session:
        print("No credentials in session.")
        return None
    
    creds_dict = session['credentials']
    
    # Ensure user_id is present, crucial for Firestore caching.
    # If not present (e.g., old session before user_id was added), clear session to force re-auth.
    if 'user_id' not in creds_dict:
        print("CRITICAL: 'user_id' not found in session credentials. Clearing to force re-auth for Firestore.")
        session.pop('credentials', None)
        session.pop('oauth_state', None)
        return None
        
    session_scopes = creds_dict.get('scopes', [])
    if not all(s in SCOPES for s in SCOPES): # Check against the global SCOPES
        print("Scope mismatch or missing scopes in session credentials. Clearing to force re-auth.")
        session.pop('credentials', None)
        session.pop('oauth_state', None) 
        return None
        
    if not creds_dict.get('refresh_token'):
         print("CRITICAL: No refresh token found in session credentials. Clearing to force re-auth.")
         session.pop('credentials', None)
         session.pop('oauth_state', None)
         return None

    # Remove user_id and user_email before creating Credentials object as they are not part of its constructor
    # but keep them in the session for our app's use.
    creds_init_dict = {k: v for k, v in creds_dict.items() if k not in ['user_id', 'user_email']}
    return Credentials(**creds_init_dict)

def get_user_id_from_session():
    """Helper to get user_id from session, returns None if not found."""
    if 'credentials' in session and 'user_id' in session['credentials']:
        return session['credentials']['user_id']
    print("User ID not found in session.")
    return None

def get_gmail_service():
    """Builds the Gmail service object using credentials from the session."""
    creds = get_credentials_from_session() 
    if not creds: 
        print("No valid credentials (or refresh token/user_id missing) in session. Re-authentication required.")
        return None 

    try:
        if creds.expired: 
            print("Credentials expired, attempting refresh...")
            try:
                creds.refresh(Request())
                # Update session credentials after refresh, preserving user_id and user_email
                session_creds = session.get('credentials', {}) # Get current session creds
                session_creds.update({
                    'token': creds.token,
                    'refresh_token': creds.refresh_token, # Refresh token might be updated
                    'token_uri': creds.token_uri,
                    'client_id': creds.client_id,
                    'client_secret': creds.client_secret,
                    'scopes': creds.scopes
                })
                session['credentials'] = session_creds # Save back to session
                print("Credentials refreshed successfully.")
            except Exception as e:
                print(f"Error refreshing credentials: {e}. Clearing session credentials to force re-auth.")
                session.pop('credentials', None)
                session.pop('oauth_state', None) 
                return None 

        service = build('gmail', 'v1', credentials=creds)
        print("Gmail service created successfully using session credentials.")
        return service
    except HttpError as error:
        print(f'An HTTP error occurred building the Gmail service: {error}')
        if error.resp.status in [401, 403]:
             print("Authentication error encountered. Clearing session credentials.")
             session.pop('credentials', None)
        return None
    except Exception as e:
        print(f'An unexpected error occurred building the Gmail service: {e}')
        return None


# --- Flask Routes ---

@app.route('/')
def index():
    # Check if user is authenticated before rendering main page
    if 'credentials' not in session or 'user_id' not in session.get('credentials', {}):
        print("User not authenticated or user_id missing, redirecting to /authorize or login page")
        return render_template('login.html') 
    
    return render_template('ai_response_screen.html')

# Add a logout route
@app.route('/logout')
def logout():
    session.pop('credentials', None)
    session.pop('oauth_state', None)
    print("User logged out, session cleared.")
    return redirect(url_for('index'))

# Add login page template route (will create template next)
@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/ai-response')
def ai_response_screen():
    if 'credentials' not in session or 'user_id' not in session.get('credentials', {}):
        return redirect(url_for('login_page')) 
    return render_template('ai_response_screen.html')

@app.route('/action-items')
def action_items_screen():
    if 'credentials' not in session or 'user_id' not in session.get('credentials', {}):
         return redirect(url_for('login_page')) 
    return render_template('action_items_screen.html')

@app.route('/knowledge')
def knowledge_screen():
    if 'credentials' not in session or 'user_id' not in session.get('credentials', {}):
         return redirect(url_for('login_page')) 
    return render_template('knowledge_screen.html')

# --- API Routes (Need Authentication Check) ---

@app.route('/api/emails', methods=['GET'])
def get_emails():
    print("--- DEBUG: GET_EMAILS --- START ---")
    print(f"DEBUG: Firestore available flag: {firestore_available}")
    print(f"DEBUG: Firestore db client instance: {db}")
    print(f"DEBUG: Is local development mode: {is_local_development()}")
    
    service = get_gmail_service()
    user_id = get_user_id_from_session()
    print(f"DEBUG: User ID from session: {user_id}")

    if not user_id:
        print("DEBUG: No User ID found in session, returning 401 error.")
        return jsonify({"error": "User ID not found or authentication failed. Please log in again."}), 401
    if not service: 
        print("DEBUG: Gmail service initialization failed, returning 401 error.")
        return jsonify({"error": "Failed to initialize Gmail service. Please log in again."}), 401

    page_token_from_client = request.args.get('pageToken')
    max_results = request.args.get('maxResults', type=int, default=25)
    filter_type = request.args.get('filter_type', 'priority').lower()
    print(f"DEBUG: Request params - filter_type: {filter_type}, page_token: {page_token_from_client}, max_results: {max_results}")
    
    is_gmail_page_token = page_token_from_client and not page_token_from_client.startswith("local_offset_") and not page_token_from_client.isdigit()
    is_local_cache_offset_token = page_token_from_client and page_token_from_client.startswith("local_offset_")

    # 1. Try Firestore Cache
    if db and firestore_available and not is_gmail_page_token: 
        print(f"DEBUG: Attempting Firestore read for user {user_id}, filter: {filter_type}, token: {page_token_from_client}")
        query = db.collection('users').document(user_id).collection('emails')
        if filter_type == 'priority':
            query = query.where('is_user_priority', '==', True)
        elif filter_type == 'other':
            query = query.where('categories', 'array_contains_any', ['promotions', 'social'])
        query = query.order_by('date', direction=firestore.Query.DESCENDING)
        firestore_offset = 0
        if page_token_from_client and page_token_from_client.isdigit(): # Check if it's a Firestore offset token
            try:
                firestore_offset = int(page_token_from_client)
                query = query.offset(firestore_offset)
            except ValueError:
                firestore_offset = 0
        query = query.limit(max_results)
        try:
            docs = query.stream()
            emails_from_cache = [doc.to_dict() for doc in docs]
            if emails_from_cache:
                next_fs_page_token = None
                if len(emails_from_cache) == max_results:
                    next_fs_page_token = str(firestore_offset + max_results)
                print(f"DEBUG: Firestore cache hit: {len(emails_from_cache)} emails. Next token: {next_fs_page_token}")
                return jsonify({"emails": emails_from_cache, "nextPageToken": next_fs_page_token, "source": "firestore_cache"})
            print(f"DEBUG: Firestore cache empty/exhausted for user {user_id}, filter {filter_type}. Will fall through.")
        except Exception as e_fs_read:
            print(f"DEBUG: Error reading from Firestore for user {user_id}: {e_fs_read}. Will fall through.")

    # 2. Try Local File Cache
    if not (db and firestore_available) and is_local_development() and not is_gmail_page_token:
        print(f"DEBUG: Attempting Local Cache read for user {user_id}, filter: {filter_type}, token: {page_token_from_client}")
        emails_from_cache, next_local_token = _read_emails_from_local_cache(user_id, filter_type, max_results, page_token_from_client if is_local_cache_offset_token else None)
        if emails_from_cache:
            print(f"DEBUG: Local cache hit: {len(emails_from_cache)} emails. Next token: {next_local_token}")
            return jsonify({"emails": emails_from_cache, "nextPageToken": next_local_token, "source": "local_cache"})
        print(f"DEBUG: Local cache empty/exhausted for user {user_id}, filter {filter_type}. Will fall through to Gmail.")

    # 3. Fetch from Gmail API (Cache miss, or explicit Gmail token)
    print(f"DEBUG: Fetching from Gmail API: user {user_id}, filter {filter_type}, pageToken: {page_token_from_client if is_gmail_page_token else None}")
    try:
        list_params = {'userId': 'me', 'labelIds': ['INBOX', 'UNREAD'], 'maxResults': max_results}
        if is_gmail_page_token: 
            list_params['pageToken'] = page_token_from_client
        
        gmail_query_parts = []
        if filter_type == 'priority': gmail_query_parts.append("-category:promotions -category:social")
        elif filter_type == 'other': gmail_query_parts.append("(category:promotions OR category:social)")
        else: gmail_query_parts.append("-category:promotions -category:social")
        
        list_params['q'] = " ".join(gmail_query_parts)
        print(f"DEBUG: Gmail API query: {list_params['q']}")

        results = service.users().messages().list(**list_params).execute()
        messages_from_gmail = results.get('messages', [])
        next_gmail_page_token = results.get('nextPageToken')

        if not messages_from_gmail:
            print("DEBUG: Gmail fetch returned no messages.")
            return jsonify({"emails": [], "nextPageToken": None, "source": "gmail_empty"})

        emails_to_return_to_client = []
        emails_for_cache_update = []
        for msg_info in messages_from_gmail:
            msg = service.users().messages().get(userId='me', id=msg_info['id'], format='metadata',
                                               metadataHeaders=['subject', 'from', 'date']).execute()
            headers = msg.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
            sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
            date_str = next((h['value'] for h in headers if h['name'].lower() == 'date'), datetime.datetime.utcnow().isoformat())
            label_ids = msg.get('labelIds', [])
            derived_categories, is_priority = _get_email_categories_and_priority(label_ids)
            email_data = {
                'id': msg_info['id'], 'threadId': msg_info['threadId'],
                'subject': subject, 'sender': sender, 'date': date_str,
                'snippet': msg.get('snippet', ''), 'labelIds': label_ids,
                'categories': derived_categories, 'is_user_priority': is_priority,
                'userId': user_id
            }
            emails_to_return_to_client.append(email_data)
            emails_for_cache_update.append(email_data.copy())

        if db and firestore_available:
            _write_emails_to_firestore(user_id, emails_for_cache_update)
            print(f"DEBUG: Attempted write to Firestore after Gmail fetch for {len(emails_for_cache_update)} emails.")
        elif is_local_development():
            _write_emails_to_local_cache(user_id, emails_for_cache_update)
            print(f"DEBUG: Attempted write to Local Cache after Gmail fetch for {len(emails_for_cache_update)} emails.")
            
        print("DEBUG: Returning data from Gmail fetch.")
        return jsonify({"emails": emails_to_return_to_client, "nextPageToken": next_gmail_page_token, "source": "gmail_fetch"})

    except HttpError as error:
        print(f'DEBUG: Gmail API HttpError in get_emails: {error}')
        if error.resp.status in [401, 403]:
            session.pop('credentials', None)
            return jsonify({"error": f"Authentication error with Gmail: {error.resp.reason}"}), error.resp.status
        return jsonify({"error": f"Gmail API error: {error.resp.reason}"}), error.resp.status
    except Exception as e:
        print(f'DEBUG: Unexpected error in get_emails (Gmail fetch part or general): {e}')
        import traceback; traceback.print_exc()
        return jsonify({"error": "An unexpected server error occurred during email fetching."}), 500

    # Safety net return
    print("DEBUG: Fallback - Reached end of get_emails function without returning. This indicates a logic error.")
    return jsonify({"error": "Server error: Could not process email request due to an unexpected state."}), 500

@app.route('/api/email_content', methods=['GET'])
def get_email_content():
    """Fetches the full content of a specific email."""
    service = get_gmail_service()
    user_id = get_user_id_from_session() # Get user_id for potential cache access

    if not service:
        return jsonify({"error": "Authentication required or failed to get Gmail service."}), 401
    # Not checking user_id here as this endpoint might not need it if always fetching from Gmail
    
    message_id = request.args.get('id')
    if not message_id:
        return jsonify({"error": "Missing message ID"}), 400

    # TODO: Future - Try fetching from Firestore cache first if full body is stored
    # For now, always fetch from Gmail.

    try:
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        payload = msg.get('payload')
        parts = payload.get('parts', [])
        body_html = ""
        body_plain = ""

        if parts: # Multipart email
            for part in parts:
                mime_type = part.get('mimeType')
                data = part.get('body', {}).get('data')
                if data:
                    decoded_data = base64.urlsafe_b64decode(data).decode('utf-8')
                    if mime_type == 'text/plain':
                        body_plain = decoded_data
                    elif mime_type == 'text/html':
                        body_html = decoded_data
            
            if body_html and not body_plain:
                pass 
            elif body_plain and not body_html:
                pass

        elif payload.get('body', {}).get('data'): # Non-multipart email
            data = payload.get('body', {}).get('data')
            content = base64.urlsafe_b64decode(data).decode('utf-8')
            payload_mime_type = payload.get('mimeType', 'text/plain') 
            if payload_mime_type == 'text/html':
                body_html = content
            else: 
                body_plain = content
        
        if not body_html and not body_plain:
            body_plain = msg.get('snippet', '')


        headers = payload.get('headers', [])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')

        email_full_content_data = {
            "id": message_id,
            "subject": subject,
            "sender": sender,
            "body_html": body_html,
            "body_plain": body_plain,
            "snippet": msg.get('snippet', '')
            # "userId": user_id # Could add this if needed later
        }
        
        # TODO: Future - Update Firestore document with full body if caching full content
        # if db and user_id:
        #     try:
        #         doc_ref = db.collection('users').document(user_id).collection('emails').document(message_id)
        #         doc_ref.set({'body_html': body_html, 'body_plain': body_plain, 'retrieved_full_content_at': firestore.SERVER_TIMESTAMP}, merge=True)
        #         print(f"Updated Firestore with full content for email {message_id} for user {user_id}")
        #     except Exception as e_fs_full:
        #         print(f"Error updating Firestore with full email content: {e_fs_full}")

        return jsonify(email_full_content_data)

    except HttpError as error:
        print(f'An error occurred fetching email content: {error}')
        if error.resp.status in [401, 403]:
             session.pop('credentials', None)
             return jsonify({"error": f"Authentication error: {error}"}), 401
        return jsonify({"error": f"Gmail API error: {error}"}), 500
    except Exception as e:
        print(f'An unexpected error occurred fetching email content: {e}')
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route('/api/generate_response', methods=['POST'])
def generate_response():
    # No direct Gmail auth needed here, but check AI model
    if not gemini_model:
         return jsonify({"error": "Gemini AI not configured correctly."}), 500

    email_content = request.json.get('email_content')
    email_subject = request.json.get('email_subject', '') # Optional subject context
    user_instructions = request.json.get('instructions', '') # Instructions from chatbot

    if not email_content:
        return jsonify({"error": "Missing email_content in request"}), 400

    try:
        # TODO: Load knowledge base content here if needed
        knowledge_context = "" # Placeholder
        knowledge_file = os.path.join('knowledge', 'repository.md') 
        if os.path.exists(knowledge_file):
            try:
                with open(knowledge_file, 'r', encoding='utf-8') as f:
                    knowledge_context = f.read()
                print("Loaded knowledge context for prompt.")
            except Exception as e:
                print(f"Warning: Could not read knowledge file {knowledge_file}: {e}")

        # Construct prompt for Gemini
        prompt = f"""You are an AI assistant helping a user respond to emails.
        Read the following email content and generate a draft response.

        Email Subject: {email_subject}
        Email Content:
        ---
        {email_content}
        ---

        User's Instructions for response (if any): {user_instructions}

        Knowledge Base Context (if relevant):
        ---
        {knowledge_context}
        ---

        Generate the response text below:"""

        # Call Gemini API
        response = gemini_model.generate_content(prompt)

        # Handle potential safety blocks or errors from Gemini
        if not response.candidates or not response.candidates[0].content.parts:
             # Attempt to get feedback if available
             safety_feedback = response.prompt_feedback if hasattr(response, 'prompt_feedback') else "No specific feedback available."
             print(f"Gemini response blocked or empty. Feedback: {safety_feedback}")
             return jsonify({"error": "Failed to generate response. Content might be blocked or empty.", "details": str(safety_feedback)}), 500

        generated_text = response.text # Accessing .text directly is simpler for basic generation

        return jsonify({"response": generated_text})

    except Exception as e:
        print(f'An error occurred generating response with Gemini: {e}')
        # Log the full error for debugging
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"AI generation error: {e}"}), 500


@app.route('/api/send_email', methods=['POST'])
def send_email():
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Authentication required or failed to get Gmail service."}), 401

    recipient = request.json.get('recipient')
    subject = request.json.get('subject')
    body = request.json.get('body')
    thread_id = request.json.get('threadId') # Important for replying in the same thread

    if not all([recipient, subject, body]):
        return jsonify({"error": "Missing recipient, subject, or body"}), 400

    try:
        message = MIMEText(body)
        message['to'] = recipient
        # TODO: Set 'from' correctly if needed, usually defaults to authenticated user
        # message['from'] = 'your_email@gmail.com'
        message['subject'] = subject

        # Encode message to base64
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        message_body = {'raw': raw_message}

        # Include threadId if replying
        if thread_id:
            message_body['threadId'] = thread_id

        sent_message = service.users().messages().send(userId='me', body=message_body).execute()
        print(f"Message Id: {sent_message['id']}")
        # TODO: Mark original email as read/replied if desired
        return jsonify({"status": "success", "message": "Email sent successfully.", "id": sent_message['id']})

    except HttpError as error:
        print(f'An error occurred sending email: {error}')
        if error.resp.status in [401, 403]:
             session.pop('credentials', None)
             return jsonify({"error": f"Authentication error: {error}"}), 401
        return jsonify({"error": f"Gmail API error: {error}"}), 500
    except Exception as e:
        print(f'An unexpected error occurred sending email: {e}')
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route('/api/delete_email', methods=['POST'])
def delete_email_route(): # Renamed to avoid conflict with any potential local 'delete_email' function
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Authentication required or failed to get Gmail service."}), 401

    message_id = request.json.get('id')
    if not message_id:
        return jsonify({"error": "Missing message ID"}), 400

    try:
        # Moves the specified message to the trash.
        service.users().messages().trash(userId='me', id=message_id).execute()
        print(f"Message with ID: {message_id} moved to trash.")
        # Optional: Mark as deleted or remove from Firestore cache
        user_id = get_user_id_from_session()
        if db and firestore_available and message_id:
            try:
                doc_ref = db.collection('users').document(user_id).collection('emails').document(message_id)
                doc_ref.delete() # Or update with a 'deleted_at' timestamp
                print(f"Deleted email {message_id} from Firestore cache for user {user_id}.")
            except Exception as e_fs_del:
                print(f"Error deleting email {message_id} from Firestore: {e_fs_del}")

        return jsonify({"status": "success", "message": f"Email {message_id} moved to trash."})
    except HttpError as error:
        print(f'An error occurred trashing email {message_id}: {error}')
        if error.resp.status in [401, 403]:
            session.pop('credentials', None)
            return jsonify({"error": f"Authentication error: {error}"}), 401
        return jsonify({"error": f"Gmail API error: {error}"}), 500
    except Exception as e:
        print(f'An unexpected error occurred trashing email {message_id}: {e}')
        return jsonify({"error": "An unexpected error occurred while trashing email"}), 500


@app.route('/api/action_items', methods=['GET'])
def get_action_items():
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Authentication required or failed to get Gmail service."}), 401
    if not gemini_model:
         return jsonify({"error": "Gemini AI not configured correctly."}), 500

    try:
        # 1. Fetch recent/unread emails
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q='is:unread', maxResults=20).execute() 
        messages_info = results.get('messages', [])

        if not messages_info:
            return jsonify([]) 

        emails_data = []
        print(f"Fetching content for {len(messages_info)} emails to find action items...")
        for msg_info in messages_info:
             msg = service.users().messages().get(userId='me', id=msg_info['id'], format='full').execute()
             payload = msg.get('payload')
             subject = next((h['value'] for h in payload.get('headers', []) if h['name'].lower() == 'subject'), 'No Subject')
             body = ""
             parts = payload.get('parts', [])
             if parts:
                 for part in parts:
                     if part.get('mimeType') == 'text/plain':
                         data = part.get('body', {}).get('data')
                         if data: body = base64.urlsafe_b64decode(data).decode('utf-8'); break
             elif payload.get('body', {}).get('data'):
                 data = payload.get('body', {}).get('data')
                 body = base64.urlsafe_b64decode(data).decode('utf-8')

             if body or msg.get('snippet'):
                emails_data.append({
                    "id": msg_info['id'],
                    "subject": subject,
                    "content": body or msg.get('snippet', '') 
                })

        if not emails_data:
             return jsonify([])

        # 2. Prepare prompt for Gemini
        knowledge_context = "" 
        knowledge_file = os.path.join('knowledge', 'repository.md') 
        if os.path.exists(knowledge_file):
            try:
                with open(knowledge_file, 'r', encoding='utf-8') as f:
                    knowledge_context = f.read()
                print("Loaded knowledge context for action items.")
            except Exception as e:
                print(f"Warning: Could not read knowledge file {knowledge_file}: {e}")

        emails_text_block = "\n\n---\n\n".join([f"Email ID: {e['id']}\nSubject: {e['subject']}\nContent:\n{e['content'][:1000]}..." 
                                                  for e in emails_data])

        prompt = f"""You are an AI assistant tasked with identifying actionable items from a list of emails.
        Analyze the following email contents and extract any clear tasks, deadlines, or requests for the user.
        Ignore general information or conversations unless they contain a specific action required from the user.
        When you identify an action item, you MUST prefix it with the exact Email ID it refers to, like this: '[EmailID: <original_email_id_here>] Action: [Description of action]'.
        If an email contains no action items, ignore it.

        Knowledge Base Context (if relevant):
        ---
        {knowledge_context}
        ---

        Emails:
        ---
        {emails_text_block}
        ---

        List the action items below, one per line. For example:
        [EmailID: 18f5b1d6a3b4c0a0] Action: Follow up with John Doe about the report deadline.
        [EmailID: 18f5b1d6a3b4c0a1] Action: Prepare slides for Tuesday's presentation.

        If no action items are found in any email, respond with "No action items found." """

        # 3. Call Gemini API
        response = gemini_model.generate_content(prompt)

        if not response.candidates or not response.candidates[0].content.parts:
             safety_feedback = response.prompt_feedback if hasattr(response, 'prompt_feedback') else "No specific feedback available."
             print(f"Gemini action item response blocked or empty. Feedback: {safety_feedback}")
             return jsonify({"error": "Failed to extract action items. Content might be blocked or empty.", "details": str(safety_feedback)}), 500

        action_items_text = response.text
        print(f"Gemini raw action items output:\n{action_items_text}") # Log Gemini's raw output

        # 4. Parse the response
        import re # Import re for parsing
        action_items_list = []
        if action_items_text.strip() and "no action items found" not in action_items_text.lower():
            lines = action_items_text.strip().split('\n')
            for line in lines:
                line = line.strip()
                # Regex to capture EmailID and the action description
                match = re.match(r'^\[EmailID:\s*([\w\d]+)\]\s*Action:\s*(.+)$', line, re.IGNORECASE)
                if match:
                    email_id = match.group(1)
                    action_desc = match.group(2).strip()
                    
                    # Find the subject for this email_id from our original emails_data list for better context
                    original_email_subject = "Unknown Subject"
                    for email_detail in emails_data:
                        if email_detail['id'] == email_id:
                            original_email_subject = email_detail['subject']
                            break
                            
                    action_items_list.append({
                        "email_id": email_id,
                        "action": action_desc,
                        "source_subject": original_email_subject # Add subject for context
                    })
                elif line: # Log lines that didn't match the expected format for debugging
                    print(f"Skipping non-matching line for action item: {line}")
                    
        return jsonify(action_items_list)

    except HttpError as error:
        print(f'An error occurred fetching action items (Gmail): {error}')
        if error.resp.status in [401, 403]:
             session.pop('credentials', None)
             return jsonify({"error": f"Authentication error: {error}"}), 401
        return jsonify({"error": f"Gmail API error: {error}"}), 500
    except Exception as e:
        print(f'An error occurred processing action items: {e}')
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Error processing action items: {e}"}), 500


@app.route('/api/knowledge', methods=['GET', 'POST'])
def manage_knowledge():
    # Knowledge API doesn't strictly need Gmail auth, but maybe useful to protect?
    # For now, leaving it open, but consider adding session check if needed.
    
    # TODO: Implement loading/saving knowledge repository data from .md files
    knowledge_dir = 'knowledge'
    knowledge_file = os.path.join(knowledge_dir, 'repository.md') 

    if not os.path.exists(knowledge_dir):
        os.makedirs(knowledge_dir)

    if request.method == 'GET':
        try:
            if os.path.exists(knowledge_file):
                with open(knowledge_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                return jsonify({"info": content})
            else:
                return jsonify({"info": ""}) 
        except Exception as e:
            print(f"Error reading knowledge file: {e}")
            return jsonify({"error": "Could not read knowledge file"}), 500

    elif request.method == 'POST':
        try:
            new_knowledge = request.json.get('data')
            if new_knowledge is None: 
                 return jsonify({"error": "Missing 'data' in request body"}), 400

            with open(knowledge_file, 'w', encoding='utf-8') as f:
                f.write(new_knowledge)
            return jsonify({"status": "success", "message": "Knowledge updated successfully."}), 200
        except Exception as e:
            print(f"Error writing knowledge file: {e}")
            return jsonify({"error": "Could not save knowledge file"}), 500


# --- Email Data Handling Helpers ---
def _get_email_categories_and_priority(label_ids):
    categories = []
    is_priority = True
    if 'CATEGORY_PROMOTIONS' in label_ids: categories.append('promotions'); is_priority = False
    if 'CATEGORY_SOCIAL' in label_ids: categories.append('social'); is_priority = False
    if 'CATEGORY_UPDATES' in label_ids: categories.append('updates')
    if 'CATEGORY_FORUMS' in label_ids: categories.append('forums')
    return categories, is_priority

def _write_emails_to_firestore(user_id, emails_data_list):
    if not db or not firestore_available or not emails_data_list:
        if not emails_data_list: print("DEBUG H_FS_WRITE: No email data provided."); return
        print("DEBUG H_FS_WRITE: Firestore not available/configured or no data."); return
    batch = db.batch()
    print(f"DEBUG H_FS_WRITE: Batching {len(emails_data_list)} emails for Firestore (user {user_id}).")
    for email_data in emails_data_list:
        doc_ref = db.collection('users').document(user_id).collection('emails').document(email_data['id'])
        email_to_write = email_data.copy()
        email_to_write['fetched_timestamp'] = firestore.SERVER_TIMESTAMP
        if isinstance(email_to_write.get('date'), datetime.datetime):
             email_to_write['date'] = email_to_write['date'].isoformat()
        batch.set(doc_ref, email_to_write, merge=True)
    try:
        batch.commit()
        print(f"DEBUG H_FS_WRITE: Batch commit success for {len(emails_data_list)} emails.")
    except Exception as e:
        print(f"DEBUG H_FS_WRITE: Error batch writing to Firestore: {e}")

def _read_emails_from_local_cache(user_id, filter_type, max_results, page_offset_str=None):
    if not is_local_development(): print("DEBUG H_LC_READ: Not local dev."); return [], None
    cache_file_path = os.path.join(LOCAL_CACHE_DIR, f"{user_id}_emails.json")
    if not os.path.exists(cache_file_path): print(f"DEBUG H_LC_READ: Cache file not found: {cache_file_path}"); return [], None
    page_offset = 0
    if page_offset_str: 
        try: page_offset = int(page_offset_str.replace("local_offset_", ""))
        except ValueError: print(f"DEBUG H_LC_READ: Invalid local offset: {page_offset_str}, using 0."); page_offset = 0
    try:
        with open(cache_file_path, 'r', encoding='utf-8') as f: all_cached_emails = json.load(f)
        print(f"DEBUG H_LC_READ: Loaded {len(all_cached_emails)} emails from {cache_file_path}")
    except Exception as e: print(f"DEBUG H_LC_READ: Error reading {cache_file_path}: {e}"); return [], None
    all_cached_emails.sort(key=lambda x: x.get('date', ''), reverse=True)
    filtered_results = []
    for email in all_cached_emails:
        is_priority_email = email.get('is_user_priority', False)
        email_cats = email.get('categories', [])
        if filter_type == 'priority' and is_priority_email: filtered_results.append(email)
        elif filter_type == 'other' and not is_priority_email and any(cat in email_cats for cat in ['promotions', 'social']):
            filtered_results.append(email)
    start_idx, end_idx = page_offset, page_offset + max_results
    paginated_emails = filtered_results[start_idx:end_idx]
    next_page_token = f"local_offset_{end_idx}" if end_idx < len(filtered_results) else None
    print(f"DEBUG H_LC_READ: Returning {len(paginated_emails)} filtered emails. Next token: {next_page_token}")
    return paginated_emails, next_page_token

def _write_emails_to_local_cache(user_id, new_emails_data_list):
    if not is_local_development() or not new_emails_data_list:
        if not new_emails_data_list: print("DEBUG H_LC_WRITE: No new email data.")
        else: print("DEBUG H_LC_WRITE: Not local dev.")
        return
    cache_file_path = os.path.join(LOCAL_CACHE_DIR, f"{user_id}_emails.json")
    print(f"DEBUG H_LC_WRITE: Writing to local cache: {cache_file_path}")
    existing_emails_map = {}
    if os.path.exists(cache_file_path):
        try:
            with open(cache_file_path, 'r', encoding='utf-8') as f: 
                existing_emails_list = json.load(f)
                for email in existing_emails_list: existing_emails_map[email['id']] = email
            print(f"DEBUG H_LC_WRITE: Loaded {len(existing_emails_map)} existing emails from local cache.")
        except Exception as e:
            print(f"DEBUG H_LC_WRITE: Error reading existing local cache for update: {e}. Will overwrite.")
            existing_emails_map = {}
    for email_data in new_emails_data_list:
        email_to_write = email_data.copy()
        ts = email_to_write.get('fetched_timestamp'); date_val = email_to_write.get('date')
        if isinstance(ts, datetime.datetime): email_to_write['fetched_timestamp'] = ts.isoformat()
        elif ts is None: email_to_write['fetched_timestamp'] = datetime.datetime.utcnow().isoformat()
        if isinstance(date_val, datetime.datetime): email_to_write['date'] = date_val.isoformat()
        existing_emails_map[email_data['id']] = email_to_write
    try:
        with open(cache_file_path, 'w', encoding='utf-8') as f:
            json.dump(list(existing_emails_map.values()), f, indent=2)
        print(f"DEBUG H_LC_WRITE: Updated local cache. Total in cache: {len(existing_emails_map)}.")
    except Exception as e:
        print(f"DEBUG H_LC_WRITE: Error writing to local cache: {e}") # Corrected indentation for this line

if __name__ == '__main__':
    # Ensure Redirect URI uses the correct protocol (http for local flask dev server)
    # Important for OAuth flow without HTTPS setup locally
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    
    # Note: Use a proper WSGI server like Gunicorn or Waitress for production
    # Specify host='0.0.0.0' to make accessible on network if needed.
    app.run(host='0.0.0.0', debug=True, port=5000) 