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

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort

# Attempt to import Google Secret Manager client
try:
    from google.cloud import secretmanager
except ImportError:
    secretmanager = None # Will be None if not in App Engine or google-cloud-secret-manager not installed

# --- App Initialization & Configuration Loading ---
app = Flask(__name__)

# Load environment variables from .env file for local development
# In App Engine, these will be set by app.yaml or fetched from Secret Manager
load_dotenv()

# Function to access secrets from Google Secret Manager
def access_secret_version(project_id, secret_id, version_id="latest"):
    if not secretmanager:
        print("Secret Manager client not available. Cannot fetch secrets.")
        return None
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8")
    except Exception as e:
        print(f"Error accessing secret {secret_id} from Secret Manager: {e}")
        return None

# Configure Flask secret key and Gemini API key
flask_secret_key_val = None
gemini_api_key_val = None

if os.getenv('GAE_ENV') == 'standard': # Running in App Engine
    print("Running in App Engine environment. Attempting to load secrets from Secret Manager.")
    # Project ID for secrets (replace with your actual project ID where secrets are stored, if different from app's project)
    # Using the project ID you provided: 872125090800
    secrets_project_id = "872125090800" 
    
    flask_secret_key_val = access_secret_version(secrets_project_id, "FLASK_APP_SECRET_KEY")
    gemini_api_key_val = access_secret_version(secrets_project_id, "GEMINI_API_KEY")

    if not flask_secret_key_val:
        print("CRITICAL ERROR: FLASK_APP_SECRET_KEY not found in Secret Manager for App Engine.")
        # Potentially raise an error or exit if this is critical for startup
    if not gemini_api_key_val:
        print("Warning: GEMINI_API_KEY not found in Secret Manager for App Engine.")
        # AI features might be disabled
else: # Local development or other environments
    print("Not in App Engine environment. Loading secrets from .env file.")
    flask_secret_key_val = os.getenv('FLASK_SECRET_KEY')
    gemini_api_key_val = os.getenv('GEMINI_API_KEY')

    if not flask_secret_key_val:
        print("CRITICAL ERROR: FLASK_SECRET_KEY not found in .env file. Sessions will not work.")
    if not gemini_api_key_val:
        print("Warning: GEMINI_API_KEY not found in .env file.")

app.secret_key = flask_secret_key_val

# --- Gemini AI Setup ---
gemini_model = None
if gemini_api_key_val:
    try:
        genai.configure(api_key=gemini_api_key_val)
        gemini_model = genai.GenerativeModel('gemini-1.5-flash') 
        print("Gemini AI configured successfully.")
    except Exception as e:
        print(f"Error configuring Gemini AI with fetched key: {e}")
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
    if not os.path.exists(CREDENTIALS_FILE):
        print(f"ERROR: Credentials file {CREDENTIALS_FILE} not found.")
        raise FileNotFoundError(f"Credentials file not found: {CREDENTIALS_FILE}")
    try:
        # Load client secrets for web flow
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE, 
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI
        )
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
            include_granted_scopes='true'
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
    # Retrieve the state from the session for verification
    state = session.get('oauth_state')
    # Check if state is missing or doesn't match the state parameter from Google
    if not state or state != request.args.get('state'):
        print("Error: State mismatch. Possible CSRF attack.")
        abort(400, description="State mismatch. Please try authorizing again.")

    try:
        flow = get_google_flow()
        # Exchange the authorization code for credentials
        # Use the full URL from the request for fetch_token
        flow.fetch_token(authorization_response=request.url)

        # Store the credentials in the session
        creds = flow.credentials
        # Convert credentials to a dictionary for session storage
        session['credentials'] = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        }
        print("OAuth callback successful, credentials stored in session.")
        # Redirect back to the main application page
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
    
    # Validate if all required SCOPES are present in the session credentials
    # This ensures that if SCOPES are updated, user will be forced to re-authorize
    session_scopes = creds_dict.get('scopes', [])
    if not all(s in session_scopes for s in SCOPES):
        print("Scope mismatch or missing scopes in session credentials. Clearing to force re-auth.")
        session.pop('credentials', None)
        session.pop('oauth_state', None) # Also clear oauth state
        return None
        
    # Important: Check for refresh token existence before assuming it can be refreshed
    if not creds_dict.get('refresh_token'):
         print("Warning: No refresh token found in session credentials. Re-authorization may be needed soon.")
         # Depending on strictness, could clear session here too if refresh token is mandatory

    return Credentials(**creds_dict)

def get_gmail_service():
    """Builds the Gmail service object using credentials from the session."""
    creds = get_credentials_from_session() # This now includes scope validation
    if not creds:
        print("No valid or correctly scoped credentials found in session.")
        return None # Caller needs to handle this (e.g., redirect to /authorize)

    try:
        # Check if credentials need refreshing (and if refresh is possible)
        if creds.expired and creds.refresh_token:
            print("Credentials expired, attempting refresh...")
            try:
                creds.refresh(Request())
                # Update session with refreshed credentials (important!)
                session['credentials'] = {
                    'token': creds.token,
                    'refresh_token': creds.refresh_token,
                    'token_uri': creds.token_uri,
                    'client_id': creds.client_id,
                    'client_secret': creds.client_secret,
                    'scopes': creds.scopes
                }
                print("Credentials refreshed successfully.")
            except Exception as e:
                print(f"Error refreshing credentials: {e}. Clearing session credentials.")
                # Clear invalid credentials from session and force re-auth
                session.pop('credentials', None)
                return None # Indicate refresh failure

        # Build the service
        service = build('gmail', 'v1', credentials=creds)
        print("Gmail service created successfully using session credentials.")
        return service
    except HttpError as error:
        print(f'An HTTP error occurred building the Gmail service: {error}')
        # Handle specific auth errors if needed
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
    if 'credentials' not in session:
        # Optional: Redirect to a simpler login page or render index with login button
        # For now, just redirect to authorize
        print("User not authenticated, redirecting to /authorize")
        # Render a simple login prompt page instead of auto-redirecting
        return render_template('login.html') 
        # return redirect(url_for('authorize'))
    
    # If authenticated, show the main app screen
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
    if 'credentials' not in session:
        return redirect(url_for('login_page')) # Or authorize
    return render_template('ai_response_screen.html')

@app.route('/action-items')
def action_items_screen():
    if 'credentials' not in session:
         return redirect(url_for('login_page')) # Or authorize
    return render_template('action_items_screen.html')

@app.route('/knowledge')
def knowledge_screen():
    if 'credentials' not in session:
         return redirect(url_for('login_page')) # Or authorize
    return render_template('knowledge_screen.html')

# --- API Routes (Need Authentication Check) ---

@app.route('/api/emails', methods=['GET'])
def get_emails():
    service = get_gmail_service() # Will now use session credentials
    if not service:
        # Return 401 if not authenticated or service failed
        return jsonify({"error": "Authentication required or failed to get Gmail service."}), 401 

    try:
        # Fetch N unread emails (or adjust query as needed)
        # Example: 'is:unread in:inbox'
        # Use 'me' for the authenticated user
        results = service.users().messages().list(userId='me', labelIds=['INBOX', 'UNREAD'], maxResults=10).execute()
        messages = results.get('messages', [])

        emails_summary = []
        if not messages:
            print('No unread messages found.')
            return jsonify([])
        else:
            print('Processing messages...')
            for message_info in messages:
                msg = service.users().messages().get(userId='me', id=message_info['id'], format='metadata', metadataHeaders=['subject', 'from', 'date']).execute()
                headers = msg.get('payload', {}).get('headers', [])
                subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
                sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
                date = next((h['value'] for h in headers if h['name'].lower() == 'date'), 'Unknown Date')
                emails_summary.append({
                    'id': message_info['id'],
                    'threadId': message_info['threadId'],
                    'subject': subject,
                    'sender': sender,
                    'date': date,
                    'snippet': msg.get('snippet', '') # Add snippet for context
                })
            return jsonify(emails_summary)

    except HttpError as error:
        print(f'An error occurred fetching emails: {error}')
        # Check if it's an auth error again
        if error.resp.status in [401, 403]:
             session.pop('credentials', None) # Clear session creds on auth error
             return jsonify({"error": f"Authentication error: {error}"}), 401
        return jsonify({"error": f"Gmail API error: {error}"}), 500
    except Exception as e:
        print(f'An unexpected error occurred fetching emails: {e}')
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route('/api/email_content', methods=['GET'])
def get_email_content():
    """Fetches the full content of a specific email."""
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Authentication required or failed to get Gmail service."}), 401
    
    message_id = request.args.get('id')
    if not message_id:
        return jsonify({"error": "Missing message ID"}), 400

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
            
            # If only one type was found, and we prefer HTML, use it for plain if plain is empty
            if body_html and not body_plain:
                # This is a simplification; true conversion from HTML to plain text is complex.
                # For now, if only HTML exists, we'll send it as plain too, or leave plain empty.
                # Consider a library for HTML-to-text if robust plain text is always needed.
                pass # body_plain remains empty or you could assign a stripped version of HTML
            elif body_plain and not body_html:
                # If only plain text exists, we might want to signal that no HTML is available.
                pass

        elif payload.get('body', {}).get('data'): # Non-multipart email
            data = payload.get('body', {}).get('data')
            content = base64.urlsafe_b64decode(data).decode('utf-8')
            # Non-multipart emails might not specify mimeType in the same way,
            # often they are plain text by default or the mimeType is in payload headers
            payload_mime_type = payload.get('mimeType', 'text/plain') # Default to plain
            if payload_mime_type == 'text/html':
                body_html = content
            else: # Includes 'text/plain' and other types we'll treat as plain
                body_plain = content
        
        # Fallback: if both are empty, use snippet as plain text
        if not body_html and not body_plain:
            body_plain = msg.get('snippet', '')


        # Extract headers again for context if needed
        headers = payload.get('headers', [])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')

        return jsonify({
            "id": message_id,
            "subject": subject,
            "sender": sender,
            "body_html": body_html,
            "body_plain": body_plain,
            "snippet": msg.get('snippet', '')
        })

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


if __name__ == '__main__':
    # Ensure Redirect URI uses the correct protocol (http for local flask dev server)
    # Important for OAuth flow without HTTPS setup locally
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    
    # Note: Use a proper WSGI server like Gunicorn or Waitress for production
    # Specify host='0.0.0.0' to make accessible on network if needed.
    app.run(host='0.0.0.0', debug=True, port=5000) 