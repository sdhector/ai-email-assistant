import os
import pickle
import base64
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
import google.generativeai as genai
from dotenv import load_dotenv

from flask import Flask, render_template, request, jsonify

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# --- Gmail API Setup ---
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.send']
CREDENTIALS_FILE = 'credentials.json'
TOKEN_PICKLE_FILE = 'token.pickle' # Using pickle for token storage

def get_gmail_service():
    """Shows basic usage of the Gmail API.
    Handles user authentication and returns the Gmail API service object.
    """
    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists(TOKEN_PICKLE_FILE):
        with open(TOKEN_PICKLE_FILE, 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except Exception as e:
                print(f"Error refreshing token: {e}. Need to re-authenticate.")
                # If refresh fails, force re-authentication
                if os.path.exists(TOKEN_PICKLE_FILE):
                    os.remove(TOKEN_PICKLE_FILE)
                flow = InstalledAppFlow.from_client_secrets_file(
                    CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
        else:
            if not os.path.exists(CREDENTIALS_FILE):
                 raise FileNotFoundError(f"Credentials file not found at {CREDENTIALS_FILE}. Please download it from Google Cloud Console.")
            flow = InstalledAppFlow.from_client_secrets_file(
                CREDENTIALS_FILE, SCOPES)
            # Note: run_local_server will open a browser window for auth
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(TOKEN_PICKLE_FILE, 'wb') as token:
            pickle.dump(creds, token)

    try:
        service = build('gmail', 'v1', credentials=creds)
        print("Gmail service created successfully")
        return service
    except HttpError as error:
        print(f'An error occurred building the Gmail service: {error}')
        # Potentially delete token.pickle if auth error persists
        # if error.resp.status in [401, 403]:
        #     if os.path.exists(TOKEN_PICKLE_FILE):
        #         os.remove(TOKEN_PICKLE_FILE)
        #         print("Removed potentially invalid token.pickle. Please restart.")
        return None
    except Exception as e:
        print(f'An unexpected error occurred building the Gmail service: {e}')
        return None


# --- Gemini AI Setup ---
try:
    gemini_api_key = os.getenv('GEMINI_API_KEY')
    if not gemini_api_key:
        print("Warning: GEMINI_API_KEY not found in .env file.")
        # Handle missing key scenario if needed, maybe disable AI features
    else:
        genai.configure(api_key=gemini_api_key)
        # TODO: Select appropriate Gemini model later
        gemini_model = genai.GenerativeModel('gemini-1.5-flash') # Or another suitable model
        print("Gemini AI configured successfully.")
except Exception as e:
    print(f"Error configuring Gemini AI: {e}")
    gemini_model = None # Ensure model is None if setup fails


# --- Flask Routes ---

@app.route('/')
def index():
    # Redirect to AI Response Screen by default for now
    return render_template('ai_response_screen.html')

@app.route('/ai-response')
def ai_response_screen():
    return render_template('ai_response_screen.html')

@app.route('/action-items')
def action_items_screen():
    return render_template('action_items_screen.html')

@app.route('/knowledge')
def knowledge_screen():
    return render_template('knowledge_screen.html')

# --- API Routes ---

@app.route('/api/emails', methods=['GET'])
def get_emails():
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Failed to authenticate or build Gmail service"}), 500

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
        return jsonify({"error": f"Gmail API error: {error}"}), 500
    except Exception as e:
        print(f'An unexpected error occurred fetching emails: {e}')
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route('/api/email_content', methods=['GET'])
def get_email_content():
    """Fetches the full content of a specific email."""
    message_id = request.args.get('id')
    if not message_id:
        return jsonify({"error": "Missing message ID"}), 400

    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Failed to authenticate or build Gmail service"}), 500

    try:
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        payload = msg.get('payload')
        parts = payload.get('parts', [])
        body = ""

        if parts:
            for part in parts:
                if part.get('mimeType') == 'text/plain':
                    data = part.get('body', {}).get('data')
                    if data:
                        body = base64.urlsafe_b64decode(data).decode('utf-8')
                        break # Prefer plain text
            # Fallback if no plain text part found
            if not body and parts[0].get('body', {}).get('data'):
                 data = parts[0].get('body', {}).get('data')
                 body = base64.urlsafe_b64decode(data).decode('utf-8') # Might be HTML

        # Handle cases where body is directly in payload (not multipart)
        elif payload.get('body', {}).get('data'):
             data = payload.get('body', {}).get('data')
             body = base64.urlsafe_b64decode(data).decode('utf-8')

        # Extract headers again for context if needed
        headers = payload.get('headers', [])
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')

        return jsonify({
            "id": message_id,
            "subject": subject,
            "sender": sender,
            "body": body,
            "snippet": msg.get('snippet', '')
        })

    except HttpError as error:
        print(f'An error occurred fetching email content: {error}')
        return jsonify({"error": f"Gmail API error: {error}"}), 500
    except Exception as e:
        print(f'An unexpected error occurred fetching email content: {e}')
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route('/api/generate_response', methods=['POST'])
def generate_response():
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
        return jsonify({"error": "Failed to authenticate or build Gmail service"}), 500

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
        return jsonify({"error": f"Gmail API error: {error}"}), 500
    except Exception as e:
        print(f'An unexpected error occurred sending email: {e}')
        return jsonify({"error": "An unexpected error occurred"}), 500


@app.route('/api/action_items', methods=['GET'])
def get_action_items():
    service = get_gmail_service()
    if not service:
        return jsonify({"error": "Failed to authenticate or build Gmail service"}), 500
    if not gemini_model:
         return jsonify({"error": "Gemini AI not configured correctly."}), 500

    try:
        # 1. Fetch recent/unread emails (similar to get_emails)
        # For action items, might want to look at more than just 10 unread. Adjust query.
        results = service.users().messages().list(userId='me', labelIds=['INBOX'], q='is:unread', maxResults=20).execute() # Example: 20 unread
        messages_info = results.get('messages', [])

        if not messages_info:
            return jsonify([]) # No relevant emails found

        emails_data = []
        print(f"Fetching content for {len(messages_info)} emails to find action items...")
        for msg_info in messages_info:
             # Fetch basic content (snippet might be enough, or fetch full body if needed)
             msg = service.users().messages().get(userId='me', id=msg_info['id'], format='full').execute() # Using full for now
             payload = msg.get('payload')
             subject = next((h['value'] for h in payload.get('headers', []) if h['name'].lower() == 'subject'), 'No Subject')
             body = ""
             parts = payload.get('parts', [])
             if parts:
                 for part in parts:
                     if part.get('mimeType') == 'text/plain':
                         data = part.get('body', {}).get('data')
                         if data: body = base64.urlsafe_b64decode(data).decode('utf-8'); break
             elif payload.get('body', {}).get('data'): # Non-multipart
                 data = payload.get('body', {}).get('data')
                 body = base64.urlsafe_b64decode(data).decode('utf-8')

             if body or msg.get('snippet'): # Only process if there's content
                emails_data.append({
                    "id": msg_info['id'],
                    "subject": subject,
                    "content": body or msg.get('snippet', '') # Prefer full body if available
                })

        if not emails_data:
             return jsonify([])

        # 2. Prepare prompt for Gemini to extract action items from multiple emails
        # TODO: Load knowledge base content here if needed
        knowledge_context = "" # Placeholder

        # Create a single block of text containing relevant parts of emails
        emails_text_block = "\\n\\n---\\n\\n".join([f"Email ID: {e['id']}\\nSubject: {e['subject']}\\nContent:\\n{e['content'][:1000]}..." # Limit length per email
                                                  for e in emails_data])

        prompt = f"""You are an AI assistant tasked with identifying actionable items from a list of emails.
        Analyze the following email contents and extract any clear tasks, deadlines, or requests for the user.
        Ignore general information or conversations unless they contain a specific action required from the user.
        For each action item, state the source email (Subject or ID) and the required action.
        If an email contains no action items, ignore it.

        Knowledge Base Context (if relevant):
        ---
        {knowledge_context}
        ---

        Emails:
        ---
        {emails_text_block}
        ---

        List the action items below, one per line, in the format:
        "Action: [Description of action] (From Email Subject: [Subject] / ID: [ID])"
        If no action items are found in any email, respond with "No action items found." """

        # 3. Call Gemini API
        response = gemini_model.generate_content(prompt)

        if not response.candidates or not response.candidates[0].content.parts:
             safety_feedback = response.prompt_feedback if hasattr(response, 'prompt_feedback') else "No specific feedback available."
             print(f"Gemini action item response blocked or empty. Feedback: {safety_feedback}")
             return jsonify({"error": "Failed to extract action items. Content might be blocked or empty.", "details": str(safety_feedback)}), 500

        action_items_text = response.text

        # 4. Parse the response (simple parsing for now)
        action_items_list = []
        if action_items_text.strip() and "no action items found" not in action_items_text.lower():
            lines = action_items_text.strip().split('\\n')
            for line in lines:
                 if line.strip().lower().startswith("action:"):
                     # Basic extraction, might need refinement based on Gemini's output format consistency
                     action_desc = line.replace("Action:", "").strip()
                     # Try to extract source info if present
                     source_email = "Unknown Source"
                     if "(From Email Subject:" in action_desc:
                         source_email = action_desc[action_desc.find("(From Email Subject:"):]
                         action_desc = action_desc[:action_desc.find("(From Email Subject:")].strip()
                     elif "(ID:" in action_desc:
                          source_email = action_desc[action_desc.find("(ID:"):]
                          action_desc = action_desc[:action_desc.find("(ID:")].strip()

                     action_items_list.append({
                         "action": action_desc,
                         "source": source_email
                         # Potentially add back email_subject/id link if needed
                     })


        # TODO: Replace placeholder with actual AI-extracted items
        # placeholder_items = [
        #     {"email_subject": "Meeting Request", "action": "Confirm attendance by EOD"},
        #     {"email_subject": "Project Update", "action": "Review document and provide feedback"}
        # ]
        # return jsonify(placeholder_items)
        return jsonify(action_items_list)

    except HttpError as error:
        print(f'An error occurred fetching action items (Gmail): {error}')
        return jsonify({"error": f"Gmail API error: {error}"}), 500
    except Exception as e:
        print(f'An error occurred processing action items: {e}')
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Error processing action items: {e}"}), 500


@app.route('/api/knowledge', methods=['GET', 'POST'])
def manage_knowledge():
    # TODO: Implement loading/saving knowledge repository data from .md files
    knowledge_dir = 'knowledge'
    knowledge_file = os.path.join(knowledge_dir, 'repository.md') # Example file name

    if not os.path.exists(knowledge_dir):
        os.makedirs(knowledge_dir)

    if request.method == 'GET':
        try:
            if os.path.exists(knowledge_file):
                with open(knowledge_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                return jsonify({"info": content})
            else:
                return jsonify({"info": ""}) # Return empty if file doesn't exist
        except Exception as e:
            print(f"Error reading knowledge file: {e}")
            return jsonify({"error": "Could not read knowledge file"}), 500

    elif request.method == 'POST':
        try:
            new_knowledge = request.json.get('data')
            if new_knowledge is None: # Check if data is actually present
                 return jsonify({"error": "Missing 'data' in request body"}), 400

            with open(knowledge_file, 'w', encoding='utf-8') as f:
                f.write(new_knowledge)
            return jsonify({"status": "success", "message": "Knowledge updated successfully."}), 200
        except Exception as e:
            print(f"Error writing knowledge file: {e}")
            return jsonify({"error": "Could not save knowledge file"}), 500


if __name__ == '__main__':
    # Ensure Flask runs in debug mode for development
    # Use a proper WSGI server like Gunicorn or Waitress for production
    app.run(debug=True, port=5000) # Specify port if needed 