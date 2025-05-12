from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

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

# Placeholder routes for future features
@app.route('/api/emails', methods=['GET'])
def get_emails():
    # TODO: Implement Gmail API integration to fetch emails
    return jsonify([]) 

@app.route('/api/generate_response', methods=['POST'])
def generate_response():
    # TODO: Implement AI call to generate response based on email content and knowledge
    email_content = request.json.get('email_content')
    # Placeholder response
    return jsonify({"response": f"AI response to: {email_content[:50]}..."})

@app.route('/api/send_email', methods=['POST'])
def send_email():
    # TODO: Implement Gmail API integration to send email
    recipient = request.json.get('recipient')
    subject = request.json.get('subject')
    body = request.json.get('body')
    # Placeholder success message
    return jsonify({"status": "success", "message": "Email sent (simulation)."}), 200

@app.route('/api/action_items', methods=['GET'])
def get_action_items():
    # TODO: Implement logic to read emails, use AI/knowledge to find action items
    # Placeholder action items
    return jsonify([
        {"email_subject": "Meeting Request", "action": "Confirm attendance by EOD"},
        {"email_subject": "Project Update", "action": "Review document and provide feedback"}
    ])

@app.route('/api/knowledge', methods=['GET', 'POST'])
def manage_knowledge():
    # TODO: Implement loading/saving knowledge repository data
    if request.method == 'GET':
        # Placeholder knowledge
        return jsonify({"info": "Current knowledge base content..."})
    elif request.method == 'POST':
        # Placeholder update logic
        new_knowledge = request.json.get('data')
        return jsonify({"status": "success", "message": "Knowledge updated (simulation)."}), 200


if __name__ == '__main__':
    # Note: Use a proper WSGI server for production
    app.run(debug=True) 