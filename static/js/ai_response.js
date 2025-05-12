// JavaScript for AI Response Screen
console.log("AI Response JS loaded.");

// Store current email details
let currentEmail = null;

document.addEventListener('DOMContentLoaded', () => {
    fetchEmails();

    const approveButton = document.getElementById('approve-button');
    approveButton.addEventListener('click', sendApprovedEmail);

    const chatbotSubmitButton = document.getElementById('chatbot-submit');
    chatbotSubmitButton.addEventListener('click', getAdjustedResponse);

    // Add listener for Enter key in chatbot input
    const chatbotInput = document.getElementById('chatbot-input');
    chatbotInput.addEventListener('keypress', function(event) {
        if (event.key === 'Enter') {
            event.preventDefault(); // Prevent default form submission
            getAdjustedResponse();
        }
    });
});

function fetchEmails() {
    const emailList = document.getElementById('email-list');
    emailList.innerHTML = '<li>Loading emails...</li>'; // Show loading indicator

    fetch('/api/emails')
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(emails => {
            emailList.innerHTML = ''; // Clear loading/previous list
            if (!emails || emails.length === 0) {
                emailList.innerHTML = '<li>No unread emails found.</li>';
                return;
            }
            emails.forEach(email => {
                const li = document.createElement('li');
                li.textContent = `${email.sender.split('<')[0]} - ${email.subject}`;
                li.dataset.id = email.id; // Store email ID
                li.dataset.threadId = email.threadId; // Store thread ID
                li.addEventListener('click', () => selectEmail(email.id));
                emailList.appendChild(li);
            });
        })
        .catch(error => {
            console.error('Error fetching emails:', error);
            emailList.innerHTML = `<li>Error loading emails: ${error.message}</li>`;
        });
}

function selectEmail(messageId) {
    console.log("Selected email ID:", messageId);
    // Clear previous content
    document.getElementById('selected-email-content').innerHTML = 'Loading content...';
    document.getElementById('ai-response-area').value = 'Generating AI response...';
    document.getElementById('chatbot-history').innerHTML = ''; // Clear history
    currentEmail = null; // Reset current email

    // Highlight selected email (optional)
    document.querySelectorAll('#email-list li').forEach(li => {
        li.classList.remove('selected');
        if (li.dataset.id === messageId) {
            li.classList.add('selected');
        }
    });

    // Fetch full email content
    fetch(`/api/email_content?id=${messageId}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(emailData => {
            currentEmail = emailData; // Store details
            // Display email content (sanitize potentially unsafe HTML if displaying directly)
            const selectedContentDiv = document.getElementById('selected-email-content');
            selectedContentDiv.innerHTML = `
                <strong>From:</strong> ${escapeHTML(emailData.sender)}<br>
                <strong>Subject:</strong> ${escapeHTML(emailData.subject)}<br>
                <hr>
                <pre>${escapeHTML(emailData.body)}</pre>
            `;

            // Fetch initial AI response
            getInitialResponse(emailData.body, emailData.subject);
        })
        .catch(error => {
            console.error('Error fetching email content:', error);
            document.getElementById('selected-email-content').innerHTML = `<p class="error">Error loading email content: ${error.message}</p>`;
            document.getElementById('ai-response-area').value = 'Error loading email content.';
        });
}

function getInitialResponse(emailBody, emailSubject) {
     fetch('/api/generate_response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email_content: emailBody, email_subject: emailSubject })
    })
    .then(response => {
        if (!response.ok) {
            // Try to get error details from JSON response
            return response.json().then(err => { 
                throw new Error(err.error || `HTTP error! status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        document.getElementById('ai-response-area').value = data.response;
    })
    .catch(error => {
        console.error('Error generating AI response:', error);
        document.getElementById('ai-response-area').value = `Error generating response: ${error.message}`;
    });
}

function getAdjustedResponse() {
    if (!currentEmail) {
        alert("Please select an email first.");
        return;
    }

    const instructions = document.getElementById('chatbot-input').value;
    const aiResponseArea = document.getElementById('ai-response-area');
    const currentResponse = aiResponseArea.value;
    const chatbotHistory = document.getElementById('chatbot-history');

    // Add instruction to history (optional)
    const userMsgDiv = document.createElement('div');
    userMsgDiv.textContent = `You: ${instructions}`;
    chatbotHistory.appendChild(userMsgDiv);

    aiResponseArea.value = 'Adjusting response...'; // Indicate loading

     fetch('/api/generate_response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        // Send original email body, subject, AND the new instructions
        body: JSON.stringify({
            email_content: currentEmail.body,
            email_subject: currentEmail.subject,
            instructions: instructions
        })
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { 
                throw new Error(err.error || `HTTP error! status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        aiResponseArea.value = data.response;
        // Add AI response to history (optional)
        const aiMsgDiv = document.createElement('div');
        aiMsgDiv.textContent = `AI: (Response updated)`;
        chatbotHistory.appendChild(aiMsgDiv);
    })
    .catch(error => {
        console.error('Error generating adjusted AI response:', error);
        aiResponseArea.value = `Error adjusting response: ${error.message}`;
        // Add error to history (optional)
        const errorMsgDiv = document.createElement('div');
        errorMsgDiv.textContent = `Error: ${error.message}`;
        errorMsgDiv.classList.add('error');
        chatbotHistory.appendChild(errorMsgDiv);
    })
    .finally(() => {
         document.getElementById('chatbot-input').value = ''; // Clear input
    });
}

function sendApprovedEmail() {
    if (!currentEmail) {
        alert("Please select an email to reply to first.");
        return;
    }

    const recipient = extractEmailAddress(currentEmail.sender);
    if (!recipient) {
        alert("Could not determine recipient email address from sender.");
        return;
    }

    // Prepend "Re:" if not already there
    let subject = currentEmail.subject;
    if (!subject.toLowerCase().startsWith('re:')) {
        subject = `Re: ${subject}`;
    }

    const body = document.getElementById('ai-response-area').value;
    const threadId = currentEmail.threadId; // Use the threadId from the fetched email data

    console.log(`Sending email to: ${recipient}, Subject: ${subject}, Thread: ${threadId}`);

    // Basic confirmation
    if (!confirm(`Send this reply to ${recipient}?\n\nSubject: ${subject}`)) {
        return;
    }

    const approveButton = document.getElementById('approve-button');
    approveButton.disabled = true;
    approveButton.textContent = 'Sending...';

    fetch('/api/send_email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            recipient: recipient,
            subject: subject,
            body: body,
            threadId: threadId // Send threadId to reply correctly
        })
    })
    .then(response => {
         if (!response.ok) {
            return response.json().then(err => { 
                throw new Error(err.error || `HTTP error! status: ${response.status}`);
            });
        }
        return response.json();
    })
    .then(data => {
        alert("Email sent successfully!");
        console.log("Send success:", data);
        // TODO: Optionally remove email from list or mark as read/replied
        fetchEmails(); // Refresh email list as a simple update
        // Clear current selection
        document.getElementById('selected-email-content').innerHTML = '';
        document.getElementById('ai-response-area').value = '';
        currentEmail = null;
    })
    .catch(error => {
        console.error('Error sending email:', error);
        alert(`Error sending email: ${error.message}`);
    })
    .finally(() => {
        approveButton.disabled = false;
        approveButton.textContent = 'Approve & Send';
    });
}

// Helper function to extract email from strings like "Sender Name <email@example.com>"
function extractEmailAddress(senderString) {
    const match = senderString.match(/<([^>]+)>/);
    return match ? match[1] : senderString; // Fallback to using the whole string if no <> found
}

// Basic HTML escaping function
function escapeHTML(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
} 