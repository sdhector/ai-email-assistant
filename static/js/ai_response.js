// JavaScript for AI Response Screen
console.log("AI Response JS loaded.");

// Store current email details
let currentEmail = null;

document.addEventListener('DOMContentLoaded', () => {
    fetchEmails();

    const approveButton = document.getElementById('approve-button');
    approveButton.addEventListener('click', sendApprovedEmail);

    const deleteButton = document.getElementById('delete-button'); // Get delete button
    deleteButton.addEventListener('click', deleteSelectedEmail); // Add listener

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
    const emailHeaderDiv = document.getElementById('selected-email-header');
    emailHeaderDiv.innerHTML = 'Loading content...'; // Clear and show loading in header

    document.getElementById('ai-response-area').value = 'Generating AI response...';
    document.getElementById('chatbot-history').innerHTML = ''; // Clear history
    currentEmail = null; // Reset current email

    const htmlDisplayFrame = document.getElementById('email-html-display');
    const plainDisplayPre = document.getElementById('email-plain-display');
    htmlDisplayFrame.srcdoc = ''; // Clear iframe
    htmlDisplayFrame.style.display = 'none';
    plainDisplayPre.textContent = ''; // Clear pre
    plainDisplayPre.style.display = 'none';
    
    let toggleButton = document.getElementById('toggle-email-view');
    const emailContentContainer = document.getElementById('email-content-view'); // Parent of iframe/pre

    if (!toggleButton) {
        toggleButton = document.createElement('button');
        toggleButton.id = 'toggle-email-view';
        // Insert it before the email-content-view div
        emailContentContainer.parentNode.insertBefore(toggleButton, emailContentContainer);
        toggleButton.addEventListener('click', toggleEmailDisplay);
    }
    toggleButton.textContent = 'Show Raw Text'; // Reset button text
    toggleButton.style.display = 'none'; // Hide initially

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
            
            // Display From/Subject in the new header div
            emailHeaderDiv.innerHTML = `<strong>From:</strong> ${escapeHTML(emailData.sender)}<br><strong>Subject:</strong> ${escapeHTML(emailData.subject)}<hr>`;

            const htmlDisplay = document.getElementById('email-html-display');
            const plainDisplay = document.getElementById('email-plain-display');
            const toggleBtn = document.getElementById('toggle-email-view');

            if (emailData.body_html) {
                htmlDisplay.srcdoc = emailData.body_html;
                htmlDisplay.style.display = 'block';
                plainDisplay.style.display = 'none';
                // Store plain text for toggle, even if not initially shown
                plainDisplay.textContent = emailData.body_plain || 'No plain text version available.'; 
                toggleBtn.textContent = 'Show Raw Text';
                toggleBtn.dataset.currentView = 'html';
                toggleBtn.style.display = 'inline-block';
            } else if (emailData.body_plain) {
                plainDisplay.textContent = emailData.body_plain;
                plainDisplay.style.display = 'block';
                htmlDisplay.style.display = 'none';
                toggleBtn.textContent = 'Show Raw HTML (N/A)';
                toggleBtn.dataset.currentView = 'plain';
                // Show button but indicate no HTML, or hide if preferred
                toggleBtn.style.display = 'inline-block'; 
            } else {
                plainDisplay.textContent = 'No content available.';
                plainDisplay.style.display = 'block';
                htmlDisplay.style.display = 'none';
                toggleBtn.style.display = 'none';
            }

            const contentForAI = emailData.body_plain || emailData.snippet || (emailData.body_html ? "HTML content provided, not shown here." : "");
            getInitialResponse(contentForAI, emailData.subject);
        })
        .catch(error => {
            console.error('Error fetching email content:', error);
            emailHeaderDiv.innerHTML = `<p class="error">Error loading email header: ${error.message}</p>`;
            // Also clear/error message the content display areas
            document.getElementById('email-html-display').style.display = 'none';
            const plainDisplay = document.getElementById('email-plain-display');
            plainDisplay.textContent = `Error loading email content: ${error.message}`;
            plainDisplay.style.display = 'block';
            document.getElementById('ai-response-area').value = 'Error loading email content.';
        });
}

function getInitialResponse(emailBody, emailSubject) {
     fetch('/api/generate_response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
            email_content: emailBody, // This should be the plain text version ideally
            email_subject: emailSubject 
        })
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

    // Use plain text for AI context if available
    const contentForAI = currentEmail.body_plain || currentEmail.snippet || (currentEmail.body_html ? "HTML content provided, not shown here." : "");

     fetch('/api/generate_response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        // Send original email body (plain text), subject, AND the new instructions
        body: JSON.stringify({
            email_content: contentForAI,
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
        clearSelectedEmailView(); // Use the existing function to clear the view
        // document.getElementById('ai-response-area').value = ''; // This is already in clearSelectedEmailView
        // currentEmail = null; // This is already in clearSelectedEmailView
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

function deleteSelectedEmail() {
    if (!currentEmail || !currentEmail.id) {
        alert("Please select an email to delete.");
        return;
    }

    if (!confirm(`Are you sure you want to move the email "${currentEmail.subject}" to trash?`)) {
        return;
    }

    const messageId = currentEmail.id;
    const deleteButton = document.getElementById('delete-button');
    deleteButton.disabled = true;
    deleteButton.textContent = 'Deleting...';

    fetch('/api/delete_email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ id: messageId })
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
        alert(data.message || "Email moved to trash successfully!");
        fetchEmails(); // Refresh the email list
        clearSelectedEmailView(); // Clear out the selected email display areas
    })
    .catch(error => {
        console.error('Error deleting email:', error);
        alert(`Error deleting email: ${error.message}`);
    })
    .finally(() => {
        deleteButton.disabled = false;
        deleteButton.textContent = 'Delete Email';
    });
}

function clearSelectedEmailView() {
    document.getElementById('selected-email-header').innerHTML = '';
    const htmlDisplayFrame = document.getElementById('email-html-display');
    htmlDisplayFrame.srcdoc = '';
    htmlDisplayFrame.style.display = 'none';
    const plainDisplayPre = document.getElementById('email-plain-display');
    plainDisplayPre.textContent = '';
    plainDisplayPre.style.display = 'none';
    document.getElementById('ai-response-area').value = '';
    document.getElementById('chatbot-history').innerHTML = '';
    document.getElementById('chatbot-input').value = '';
    const toggleButton = document.getElementById('toggle-email-view');
    if (toggleButton) {
        toggleButton.style.display = 'none';
    }
    currentEmail = null;
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

function toggleEmailDisplay() {
    const htmlDisplay = document.getElementById('email-html-display');
    const plainDisplay = document.getElementById('email-plain-display');
    const toggleButton = document.getElementById('toggle-email-view');

    if (toggleButton.dataset.currentView === 'html') {
        htmlDisplay.style.display = 'none';
        plainDisplay.style.display = 'block';
        toggleButton.textContent = 'Show Rendered HTML';
        toggleButton.dataset.currentView = 'plain';
    } else {
        // Only switch to HTML if it actually exists (currentEmail.body_html should be checked)
        if (currentEmail && currentEmail.body_html) {
            htmlDisplay.style.display = 'block';
            plainDisplay.style.display = 'none';
            toggleButton.textContent = 'Show Raw Text';
            toggleButton.dataset.currentView = 'html';
        } else {
            // If no HTML, keep showing plain and indicate that
            alert("No HTML version available to display.");
            // Optionally disable the button or change text further
        }
    }
} 