// JavaScript for Action Items Screen
console.log("Action Items JS loaded.");

let currentSelectedEmailForAction = null; // To store details for toggling view

document.addEventListener('DOMContentLoaded', () => {
    fetchActionItems();
    // Placeholder for a toggle button if we add it later for email view
    const emailViewToggle = document.getElementById('action-item-email-view-toggle');
    if (emailViewToggle) {
        emailViewToggle.addEventListener('click', toggleActionItemEmailDisplay);
    }
});

function fetchActionItems() {
    const listElement = document.getElementById('action-items-ul'); // Target the UL
    const emailPanelPlaceholder = document.getElementById('action-item-email-placeholder');
    listElement.innerHTML = '<li>Loading action items...</li>'; // Show loading indicator
    emailPanelPlaceholder.style.display = 'block'; // Ensure placeholder is visible
    document.getElementById('action-item-email-html-display').style.display = 'none';
    document.getElementById('action-item-email-plain-display').style.display = 'none';
    document.getElementById('action-item-email-header').innerHTML = '';


    fetch('/api/action_items')
        .then(response => {
             if (!response.ok) {
                return response.json().then(err => { 
                    throw new Error(err.error || `HTTP error! status: ${response.status}`);
                }).catch(() => {
                     throw new Error(`HTTP error! status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            listElement.innerHTML = ''; // Clear loading message
            if (!data || data.length === 0) {
                listElement.innerHTML = '<li>No action items found.</li>';
                emailPanelPlaceholder.textContent = 'No action items found.';
                return;
            }
            data.forEach(item => {
                const li = document.createElement('li');
                li.style.cursor = 'pointer';
                li.style.marginBottom = '10px';
                li.style.padding = '5px';
                li.style.border = '1px solid transparent'; // For hover/selected effect

                li.innerHTML = `<strong>Action:</strong> ${escapeHTML(item.action || 'N/A')}<br>
                                 <small><em>Email Subject: ${escapeHTML(item.source_subject || 'Unknown')}</em></small>`;
                li.dataset.emailId = item.email_id;
                
                li.addEventListener('click', () => {
                    document.querySelectorAll('#action-items-ul li').forEach(el => el.style.borderColor = 'transparent');
                    li.style.borderColor = '#007bff'; // Highlight selected
                    selectActionItem(item.email_id);
                });
                listElement.appendChild(li);
            });
            emailPanelPlaceholder.textContent = 'Select an action item to view the email.';
        })
        .catch(error => {
            console.error('Error fetching action items:', error);
            listElement.innerHTML = `<li class="error">Error loading action items: ${error.message}</li>`;
            emailPanelPlaceholder.textContent = 'Error loading action items.';
        });
}

function selectActionItem(emailId) {
    if (!emailId) return;
    console.log("Selected action item, fetching email ID:", emailId);

    const emailHeaderDiv = document.getElementById('action-item-email-header');
    const htmlDisplay = document.getElementById('action-item-email-html-display');
    const plainDisplay = document.getElementById('action-item-email-plain-display');
    const placeholder = document.getElementById('action-item-email-placeholder');

    emailHeaderDiv.innerHTML = 'Loading email details...';
    htmlDisplay.style.display = 'none';
    htmlDisplay.srcdoc = '';
    plainDisplay.style.display = 'none';
    plainDisplay.textContent = '';
    placeholder.style.display = 'block';
    placeholder.textContent = 'Loading email content...';
    currentSelectedEmailForAction = null;

    // Add a toggle button dynamically (or ensure it exists and is set up)
    let toggleButton = document.getElementById('action-item-email-view-toggle');
    if (!toggleButton) {
        toggleButton = document.createElement('button');
        toggleButton.id = 'action-item-email-view-toggle';
        // Insert it, for example, after the email header
        emailHeaderDiv.parentNode.insertBefore(toggleButton, emailHeaderDiv.nextSibling);
        toggleButton.addEventListener('click', toggleActionItemEmailDisplay);
    }
    toggleButton.style.display = 'none'; // Hide until content is loaded

    fetch(`/api/email_content?id=${emailId}`)
        .then(response => {
            if (!response.ok) {
                return response.json().then(err => { 
                    throw new Error(err.error || `HTTP error! status: ${response.status}`);
                }).catch(() => {
                    throw new Error(`HTTP error! status: ${response.status} - Could not parse error response.`);
                });
            }
            return response.json();
        })
        .then(emailData => {
            currentSelectedEmailForAction = emailData; // Store for toggle
            emailHeaderDiv.innerHTML = `<strong>From:</strong> ${escapeHTML(emailData.sender)}<br>
                                        <strong>Subject:</strong> ${escapeHTML(emailData.subject)}<hr>`;
            placeholder.style.display = 'none';

            if (emailData.body_html) {
                htmlDisplay.srcdoc = emailData.body_html;
                htmlDisplay.style.display = 'block';
                plainDisplay.style.display = 'none';
                // Store plain text for toggle
                plainDisplay.textContent = emailData.body_plain || 'No plain text version available.'; 
                toggleButton.textContent = 'Show Raw Text';
                toggleButton.dataset.currentView = 'html';
                toggleButton.style.display = 'inline-block';
            } else if (emailData.body_plain) {
                plainDisplay.textContent = emailData.body_plain;
                plainDisplay.style.display = 'block';
                htmlDisplay.style.display = 'none';
                toggleButton.textContent = 'Show HTML (N/A)';
                toggleButton.dataset.currentView = 'plain';
                toggleButton.style.display = 'inline-block';
            } else {
                plainDisplay.textContent = 'No content available for this email.';
                plainDisplay.style.display = 'block';
                htmlDisplay.style.display = 'none';
                toggleButton.style.display = 'none';
            }
        })
        .catch(error => {
            console.error('Error fetching email content for action item:', error);
            emailHeaderDiv.innerHTML = '';
            placeholder.style.display = 'block';
            placeholder.innerHTML = `<p class="error">Error loading email content: ${error.message}</p>`;
            htmlDisplay.style.display = 'none';
            plainDisplay.style.display = 'none';
            if(toggleButton) toggleButton.style.display = 'none';
        });
}

function toggleActionItemEmailDisplay() {
    if (!currentSelectedEmailForAction) return;

    const htmlDisplay = document.getElementById('action-item-email-html-display');
    const plainDisplay = document.getElementById('action-item-email-plain-display');
    const toggleButton = document.getElementById('action-item-email-view-toggle');

    if (toggleButton.dataset.currentView === 'html') {
        htmlDisplay.style.display = 'none';
        plainDisplay.style.display = 'block';
        toggleButton.textContent = 'Show Rendered HTML';
        toggleButton.dataset.currentView = 'plain';
    } else {
        if (currentSelectedEmailForAction.body_html) {
            htmlDisplay.style.display = 'block';
            plainDisplay.style.display = 'none';
            toggleButton.textContent = 'Show Raw Text';
            toggleButton.dataset.currentView = 'html';
        } else {
            alert("No HTML version available to display.");
        }
    }
}

// Basic HTML escaping function
function escapeHTML(str) {
    if (typeof str !== 'string') str = String(str || '');
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
} 