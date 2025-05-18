// JavaScript for AI Response Screen
console.log("AI Response JS loaded.");

// Store current email details
let currentEmail = null;
let currentViewMode = 'desktop'; // Can be 'desktop' or 'mobile-list' or 'mobile-single'

// Function to add 'force-mobile-active' class to body if URL param is set
function applyForceMobileViewIfNeeded() {
    const urlParams = new URLSearchParams(window.location.search);
    const forceMobile = urlParams.get('forceMobileView') === 'true';
    if (forceMobile) {
        document.body.classList.add('force-mobile-active');
        console.log("Forcing mobile view via URL parameter.");
    }
}

// Function to check current view based on CSS display properties or forced mode
function updateViewMode() {
    const isForcedMobile = document.body.classList.contains('force-mobile-active');
    
    const desktopGrid = document.querySelector('.response-grid-container');
    const mobileSingle = document.querySelector('.mobile-single-email-view-container');
    // mobileListContainer is assumed to be the alternative if not single view in mobile mode

    if (isForcedMobile) {
        // In forced mobile mode, desktopGrid is hidden by CSS.
        // Determine if mobile-list or mobile-single is the current state.
        if (mobileSingle && mobileSingle.classList.contains('active')) {
            currentViewMode = 'mobile-single';
        } else {
            currentViewMode = 'mobile-list';
        }
    } else {
        // Standard responsive logic based on computed styles (driven by media queries)
        if (desktopGrid && getComputedStyle(desktopGrid).display !== 'none') {
            currentViewMode = 'desktop';
        } else { // Screen is small enough for mobile layout as per CSS, or desktop is hidden by other means
            if (mobileSingle && mobileSingle.classList.contains('active')) {
                 currentViewMode = 'mobile-single';
            } else {
                currentViewMode = 'mobile-list';
            }
        }
    }
    console.log("Updated view mode:", currentViewMode, "| Is Forced Mobile:", isForcedMobile);
}

document.addEventListener('DOMContentLoaded', () => {
    applyForceMobileViewIfNeeded(); // Apply force mobile class first
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

    // Mobile view buttons
    document.getElementById('mobile-back-to-list-btn').addEventListener('click', showMobileEmailListView);
    document.getElementById('mobile-reply-btn').addEventListener('click', handleMobileReply);
    document.getElementById('mobile-delete-btn').addEventListener('click', deleteSelectedEmail); // Mobile delete, can reuse
    document.getElementById('mobile-send-reply-btn').addEventListener('click', sendMobileApprovedEmail);
    document.getElementById('mobile-cancel-reply-btn').addEventListener('click', cancelMobileReply);
    document.getElementById('mobile-adjust-reply-btn').addEventListener('click', getAdjustedResponse); // Mobile adjust

    // Add toggle for email view (HTML/Plain) for desktop
    const toggleDesktopButton = document.getElementById('toggle-email-view');
    if (toggleDesktopButton) {
        toggleDesktopButton.addEventListener('click', () => {
            const htmlDisplay = document.getElementById('email-html-display');
            const plainDisplay = document.getElementById('email-plain-display');
            if (htmlDisplay.style.display === 'none') {
                htmlDisplay.style.display = 'block';
                plainDisplay.style.display = 'none';
                toggleDesktopButton.textContent = 'Show Raw Text';
            } else {
                htmlDisplay.style.display = 'none';
                plainDisplay.style.display = 'block';
                toggleDesktopButton.textContent = 'Show HTML';
            }
        });
    }
    
    // Initial view mode check and listener for resize
    updateViewMode(); // Call after applying force class and other initial setup
    window.addEventListener('resize', updateViewMode);

    // Setup for load more button
    const loadMoreBtn = document.getElementById('load-more-btn');
    if (loadMoreBtn) {
        loadMoreBtn.addEventListener('click', () => fetchEmails(true)); // Pass a flag to indicate loading more
    }
});

let nextPageToken = null; // For Gmail API pagination

function fetchEmails(loadMore = false) {
    const desktopEmailList = document.getElementById('email-list');
    const mobileEmailList = document.getElementById('mobile-email-list');
    const loadMoreContainer = document.getElementById('load-more-emails-container');

    if (!loadMore) {
        if (desktopEmailList) desktopEmailList.innerHTML = '<li>Loading emails...</li>';
        if (mobileEmailList) mobileEmailList.innerHTML = '<li>Loading emails...</li>';
        nextPageToken = null; // Reset token for a fresh load
    } else {
        document.getElementById('load-more-btn').textContent = 'Loading...';
        document.getElementById('load-more-btn').disabled = true;
    }

    let apiUrl = '/api/emails';
    if (loadMore && nextPageToken) {
        apiUrl += `?pageToken=${nextPageToken}`;
    } else if (loadMore && !nextPageToken) {
        console.log("No more pages to load.");
        if (loadMoreContainer) loadMoreContainer.style.display = 'none'; // Hide button if no token
        document.getElementById('load-more-btn').textContent = 'Load More Emails';
        document.getElementById('load-more-btn').disabled = false;
        return; // Nothing to load
    }

    fetch(apiUrl)
        .then(response => {
            if (!response.ok) {
                if (response.status === 401) { // Handle auth errors specifically
                    alert("Authentication error. Please log in again.");
                    window.location.href = '/authorize'; // Redirect to login/auth page
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // The API now returns an object like { emails: [], nextPageToken: '...' }
            const emails = data.emails || []; // Ensure emails is an array
            nextPageToken = data.nextPageToken || null;

            if (!loadMore) { // Full refresh
                if (desktopEmailList) desktopEmailList.innerHTML = '';
                if (mobileEmailList) mobileEmailList.innerHTML = '';
            }

            if ((!emails || emails.length === 0) && !loadMore) {
                if (desktopEmailList) desktopEmailList.innerHTML = '<li>No unread emails found.</li>';
                if (mobileEmailList) mobileEmailList.innerHTML = '<li>No unread emails found.</li>';
                if (loadMoreContainer) loadMoreContainer.style.display = 'none';
                return;
            }
            
            emails.forEach(email => {
                // Populate desktop list (existing simple format)
                if (desktopEmailList) {
                    const li = document.createElement('li');
                    li.textContent = `${email.sender.split('<')[0].trim()} - ${email.subject}`;
                    li.dataset.id = email.id;
                    li.dataset.threadId = email.threadId;
                    li.addEventListener('click', () => selectEmail(email.id));
                    desktopEmailList.appendChild(li);
                }

                // Populate mobile list (new snippet format)
                if (mobileEmailList) {
                    const li = document.createElement('li');
                    li.dataset.id = email.id;
                    li.dataset.threadId = email.threadId;

                    const senderDiv = document.createElement('div');
                    senderDiv.className = 'email-snippet-sender';
                    senderDiv.textContent = email.sender.split('<')[0].trim();

                    const dateDiv = document.createElement('div');
                    dateDiv.className = 'email-snippet-date';
                    // Format date nicely - this is a basic version
                    try {
                        dateDiv.textContent = new Date(email.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
                    } catch (e) {
                        dateDiv.textContent = email.date.substring(0, 10); // Fallback
                    }

                    const subjectDiv = document.createElement('div');
                    subjectDiv.className = 'email-snippet-subject';
                    subjectDiv.textContent = email.subject || '(No Subject)';
                    
                    const snippetDiv = document.createElement('div');
                    snippetDiv.className = 'email-snippet-body';
                    snippetDiv.textContent = email.snippet || '(No snippet available)';

                    li.appendChild(dateDiv); // Date first for float to work well with overflows
                    li.appendChild(senderDiv);
                    li.appendChild(subjectDiv);
                    li.appendChild(snippetDiv);
                    
                    li.addEventListener('click', () => selectEmail(email.id));
                    mobileEmailList.appendChild(li);
                }
            });

            if (loadMoreContainer) {
                if (nextPageToken) {
                    loadMoreContainer.style.display = 'block';
                } else {
                    loadMoreContainer.style.display = 'none';
                    if (loadMore && emails.length > 0) { // If loaded more and no next page, can say "No more emails"
                         // Optionally add a message to mobileEmailList that no more emails
                    }
                }
            }
        })
        .catch(error => {
            console.error('Error fetching emails:', error);
            if (desktopEmailList) desktopEmailList.innerHTML = `<li>Error loading emails: ${error.message}</li>`;
            if (mobileEmailList) mobileEmailList.innerHTML = `<li>Error loading emails: ${error.message}</li>`;
            if (loadMoreContainer) loadMoreContainer.style.display = 'none'; // Hide on error too
        })
        .finally(() => {
            if (loadMore) {
                document.getElementById('load-more-btn').textContent = 'Load More Emails';
                document.getElementById('load-more-btn').disabled = false;
            }
            // updateViewMode(); // Re-check view mode after fetching - already called in DOMContentLoaded & resize
            // It might be good to call it here IF fetching emails could change layout (e.g. no emails shown vs emails)
            // but for now, main triggers are initial load and resize.
        });
}

function selectEmail(messageId) {
    console.log("Selected email ID:", messageId, "Current view mode:", currentViewMode);
    currentEmail = null; // Reset global currentEmail

    // Clear previous AI response and chatbot history
    document.getElementById('ai-response-area').value = ''; // Desktop
    if(document.getElementById('mobile-ai-response-area')) document.getElementById('mobile-ai-response-area').value = ''; // Mobile
    document.getElementById('chatbot-history').innerHTML = '';
    document.getElementById('chatbot-input').value = '';

    // Highlight selected item in lists (optional, but good UX)
    document.querySelectorAll('#email-list li, #mobile-email-list li').forEach(item => {
        item.classList.remove('selected');
        if (item.dataset.id === messageId) {
            item.classList.add('selected');
        }
    });

    if (currentViewMode === 'desktop') {
        // --- Desktop View Logic ---
        const emailHeaderDiv = document.getElementById('selected-email-header');
        const htmlDisplay = document.getElementById('email-html-display');
        const plainDisplay = document.getElementById('email-plain-display');
        const toggleBtn = document.getElementById('toggle-email-view');

        emailHeaderDiv.innerHTML = 'Loading email details...';
        htmlDisplay.style.display = 'none';
        plainDisplay.style.display = 'none';
        if(toggleBtn) toggleBtn.style.display = 'none';

        fetch(`/api/email_content?id=${messageId}`)
            .then(response => {
                if (!response.ok) {
                     if (response.status === 401) { // Handle auth errors
                        alert("Authentication error. Please log in again.");
                        window.location.href = '/authorize';
                    }
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(emailData => {
                currentEmail = emailData; // Store details globally

                emailHeaderDiv.innerHTML = `<strong>From:</strong> ${escapeHTML(emailData.sender)}<br><strong>Subject:</strong> ${escapeHTML(emailData.subject)}<hr>`;

                if (emailData.body_html) {
                    htmlDisplay.srcdoc = emailData.body_html;
                    htmlDisplay.style.display = 'block';
                    plainDisplay.style.display = 'none';
                    if(plainDisplay) plainDisplay.textContent = emailData.body_plain || 'No plain text version available.';
                    if(toggleBtn) {
                        toggleBtn.textContent = 'Show Raw Text';
                        toggleBtn.dataset.currentView = 'html';
                        toggleBtn.style.display = 'inline-block';
                    }
                } else if (emailData.body_plain) {
                    if(plainDisplay) {
                        plainDisplay.textContent = emailData.body_plain;
                        plainDisplay.style.display = 'block';
                    }
                    htmlDisplay.style.display = 'none';
                    if(toggleBtn) {
                        toggleBtn.textContent = 'Show HTML (N/A)';
                        toggleBtn.dataset.currentView = 'plain';
                        toggleBtn.style.display = 'inline-block';
                    }
                } else {
                    if(plainDisplay) {
                        plainDisplay.textContent = 'No content available.';
                        plainDisplay.style.display = 'block';
                    }
                    htmlDisplay.style.display = 'none';
                    if(toggleBtn) toggleBtn.style.display = 'none';
                }
                // Get initial AI response for desktop
                const contentForAI = emailData.body_plain || emailData.snippet || (emailData.body_html ? "HTML content provided, not shown here." : "");
                getInitialResponse(contentForAI, emailData.subject, 'ai-response-area');
            })
            .catch(error => {
                console.error('Error fetching email content for desktop:', error);
                emailHeaderDiv.innerHTML = `<p class="error">Error loading email header: ${error.message}</p>`;
                if(plainDisplay) {
                    plainDisplay.textContent = `Error loading email content: ${error.message}`;
                    plainDisplay.style.display = 'block';
                }
                htmlDisplay.style.display = 'none';
                document.getElementById('ai-response-area').value = 'Error loading email content.';
            });
    } else if (currentViewMode === 'mobile-list' || currentViewMode === 'mobile-single') {
        // --- Mobile View Logic ---
        showMobileSingleEmailView(messageId);
    }
}

function showMobileEmailListView() {
    document.querySelector('.mobile-email-list-container').style.display = 'block';
    document.querySelector('.mobile-single-email-view-container').classList.remove('active');
    
    const mainNav = document.querySelector('nav');
    if (mainNav) {
        mainNav.style.display = ''; // Revert to default display
    }

    // Ensure hamburger menu is reset
    const navLinks = document.querySelector('.nav-links');
    const hamburger = document.querySelector('.hamburger-menu');
    if (navLinks && hamburger && navLinks.classList.contains('active')) {
        navLinks.classList.remove('active');
        hamburger.classList.remove('active');
        hamburger.setAttribute('aria-expanded', 'false');
    }

    const replyInterface = document.querySelector('.mobile-reply-interface-wrapper');
    if (replyInterface) {
        replyInterface.classList.remove('active-reply');
        // replyInterface.style.display = 'none'; // .active-reply class handles display
    }
    // Clear instruction input when hiding reply interface
    const mobileInstructionsInput = document.getElementById('mobile-user-instructions-input');
    if (mobileInstructionsInput) mobileInstructionsInput.value = '';

    currentEmail = null; 
    updateViewMode(); 
}

function showMobileSingleEmailView(messageId) {
    document.querySelector('.mobile-email-list-container').style.display = 'none';
    document.querySelector('.mobile-single-email-view-container').classList.add('active');

    const mainNav = document.querySelector('nav');
    if (mainNav) {
        mainNav.style.display = 'none';
    }

    const emailHeaderDiv = document.getElementById('mobile-selected-email-header');
    const htmlDisplay = document.getElementById('mobile-email-html-display');
    const plainDisplay = document.getElementById('mobile-email-plain-display');
    const replyInterface = document.querySelector('.mobile-reply-interface-wrapper');

    emailHeaderDiv.innerHTML = 'Loading email details...';
    htmlDisplay.style.display = 'none'; 
    htmlDisplay.srcdoc = ''; 
    plainDisplay.style.display = 'none';
    plainDisplay.textContent = '';

    // Ensure reply interface is hidden initially when a new email is selected
    if (replyInterface) {
        replyInterface.classList.remove('active-reply');
        // replyInterface.style.display = 'none'; // .active-reply class handles display
    }
    // Clear instruction input as well
    const mobileInstructionsInput = document.getElementById('mobile-user-instructions-input');
    if (mobileInstructionsInput) mobileInstructionsInput.value = '';

    fetch(`/api/email_content?id=${messageId}`)
        .then(response => {
            if (!response.ok) {
                if (response.status === 401) {
                    alert("Authentication error. Please log in again.");
                    window.location.href = '/authorize';
                }
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(emailData => {
            currentEmail = emailData; // Store globally

            emailHeaderDiv.innerHTML = `<strong>From:</strong> ${escapeHTML(emailData.sender)}<br><strong>Subject:</strong> ${escapeHTML(emailData.subject)}<hr>`;

            if (emailData.body_html) {
                htmlDisplay.srcdoc = emailData.body_html;
                htmlDisplay.style.display = 'block';
                plainDisplay.style.display = 'none';
            } else if (emailData.body_plain) {
                plainDisplay.textContent = emailData.body_plain;
                plainDisplay.style.display = 'block';
                htmlDisplay.style.display = 'none';
            } else {
                plainDisplay.textContent = 'No content available for this email.';
                plainDisplay.style.display = 'block';
                htmlDisplay.style.display = 'none';
            }
             // AI response handling for mobile will be via the 'Reply' button action
            document.getElementById('mobile-ai-response-area').value = ''; // Clear any previous reply
            
            // Ensure reply interface is reset and hidden (already done above, but good for clarity here too)
            // const replyInterface = document.querySelector('.mobile-reply-interface-wrapper'); already declared
            if (replyInterface) {
                replyInterface.classList.remove('active-reply');
            }
            updateViewMode(); // Update mode after view change
        })
        .catch(error => {
            console.error('Error fetching email content for mobile:', error);
            emailHeaderDiv.innerHTML = `<p class="error">Error loading email: ${error.message}</p>`;
            plainDisplay.textContent = `Error loading content: ${error.message}`;
            plainDisplay.style.display = 'block';
            htmlDisplay.style.display = 'none';
            updateViewMode(); // Update mode after error/view change
        });
}

function handleMobileReply() {
    if (!currentEmail) {
        alert("No email selected to reply to.");
        return;
    }
    const replyInterface = document.querySelector('.mobile-reply-interface-wrapper');
    if (replyInterface) {
        // replyInterface.style.display = 'flex'; // Handled by class
        replyInterface.classList.add('active-reply');
    } else {
        console.error(".mobile-reply-interface-wrapper not found");
        return;
    }

    document.getElementById('mobile-ai-response-area').value = "Generating AI suggestion...";
    if (document.getElementById('mobile-user-instructions-input')) {
        document.getElementById('mobile-user-instructions-input').value = ''; // Clear previous instructions
    }

    const contentForAI = currentEmail.body_plain || currentEmail.snippet || (currentEmail.body_html ? "HTML body provided (not used for prompt)" : "No text content for prompt.");
    getInitialResponse(contentForAI, currentEmail.subject, 'mobile-ai-response-area');
}

function cancelMobileReply() {
    const replyInterface = document.querySelector('.mobile-reply-interface-wrapper');
    if (replyInterface) {
        // replyInterface.style.display = 'none'; // Handled by class
        replyInterface.classList.remove('active-reply');
    }
    document.getElementById('mobile-ai-response-area').value = '';
    const mobileInstructionsInput = document.getElementById('mobile-user-instructions-input');
    if (mobileInstructionsInput) mobileInstructionsInput.value = '';
}

function sendMobileApprovedEmail() {
    if (!currentEmail) {
        alert("Please select an email to reply to first.");
        return;
    }

    const recipient = extractEmailAddress(currentEmail.sender);
    if (!recipient) {
        alert("Could not determine recipient email address from sender.");
        return;
    }

    let subject = currentEmail.subject;
    if (!subject.toLowerCase().startsWith('re:')) {
        subject = `Re: ${subject}`;
    }

    const body = document.getElementById('mobile-ai-response-area').value;
    const threadId = currentEmail.threadId;

    if (!confirm(`Send this reply to ${recipient}?\\n\\nSubject: ${subject}`)) {
        return;
    }

    const sendButton = document.getElementById('mobile-send-reply-btn');
    sendButton.disabled = true;
    sendButton.textContent = 'Sending...';

    fetch('/api/send_email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipient, subject, body, threadId })
    })
    .then(response => {
        if (!response.ok) {
            return response.json().then(err => { throw new Error(err.error || `HTTP error! status: ${response.status}`); });
        }
        return response.json();
    })
    .then(data => {
        alert("Email sent successfully!");
        console.log("Mobile Send success:", data);
        fetchEmails(); // Refresh email list
        showMobileEmailListView(); // Go back to list view
    })
    .catch(error => {
        console.error('Error sending mobile email:', error);
        alert(`Error sending email: ${error.message}`);
    })
    .finally(() => {
        sendButton.disabled = false;
        sendButton.textContent = 'Send Reply';
    });
}

function getInitialResponse(emailBody, emailSubject, targetTextAreaId) {
    const aiResponseArea = document.getElementById(targetTextAreaId);
    if (!aiResponseArea) {
        console.error("Target textarea for AI response not found:", targetTextAreaId);
        return;
    }
    aiResponseArea.value = 'Generating AI suggestion...';

     fetch('/api/generate_response', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email_content: emailBody,
            email_subject: emailSubject
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
    })
    .catch(error => {
        console.error('Error generating AI response:', error);
        aiResponseArea.value = `Error generating response: ${error.message}`;
    });
}

function getAdjustedResponse() {
    if (!currentEmail) {
        alert("Please select an email first.");
        return;
    }

    let instructions = '';
    let targetAiResponseAreaId = '';
    const chatbotHistory = document.getElementById('chatbot-history'); // Desktop history

    if (currentViewMode === 'desktop') {
        instructions = document.getElementById('chatbot-input').value;
        targetAiResponseAreaId = 'ai-response-area';
        const userMsgDiv = document.createElement('div');
        userMsgDiv.textContent = `You: ${instructions}`;
        if(chatbotHistory) chatbotHistory.appendChild(userMsgDiv);
    } else if (currentViewMode === 'mobile-single') {
        const mobileInstructionsInput = document.getElementById('mobile-user-instructions-input');
        if (!mobileInstructionsInput) {
            console.error("#mobile-user-instructions-input not found");
            return;
        }
        instructions = mobileInstructionsInput.value;
        targetAiResponseAreaId = 'mobile-ai-response-area';
        // No separate history div for mobile instructions in this design yet
    } else {
        console.error("getAdjustedResponse called in unexpected view mode:", currentViewMode);
        return;
    }

    const activeAiTextarea = document.getElementById(targetAiResponseAreaId);
    if (!activeAiTextarea) {
        console.error("Critical error: Target AI response textarea not found with ID:", targetAiResponseAreaId);
        alert("An error occurred: the AI response area could not be found.");
        return;
    }
    const currentResponse = activeAiTextarea.value; 
    activeAiTextarea.value = 'Adjusting response...';

    const contentForAI = currentEmail.body_plain || currentEmail.snippet || (currentEmail.body_html ? "HTML content provided, not shown here." : "");

    fetch('/api/generate_response', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            email_content: contentForAI,
            email_subject: currentEmail.subject,
            instructions: instructions,
            previous_response: currentResponse
        })
    })
    .then(response => response.json())
    .then(data => {
        activeAiTextarea.value = data.response;
        if (currentViewMode === 'desktop' && chatbotHistory) {
            const aiMsgDiv = document.createElement('div');
            aiMsgDiv.textContent = `AI: (Response updated)`;
            chatbotHistory.appendChild(aiMsgDiv);
        }
        // Clear instructions input after successful adjustment
        if (currentViewMode === 'desktop') document.getElementById('chatbot-input').value = '';
        else if (currentViewMode === 'mobile-single') {
            const mobileInstructionsInput = document.getElementById('mobile-user-instructions-input');
            if (mobileInstructionsInput) mobileInstructionsInput.value = '';
        }
    })
    .catch(error => {
        console.error('Error generating adjusted AI response:', error);
        activeAiTextarea.value = `Error adjusting response: ${error.message}`;
        if (currentViewMode === 'desktop' && chatbotHistory) {
            const errorMsgDiv = document.createElement('div');
            errorMsgDiv.textContent = `Error: ${error.message}`;
            errorMsgDiv.classList.add('error');
            chatbotHistory.appendChild(errorMsgDiv);
        }
    });
}

function sendApprovedEmail() {
    // This function is primarily for the DESKTOP view's "Approve & Send"
    if (currentViewMode !== 'desktop' || !currentEmail) {
        if (currentViewMode.startsWith('mobile') && currentEmail) {
            const replyInterface = document.querySelector('.mobile-reply-interface-wrapper');
            if (replyInterface && (replyInterface.style.display === 'flex' || replyInterface.classList.contains('active-reply'))) {
                sendMobileApprovedEmail(); 
            } else {
                alert("To send from mobile, first tap 'Reply'.");
            }
        } else if (!currentEmail) {
             alert("Please select an email to reply to first.");
        }
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
    
    // Determine which button to update based on view mode
    let deleteButton;
    if (currentViewMode === 'desktop') {
        deleteButton = document.getElementById('delete-button');
    } else { // mobile-single or mobile-list (though delete usually happens in single view)
        deleteButton = document.getElementById('mobile-delete-btn');
    }
    
    if(deleteButton) {
        deleteButton.disabled = true;
        deleteButton.textContent = 'Deleting...';
    }

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
        fetchEmails(); // Refresh the email list (both mobile and desktop)
        
        if (currentViewMode === 'desktop') {
            clearSelectedEmailView(); // Clear desktop view
        } else {
            showMobileEmailListView(); // Go back to mobile list view
        }
    })
    .catch(error => {
        console.error('Error deleting email:', error);
        alert(`Error deleting email: ${error.message}`);
    })
    .finally(() => {
        if(deleteButton) {
            deleteButton.disabled = false;
            deleteButton.textContent = 'Delete Email';
        }
    });
}

function clearSelectedEmailView() {
    // This is primarily for DESKTOP view
    document.getElementById('selected-email-header').innerHTML = '';
    const htmlDisplay = document.getElementById('email-html-display');
    const plainDisplay = document.getElementById('email-plain-display');
    const toggleBtn = document.getElementById('toggle-email-view');

    if(htmlDisplay) htmlDisplay.srcdoc = '';
    if(htmlDisplay) htmlDisplay.style.display = 'none';
    if(plainDisplay) plainDisplay.textContent = '';
    if(plainDisplay) plainDisplay.style.display = 'none';
    if(toggleBtn) toggleBtn.style.display = 'none';
    
    document.getElementById('ai-response-area').value = '';
    document.getElementById('chatbot-input').value = '';
    document.getElementById('chatbot-history').innerHTML = '';
    currentEmail = null;
    // Deselect items in desktop list
    document.querySelectorAll('#email-list li.selected').forEach(item => item.classList.remove('selected'));
}

// Helper function to extract email from strings like "Sender Name <email@example.com>"
function extractEmailAddress(senderString) {
    const match = senderString.match(/<([^>]+)>/);
    return match ? match[1] : senderString; // Fallback to using the whole string if no <> found
}

// Basic HTML escaping function
function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return str.replace(/[&<>"']/g, function (match) {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        }[match];
    });
}

// Make sure currentEmail is cleared when navigating away or something similar if needed.
// Call updateViewMode initially and on resize
window.addEventListener('resize', updateViewMode);
//DOMContentLoaded is already handling initial updateViewMode and fetchEmails

// ... rest of the existing code ... 
// ... rest of the existing code ... 