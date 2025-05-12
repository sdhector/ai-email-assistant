// JavaScript for Action Items Screen
console.log("Action Items JS loaded.");

document.addEventListener('DOMContentLoaded', () => {
    fetchActionItems();
});

function fetchActionItems() {
    const listElement = document.getElementById('action-items-list');
    listElement.innerHTML = '<p>Loading action items...</p>'; // Show loading indicator

    fetch('/api/action_items')
        .then(response => {
             if (!response.ok) {
                // Try to get error details from JSON response
                return response.json().then(err => { 
                    throw new Error(err.error || `HTTP error! status: ${response.status}`);
                }).catch(() => {
                    // Fallback if error response is not JSON
                     throw new Error(`HTTP error! status: ${response.status}`);
                });
            }
            return response.json();
        })
        .then(data => {
            listElement.innerHTML = ''; // Clear loading message
            if (!data || data.length === 0) {
                listElement.innerHTML = '<p>No action items found.</p>';
                return;
            }
            data.forEach(item => {
                const div = document.createElement('div');
                // Display action and source information
                div.innerHTML = `<strong>Action:</strong> ${escapeHTML(item.action || 'N/A')}<br>
                                 <small><em>Source: ${escapeHTML(item.source || 'Unknown')}</em></small>`;
                listElement.appendChild(div);
            });
        })
        .catch(error => {
            console.error('Error fetching action items:', error);
            listElement.innerHTML = `<p class="error">Error loading action items: ${error.message}</p>`;
        });
}

// Basic HTML escaping function (can be shared in main.js later)
function escapeHTML(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
} 