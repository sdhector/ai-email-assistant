// JavaScript for Action Items Screen
console.log("Action Items JS loaded.");

document.addEventListener('DOMContentLoaded', () => {
    fetchActionItems();
});

function fetchActionItems() {
    fetch('/api/action_items')
        .then(response => response.json())
        .then(data => {
            const listElement = document.getElementById('action-items-list');
            listElement.innerHTML = ''; // Clear loading message
            if (data.length === 0) {
                listElement.innerHTML = '<p>No action items found.</p>';
                return;
            }
            data.forEach(item => {
                const div = document.createElement('div');
                div.innerHTML = `<strong>${item.email_subject}:</strong> ${item.action}`;
                listElement.appendChild(div);
            });
        })
        .catch(error => {
            console.error('Error fetching action items:', error);
            document.getElementById('action-items-list').innerHTML = '<p>Error loading action items.</p>';
        });
} 