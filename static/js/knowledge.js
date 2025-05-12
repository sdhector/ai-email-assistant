// JavaScript for Knowledge Base Screen
console.log("Knowledge JS loaded.");

document.addEventListener('DOMContentLoaded', () => {
    loadKnowledge();

    const saveButton = document.getElementById('save-knowledge-button');
    saveButton.addEventListener('click', saveKnowledge);
});

function loadKnowledge() {
    fetch('/api/knowledge')
        .then(response => response.json())
        .then(data => {
            document.getElementById('knowledge-content').value = data.info || '';
        })
        .catch(error => console.error('Error loading knowledge:', error));
}

function saveKnowledge() {
    const content = document.getElementById('knowledge-content').value;
    const statusMessage = document.getElementById('status-message');
    statusMessage.textContent = 'Saving...';

    fetch('/api/knowledge', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ data: content })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            statusMessage.textContent = 'Knowledge saved successfully!';
        } else {
            statusMessage.textContent = 'Error saving knowledge.';
        }
        setTimeout(() => statusMessage.textContent = '', 3000); // Clear message after 3s
    })
    .catch(error => {
        console.error('Error saving knowledge:', error);
        statusMessage.textContent = 'Error saving knowledge.';
        setTimeout(() => statusMessage.textContent = '', 3000);
    });
} 