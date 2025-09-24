const recentDomainsList = document.getElementById('recent-domains');
const logs = document.getElementById('logs');

function fetchData() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            recentDomainsList.innerHTML = data.recent_domains.map(domain => `<li>${domain}</li>`).join('');
        });
}

fetchData();

const socket = new WebSocket(`ws://${location.host}/ws`);

socket.onmessage = function(event) {
    const data = JSON.parse(event.data);
    if (data.type === 'update') {
        fetchData();
    } else if (data.type === 'log') {
        logs.textContent += data.message + '\n';
    }
};