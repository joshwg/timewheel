// Update time display on dashboard
function updateTime() {
    const timeDisplay = document.getElementById('currentTime');
    if (!timeDisplay) return;

    const now = new Date();
    
    // Format date and time
    const options = { 
        weekday: 'long', 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    };
    
    const formattedTime = now.toLocaleDateString('en-US', options);
    timeDisplay.textContent = formattedTime;
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { updateTime };
}
