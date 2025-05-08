document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const verifyButton = document.getElementById('verifyButton');
    const resultArea = document.getElementById('resultArea');
    const resultText = document.getElementById('resultText');

    verifyButton.addEventListener('click', function() {
        const urlToVerify = urlInput.value.trim();

        if (urlToVerify) {
            // Lógica para verificar a URL

            const isPhishing = Math.random() < 0.5; // Simulação aleatória

            if (isPhishing) {
                resultText.textContent = `A URL "${urlToVerify}" foi identificada como potencialmente suspeita de phishing.`;
            } else {
                resultText.textContent = `A URL "${urlToVerify}" parece segura.`;
            }

            resultArea.classList.remove('hidden');
        } else {
            alert('Por favor, insira uma URL para verificar.');
            resultArea.classList.add('hidden');
        }
    });
});