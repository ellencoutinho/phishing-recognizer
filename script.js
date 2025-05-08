document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const verifyButton = document.getElementById('verifyButton');
    const resultArea = document.getElementById('resultArea');
    const resultText = document.getElementById('resultText');
    
    let API_KEY = ''; 
    fetch('api_key.txt')
        .then(response => response.text())
        .then(text => {API_KEY = text})
        .catch(err => {
        console.error('Erro ao carregar a chave da API:', err);
    });
      
    verifyButton.addEventListener('click', async function() {
        const urlToVerify = urlInput.value.trim();
        if (!urlToVerify) {
            alert('Por favor, insira uma URL para verificar.');
            resultArea.classList.add('hidden');
            return;
        }

        resultText.textContent = 'Verificando...';
        resultArea.classList.remove('hidden');

        // Monta o corpo da requisição conforme especificação da Safe Browsing API v4
        const body = {
            client: {
                clientId: "phishing-recognizer"
            },
            threatInfo: {
                threatTypes:      ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes:    ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [
                    { url: urlToVerify }
                ]
            }
        };

        try {
            const response = await fetch(
                `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                }
            );
            if (!response.ok) {
                throw new Error(`Erro na API: ${response.status}`);
            }
            const data = await response.json();

            if (data && data.matches && data.matches.length > 0) {
                // Há pelo menos uma ameaça listada
                resultText.textContent = `A URL "${urlToVerify}" foi identificada como suspeita de phishing (${data.matches[0].threatType}).`;
            } else {
                resultText.textContent = `A URL "${urlToVerify}" parece segura.`;
            }
        } catch (err) {
            console.error(err);
            resultText.textContent = `Ocorreu um erro ao verificar a URL: ${err.message}`;
        }
    });
});