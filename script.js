document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const verifyButton = document.getElementById('verifyButton');
    const resultArea = document.getElementById('resultArea');
    const resultText = document.getElementById('resultText');
    
    let API_KEY = '';
    fetch('api_key.txt')
        .then(response => response.text())
        .then(text => { API_KEY = text.trim(); verifyButton.disabled = false; })
        .catch(err => {
            console.error('Erro ao carregar a chave da API:', err);
        });

    verifyButton.disabled = true;  // desabilita até carregar chave

    verifyButton.addEventListener('click', async function() {
        const urlToVerify = urlInput.value.trim();
        if (!urlToVerify) {
            alert('Por favor, insira uma URL para verificar.');
            resultArea.classList.add('hidden');
            return;
        }

        // Verificação de caracteres especiais
        const specialCharPattern = /["'<>@$&#%{}|\\^~\[\]`;]/;
        if (specialCharPattern.test(urlToVerify)) {
            resultText.textContent = `A URL "${urlToVerify}" contém caracteres especiais suspeitos.`;
            resultArea.classList.remove('hidden');
            return;
        }

        // Verificação de substituição numérica
        let domain;
        try {
            domain = new URL(urlToVerify).hostname.toLowerCase();
        } catch {
            domain = urlToVerify.toLowerCase();
        }
        const leetMap = { '0':'o', '1':'i', '3':'e', '4':'a', '5':'s', '7':'t' };
        const normalized = domain.replace(/[013457]/g, c => leetMap[c]);
        if (normalized !== domain) {
            resultText.textContent = `A URL "${urlToVerify}" contém possível substituição numérica no domínio ("${domain}" → "${normalized}").`;
            resultArea.classList.remove('hidden');
            return;
        }

        // Verificação Safe Browsing API
        resultText.textContent = 'Verificando...';
        resultArea.classList.remove('hidden');

        const body = {
            client: { clientId: "phishing-recognizer", clientVersion: "1.0" },
            threatInfo: {
                threatTypes:      ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                platformTypes:    ["ANY_PLATFORM"],
                threatEntryTypes: ["URL"],
                threatEntries: [{ url: urlToVerify }]
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
            if (!response.ok) throw new Error(`Erro na API: ${response.status}`);
            const data = await response.json();
            if (data.matches && data.matches.length) {
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
