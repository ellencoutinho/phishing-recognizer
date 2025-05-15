document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const verifyButton = document.getElementById('verifyButton');
    const resultArea = document.getElementById('resultArea');
    const resultText = document.getElementById('resultText');

    const TTL_THRESHOLD = 300; // Threshold de TTL em segundos
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

        resultText.textContent = 'Verificando...';
        resultArea.classList.remove('hidden');

        let isPhishingSuspect = false;
        let phishingReason = '';

        // Verificação de caracteres especiais
        const specialCharPattern = /["'<>@$&#%{}|\\^~\[\]`;]/;
        if (specialCharPattern.test(urlToVerify)) {
            isPhishingSuspect = true;
            phishingReason += `A URL contém caracteres especiais suspeitos. `;
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
            isPhishingSuspect = true;
            phishingReason += `Possível substituição numérica no domínio ("${domain}" → "${normalized}"). `;
        }

        // Consulta à API de DNS do Google para obter o TTL
        let ttl = null;
        try {
            const domainToCheck = new URL(urlToVerify).hostname;
            const dnsResponse = await fetch(`https://dns.google/resolve?name=${domainToCheck}&type=A`);
            if (dnsResponse.ok) {
                const dnsData = await dnsResponse.json();
                if (dnsData.Answer && dnsData.Answer.length > 0 && dnsData.Answer[0].TTL) {
                    ttl = dnsData.Answer[0].TTL;
                    if (ttl < TTL_THRESHOLD) {
                        isPhishingSuspect = true;
                        phishingReason += `O TTL do domínio (${ttl} segundos) é baixo, o que pode ser um indicador de DNS dinâmico usado para phishing.`;
                    }
                } else {
                    console.warn('Não foi possível obter um registro A válido para o domínio.');
                }
            } else {
                console.error('Erro ao consultar a API de DNS do Google:', dnsResponse.status);
            }
        } catch (error) {
            console.error('Erro ao consultar a API de DNS do Google:', error);
        }

        // Verificação Safe Browsing API
        try {
            const body = {
                client: { clientId: "phishing-recognizer", clientVersion: "1.0" },
                threatInfo: {
                    threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL"],
                    threatEntries: [{ url: urlToVerify }]
                }
            };

            const response = await fetch(
                `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                }
            );
            if (!response.ok) throw new Error(`Erro na API Safe Browsing: ${response.status}`);
            const data = await response.json();
            if (data.matches && data.matches.length) {
                isPhishingSuspect = true;
                phishingReason += `A URL foi identificada como suspeita de phishing pelo Safe Browsing (${data.matches[0].threatType}). `;
            }
        } catch (err) {
            console.error('Erro ao verificar com a API Safe Browsing:', err);
            phishingReason += `Ocorreu um erro ao verificar com a API Safe Browsing: ${err.message}. `;
        }

        if (isPhishingSuspect) {
            resultText.textContent = `A URL "${urlToVerify}" foi identificada como suspeita de phishing devido a: ${phishingReason.trim()}`;
        } else {
            resultText.textContent = `A URL "${urlToVerify}" parece segura (com base nas verificações realizadas).`;
        }
    });
});