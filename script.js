import { TTL_THRESHOLD, LEVENSHTEIN_THRESHOLD, TOP_100_BRANDS, KEYWORDS } from './constants.js';

function getDomainLabel(rawUrl) {
  let hostname;
  try {
    // usa URL API se for bem-formada
    hostname = new URL(rawUrl).hostname.toLowerCase();
  } catch {
    hostname = rawUrl.toLowerCase()
                     .replace(/^.*?:\/\//, '')  // remove protocolo
                     .split('/')[0];            // remove caminho
  }
  if (hostname.startsWith('www.')) {
    hostname = hostname.slice(4);
  }
  return hostname.split('.')[0];
}

async function checkRedirects(url) {
    try {
        const res = await fetch(url, { 
            method: 'HEAD',
            redirect: 'manual',
            referrerPolicy: 'no-referrer'
        });

        if ((res.status >= 300 && res.status < 400) || res.type === 'opaqueredirect') {
            const location = res.headers.get('location') || res.headers.get('Location');
            return {
                isSuspicious: true,
                message: "Redirecionamento detectado"
            };
            
        }
        return { isSuspicious: false };
    } catch (error) {
        console.error('Erro ao verificar redirecionamentos:', error);
        return { isSuspicious: false };
    }
}

async function checkDomainAge(domain, API_KEYS) {
    try {
        const domainParts = domain.replace(/^https?:\/\//, '').split('/')[0];
        console.log("testando o ", domainParts);
        const response = await fetch(
            `https://api.apilayer.com/whois/query?domain=${domainParts}`,
            {
                method: 'GET',
                headers: { 'apikey': API_KEYS.whois }
            }
        );

        if (!response.ok) {
            throw new Error(`Erro na API: ${response.status}`);
        }

        const data = await response.json();
        console.log('Resposta WHOIS:', data);

        if (data.result && data.result.creation_date) {
            const createdDate = new Date(data.result.creation_date);
            const ageInDays = Math.floor((new Date() - createdDate) / (86400000));
            
            return {
                ageInDays,
                createdDate: data.result.creation_date.split('T')[0],
                isSuspicious: ageInDays < 30,
                registrar: data.result.registrar || 'Desconhecido'
            };
        }
        
        return { error: 'Data de criação não disponível' };
    } catch (error) {
        console.error('Erro WHOIS:', error);
        return { error: 'Serviço indisponível' };
    }
}

async function checkSSLCertificate(domain, API_KEYS) {
    const targetUrl = 
        `https://api.ssllabs.com/api/v3/analyze?host=${domain}` +
        `&publish=off&fromCache=on&all=on`;
    const proxyUrl = `https://api.allorigins.win/get?url=${targetUrl}`;

    try {
        const res = await fetch(proxyUrl);
        if (!res.ok) throw new Error(`Proxy respondeu com ${res.status}`);
        const wrapper = await res.json();
        const data = JSON.parse(wrapper.contents);
        return data.endpoints[0]?.grade;;
    }
    catch (err) {
        console.error('Erro ao  consultar a API SSL Labs:', err);
        return { error: err.message };
    }
}

async function checkSensitiveForms(url) {
    try {
        const proxyUrl = `https://api.allorigins.win/raw?url=${encodeURIComponent(url)}`;
        const response = await fetch(proxyUrl);

        if (!response.ok) throw new Error(`Erro ao buscar HTML: ${response.status}`);

        const html = await response.text();

        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');

        const suspiciousInputs = [];

        // Formulários com campos sensíveis
        const forms = doc.querySelectorAll('form');
        forms.forEach(form => {
            const inputs = form.querySelectorAll('input');
            inputs.forEach(input => {
                const type = input.getAttribute('type')?.toLowerCase() || '';
                const name = input.getAttribute('name')?.toLowerCase() || '';
                const placeholder = input.getAttribute('placeholder')?.toLowerCase() || '';

                if (
                    ['password', 'email', 'tel', 'number'].includes(type) ||
                    KEYWORDS.some(word =>
                        name.includes(word) || placeholder.includes(word)
                    )
                ) {
                    suspiciousInputs.push({ type, name, placeholder });
                }
            });
        });

        // Palavras fora de formulários
        const lowerHTML = html.toLowerCase();
        const detectedKeywords = KEYWORDS.filter(k => lowerHTML.includes(k));

        const isSuspicious = suspiciousInputs.length > 0 || detectedKeywords.length > 0;

        return {
            isSuspicious,
            suspiciousInputs,
            detectedKeywords
        };

    } catch (err) {
        console.error("Erro ao analisar conteúdo HTML:", err);
        return { error: "Erro ao analisar conteúdo da página" };
    }
}


document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const verifyButton = document.getElementById('verifyButton');
    const resultArea = document.getElementById('resultArea');
    const resultText = document.getElementById('resultText');

    let API_KEYS = {};

    fetch('api_key.json')
        .then(response => response.json())
        .then(json => {
            API_KEYS = json;
            verifyButton.disabled = false;
        })
        .catch(err => {
            console.error('Erro ao carregar as chaves da API:', err);
        });

    verifyButton.disabled = true;  // desabilita até carregar chave

    verifyButton.addEventListener('click', async function() {
        const urlToVerify = urlInput.value.trim();
        if (!urlToVerify) {
            alert('Por favor, insira uma URL para verificar.');
            return;
        }

        const conclusionText = document.getElementById('conclusionText');
        conclusionText.textContent = 'Verificando...';
        conclusionText.className = 'conclusion-loading';
        
        // Mostra o container de resultados
        document.getElementById('resultContainer').classList.remove('hidden');
    
        // Reseta todos os cards
        const allCards = document.querySelectorAll('.analysis-card');
        allCards.forEach(card => {
            card.querySelector('.status-text').textContent = 'Verificando...';
            card.querySelector('.status-text').className = 'status-text';
        });

        // Variáveis para armazenar os resultados
        let isPhishingSuspect = false;
        let phishingReasons = [];
        let safeReasons = [];

        // Contador de verificações que indicam phishing
        let phishingIndicators = 0;
        const thresholdForPhishing = 4; // Número mínimo de indicadores para considerar como phishing

        // Verificação da idade do domínio
        const domainAge = await checkDomainAge(urlToVerify, API_KEYS);
        const domainAgeCard = document.getElementById('domainAgeCard');
        if (domainAge.error) {
            phishingIndicators++;
            domainAgeCard.querySelector('.status-text').textContent = 'Erro na verificação';
            domainAgeCard.querySelector('.status-text').classList.add('unsafe');
        } else {
            const ageText = `${domainAge.ageInDays} dias (${domainAge.createdDate})`;
            if (domainAge.isSuspicious) {
                phishingIndicators++;
                domainAgeCard.querySelector('.status-text').textContent = `Suspeito: ${ageText}`;
                domainAgeCard.querySelector('.status-text').classList.add('unsafe');
            } else {
                domainAgeCard.querySelector('.status-text').textContent = `Seguro: ${ageText}`;
                domainAgeCard.querySelector('.status-text').classList.add('safe');
            }
        }

        // Verificação de redirecionamentos
        const redirectCheck = await checkRedirects(urlToVerify);
        const redirectsCard = document.getElementById('redirectsCard');
        if (redirectCheck.isSuspicious) {
            phishingIndicators++;
            redirectsCard.querySelector('.status-text').textContent = 'Redirecionamento suspeito';
            redirectsCard.querySelector('.status-text').classList.add('unsafe');
        } else {
            redirectsCard.querySelector('.status-text').textContent = 'Nenhum redirecionamento suspeito';
            redirectsCard.querySelector('.status-text').classList.add('safe');
        }

        // Verificação de caracteres especiais e substituição numérica
        const specialCharsCard = document.getElementById('specialCharsCard');
        const specialCharPattern = /["'<>@$&#%{}|\\^~\[\]`;]/;
        const domain = getDomainLabel(urlToVerify);
        const leetMap = { '0':'o', '1':'i', '3':'e', '4':'a', '5':'s', '7':'t' };
        const normalized = domain.replace(/[013457]/g, c => leetMap[c]);
    
        if (specialCharPattern.test(urlToVerify)) {
            phishingIndicators++;
            specialCharsCard.querySelector('.status-text').textContent = 'Caracteres suspeitos encontrados';
            specialCharsCard.querySelector('.status-text').classList.add('unsafe');
        } else if (normalized !== domain) {
            phishingIndicators++;
            specialCharsCard.querySelector('.status-text').textContent = `Substituição numérica detectada`;
            specialCharsCard.querySelector('.status-text').classList.add('unsafe');
        } else {
            specialCharsCard.querySelector('.status-text').textContent = 'Sem caracteres suspeitos';
            specialCharsCard.querySelector('.status-text').classList.add('safe');
        }

        // Verificação de similaridade com marcas conhecidas
        const levenshteinCard = document.getElementById('levenshteinCard');
        let brandSimilarity = false;
        for (const brand of TOP_100_BRANDS) {
            const distance = Levenshtein.get(domain, brand);
            if (distance <= LEVENSHTEIN_THRESHOLD && distance>0) {
                phishingIndicators++;
                brandSimilarity = true;
                levenshteinCard.querySelector('.status-text').textContent = `Similar a ${brand} (${distance})`;
                levenshteinCard.querySelector('.status-text').classList.add('unsafe');
                break;
            }
        }
        if (!brandSimilarity) {
            levenshteinCard.querySelector('.status-text').textContent = 'Sem similaridade suspeita';
            levenshteinCard.querySelector('.status-text').classList.add('safe');
        }

        // Verificação de DNS dinâmico
        const dnsCard = document.getElementById('dnsCard');
        try {
            const domainToCheck = new URL(urlToVerify).hostname;
            const dnsResponse = await fetch(`https://dns.google/resolve?name=${domainToCheck}&type=A`);
    
            if (!dnsResponse.ok) {
                throw new Error('Erro na resposta DNS');
            }
    
            const dnsData = await dnsResponse.json();
            if (dnsData.Answer && dnsData.Answer.length > 0 && dnsData.Answer[0].TTL) {
                let ttl = dnsData.Answer[0].TTL;
                if (ttl < TTL_THRESHOLD) {
                    phishingIndicators++;
                    dnsCard.querySelector('.status-text').textContent = `TTL baixo (${ttl}s)`;
                    dnsCard.querySelector('.status-text').classList.add('unsafe');
                } else {
                    dnsCard.querySelector('.status-text').textContent = `TTL normal (${ttl}s)`;
                    dnsCard.querySelector('.status-text').classList.add('safe');
                }
            } else if (dnsData.Status === 3) { // domínio não existe
                phishingIndicators++;
                dnsCard.querySelector('.status-text').textContent = 'Domínio não existe';
                dnsCard.querySelector('.status-text').classList.add('unsafe');
            } else {
                phishingIndicators++; // Considera erro na verificação como suspeito
                dnsCard.querySelector('.status-text').textContent = 'Erro na verificação DNS';
                dnsCard.querySelector('.status-text').classList.add('unsafe');
            }
        } catch (error) {
            phishingIndicators++; 
            dnsCard.querySelector('.status-text').textContent = 'Erro na verificação DNS';
            dnsCard.querySelector('.status-text').classList.add('unsafe');
        }

        // Verificação Safe Browsing API
        const safeBrowsingCard = document.getElementById('safeBrowsingCard');
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
                `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEYS.google}`,
                {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                }
            );
        
            if (!response.ok) throw new Error(`Erro na API: ${response.status}`);
        
            const data = await response.json();
            if (data.matches && data.matches.length) {
                phishingIndicators++;
                safeBrowsingCard.querySelector('.status-text').textContent = 'Listado como phishing';
                safeBrowsingCard.querySelector('.status-text').classList.add('unsafe');
            } else {
                safeBrowsingCard.querySelector('.status-text').textContent = 'Não listado';
                safeBrowsingCard.querySelector('.status-text').classList.add('safe');
            }
        } catch (err) {
            safeBrowsingCard.querySelector('.status-text').textContent = 'Erro na verificação';
        }

        // Verificação dos certificados SSL
        const sslCard = document.getElementById('sslCard');
        try {
            const domainToCheckSSL = new URL(urlToVerify).hostname;
            const sslInfo = await checkSSLCertificate(domainToCheckSSL, API_KEYS);
    
            if (sslInfo.error) {
                throw new Error(sslInfo.error);
            }
    
            if (!sslInfo) { // Se não retornou nenhuma informação
                phishingIndicators++;
                sslCard.querySelector('.status-text').textContent = 'Sem certificado válido';
                sslCard.querySelector('.status-text').classList.add('unsafe');
            } else {
                sslCard.querySelector('.status-text').textContent = `Nota: ${sslInfo}`;
                if (sslInfo === 'A' || sslInfo === 'A+') {
                    sslCard.querySelector('.status-text').classList.add('safe');
                } else {
                    phishingIndicators++;
                    sslCard.querySelector('.status-text').classList.add('unsafe');
                }
            }
        } catch (error) {
            phishingIndicators++; // Considera erro na verificação como suspeito
            sslCard.querySelector('.status-text').textContent = 'Erro na verificação SSL';
            sslCard.querySelector('.status-text').classList.add('unsafe');
        }

        // Verificação de formulários sensíveis
        const formsCard = document.getElementById('formsCard');
        const htmlAnalysis = await checkSensitiveForms(urlToVerify);
        if (htmlAnalysis.error) {
            formsCard.querySelector('.status-text').textContent = 'Erro na verificação';
        } else if (htmlAnalysis.isSuspicious) {
            phishingIndicators++;
            formsCard.querySelector('.status-text').textContent = 'Formulários suspeitos';
            formsCard.querySelector('.status-text').classList.add('unsafe');
        } else {
            formsCard.querySelector('.status-text').textContent = 'Nenhum formulário suspeito';
            formsCard.querySelector('.status-text').classList.add('safe');
        }

        // Exibe a conclusão geral baseada no número de indicadores
        if (phishingIndicators >= thresholdForPhishing) {
            conclusionText.textContent = `O site ${urlToVerify} provavelmente é phishing (${phishingIndicators}/8 indicadores)`;
            conclusionText.style.color = '#dc143c';
            conclusionText.style.backgroundColor = '#ffebee';
        } else {
            conclusionText.textContent = `O site ${urlToVerify} provavelmente não é phishing (${phishingIndicators}/8 indicadores)`;
            conclusionText.style.color = '#2e8b57';
            conclusionText.style.backgroundColor = '#e8f5e9';
        }
    });
});