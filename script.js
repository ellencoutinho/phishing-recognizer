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
            resultArea.classList.add('hidden');
            return;
        }

        resultText.textContent = 'Verificando...';
        resultArea.classList.remove('hidden');

        let isPhishingSuspect = false;
        let phishingReason = '';

        // Verificação da idade do domínio
        const domainAge = await checkDomainAge(urlToVerify, API_KEYS);
        if (!domainAge.error && domainAge.isSuspicious) {
            phishingReason += `⚠️ Domínio suspeito: criado há ${domainAge.ageInDays} dias (${domainAge.createdDate})`;
        }

        // Verificação de redirecionamentos suspeitos
        const redirectCheck = await checkRedirects(urlToVerify);
        if (redirectCheck.isSuspicious) {
            isPhishingSuspect = true;
            phishingReason += redirectCheck.message + ' ';
        }

        // Verificação de caracteres especiais
        const specialCharPattern = /["'<>@$&#%{}|\\^~\[\]`;]/;
        if (specialCharPattern.test(urlToVerify)) {
            isPhishingSuspect = true;
            phishingReason += `A URL contém caracteres especiais suspeitos. `;
        }

        // Verificação de substituição numérica
        const domain = getDomainLabel(urlToVerify);
        const leetMap = { '0':'o', '1':'i', '3':'e', '4':'a', '5':'s', '7':'t' };
        const normalized = domain.replace(/[013457]/g, c => leetMap[c]);
        if (normalized !== domain) {
            isPhishingSuspect = true;
            phishingReason += `Possível substituição numérica no domínio ("${domain}" → "${normalized}"). `;
        }

        // Verificação de similaridade com marcas conhecidas (Levenshtein)
        for (const brand of TOP_100_BRANDS) {
            const distance = Levenshtein.get(domain, brand);
            
            if (distance <= LEVENSHTEIN_THRESHOLD && distance>0) {
                isPhishingSuspect = true;
                phishingReason += `O domínio "${domain}" é similar à marca conhecida "${brand}" (distância de Levenshtein: ${distance}). `;
                break; // Se encontrar uma similaridade, para de verificar
            }
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
                `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEYS.google}`,
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

        // Verificação dos certificados SSL
        const domainToCheck = new URL(urlToVerify).hostname;
        sslInfo = await checkSSLCertificate(domainToCheck, API_KEYS);
        if (!sslInfo.error) {
            phishingReason += `O certificado SSL está avaliado como ${sslInfo}`;
        }

        // Verificação de formulários sensíveis
        const htmlAnalysis = await checkSensitiveForms(urlToVerify);
        if (htmlAnalysis.isSuspicious) {
            isPhishingSuspect = true;
            phishingReason += `Formulários suspeitos ou campos sensíveis detectados na página (palavras-chave: ${htmlAnalysis.detectedKeywords.join(', ') || 'nenhuma'}). `;
        }

        
        if (isPhishingSuspect) {
            resultText.textContent = `A URL "${urlToVerify}" foi identificada como suspeita de phishing devido a: ${phishingReason.trim()}`;
        } else {
            resultText.textContent = `A URL "${urlToVerify}" parece segura (com base nas verificações realizadas).`;
        }
    });
});