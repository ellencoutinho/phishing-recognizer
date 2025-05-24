# Verificador de URLs Suspeitas de Phishing

Uma página web simples desenvolvida com **HTML**, **CSS** e **JavaScript** que permite ao usuário inserir uma URL e submetê-la para análise. O sistema então realiza diversas verificações para determinar se a URL pode ser considerada suspeita de phishing e exibe os resultados de forma clara.

## 🔍 Funcionalidades

Ao submeter uma URL, o sistema verifica os seguintes critérios:

- ✅ **Google Safe Browsing API**  
  Verifica se a URL aparece em listas de domínios maliciosos conhecidas.

- 🔠 **Similaridade com marcas famosas**  
  Compara a URL com os domínios das [100 maiores marcas globais](https://interbrand.com/best-global-brands/) usando **distância de Levenshtein**.

- 🔢 **Uso de substituições numéricas e caracteres especiais**  
  Detecta padrões como “g00gle” ou “amaz0n” e a presença de símbolos suspeitos na URL.

- 🌐 **DNS dinâmico (TTL baixo)**  
  Analisa o TTL dos registros DNS para detectar domínios frequentemente alterados.

- 📅 **Idade do domínio**  
  Verifica a data de criação do domínio usando a [API WHOIS](https://apilayer.com/marketplace/whois-api#documentation-tab).

- 🔐 **Certificados SSL**  
  Consulta a [SSL Labs](https://www.ssllabs.com/) para verificar a nota geral do certificado de segurança do domínio.

- 🔁 **Redirecionamentos automáticos**  
  Detecta se a URL redireciona automaticamente para outros domínios ou páginas.

- 🔓 **Formulários sensíveis na página**  
  Verifica o HTML da página em busca de formulários de login, campos de senha ou termos sensíveis como "senha", "cvv", etc.

## 📦 Estrutura dos Arquivos

- `index.html` — Estrutura da página
- `style.css` — Estilos visuais
- `script.js` — Lógica de verificação e integração com APIs
- `constants.js` — Contém variáveis e listas auxiliares
- `api_key.json` — Arquivo JSON com chaves das APIs (não versionado publicamente)

## 📋 Observações

- Certifique-se de possuir as chaves de API válidas para:
  - **Google Safe Browsing**
  - **WHOIS (apilayer)**

- Desenvolvido como parte de um projeto acadêmico do curso de Engenharia de Computação.