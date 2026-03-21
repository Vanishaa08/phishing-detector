console.log('Phishing Detector: Active on Gmail.');

const BACKEND = 'http://127.0.0.1:5000';
const scannedUrls = new Set();
let totalLinks = 0;
let totalThreats = 0;
let totalScanned = 0;

// Phishing keywords by category with weights
const PHISHING_KEYWORDS = {
  urgency: { words: ['urgent','immediately','within 24 hours','act now',
    'expires today','limited time','final notice','last chance'], weight: 3 },
  account: { words: ['verify your account','confirm your identity',
    'update your information','validate your','suspended','locked',
    'unusual activity','unauthorized access','login attempt'], weight: 4 },
  financial: { words: ['bank account','credit card','wire transfer',
    'payment required','invoice attached','refund','paypal',
    'western union','bitcoin'], weight: 3 },
  action: { words: ['click here','click the link','click below',
    'open attachment','download now','sign in immediately',
    'update now','verify now'], weight: 2 },
  threat: { words: ['will be suspended','will be terminated',
    'will be closed','legal action','law enforcement',
    'your account has been','security alert'], weight: 5 }
};

function analyzeEmailText(emailText) {
  const text = emailText.toLowerCase();
  let score = 0;
  const triggered = [];

  for (const [category, data] of Object.entries(PHISHING_KEYWORDS)) {
    for (const word of data.words) {
      if (text.includes(word)) {
        score += data.weight;
        triggered.push({ word, category, weight: data.weight });
      }
    }
  }

  return {
    score,
    triggered,
    risk: score >= 10 ? 'HIGH' : score >= 5 ? 'MEDIUM' : score >= 1 ? 'LOW' : 'NONE'
  };
}

function getEmailSender() {
  const sender = document.querySelector('.gD');
  return sender ? sender.getAttribute('email') || sender.textContent : '';
}

function isSuspiciousSender(email) {
  const domain = email.split('@')[1] || '';
  const suspicious = ['xyz','top','club','online','tk','ml','ga','cf'].some(
    t => domain.endsWith('.'+t));
  const freemail = ['gmail.com','yahoo.com','hotmail.com','outlook.com'];
  const pretendingOfficial = ['paypal','amazon','google','apple','microsoft',
    'bank','security','support','account'].some(b => 
    email.toLowerCase().includes(b) && freemail.some(f => domain === f));
  return suspicious || pretendingOfficial;
}

// Load existing stats
chrome.storage.local.get(['totalLinks','totalThreats','totalScanned'], (data) => {
  totalLinks = data.totalLinks || 0;
  totalThreats = data.totalThreats || 0;
  totalScanned = data.totalScanned || 0;
});

function getTooltipText(threatLevel, probability, url) {
  const pct = Math.round(probability * 100);
  const domain = (() => { try { return new URL(url).hostname; } catch { return url; }})();
  const reasons = [];
  if (!url.startsWith('https')) reasons.push('No HTTPS');
  if (/\d+\.\d+\.\d+\.\d+/.test(url)) reasons.push('Raw IP address');
  if (url.includes('@')) reasons.push('@ symbol in URL');
  if (['xyz','top','club','online','tk'].some(t => url.includes('.'+t))) reasons.push('Suspicious TLD');
  if (['login','verify','secure','update','confirm'].some(w => url.includes(w))) reasons.push('Phishing keywords');
  const reasonText = reasons.length > 0 ? `\nReasons: ${reasons.join(', ')}` : '';
  return `Domain: ${domain}\nRisk: ${threatLevel} (${pct}%)${reasonText}`;
}

function addBadge(linkElement, threatLevel, probability, url) {
  const existing = linkElement.parentNode.querySelector('.phishing-badge');
  if (existing) existing.remove();

  const badge = document.createElement('span');
  const level = threatLevel.toLowerCase().replace('_','-');
  badge.className = `phishing-badge phishing-${level}`;

  const pct = Math.round(probability * 100);
  if (threatLevel === 'DANGEROUS')       badge.textContent = `⚠ PHISHING ${pct}%`;
  else if (threatLevel === 'SUSPICIOUS') badge.textContent = `⚠ SUSPICIOUS ${pct}%`;
  else if (threatLevel === 'LOW_RISK')   badge.textContent = `? LOW RISK ${pct}%`;
  else                                   badge.textContent = `✓ SAFE`;

  // Tooltip
  const tooltip = document.createElement('span');
  tooltip.className = 'phishing-tooltip';
  tooltip.textContent = getTooltipText(threatLevel, probability, url);
  badge.appendChild(tooltip);
  linkElement.parentNode.insertBefore(badge, linkElement.nextSibling);

  // Block dangerous links
  if (threatLevel === 'DANGEROUS') {
    linkElement.classList.add('phishing-link-blocked');
    linkElement.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      alert(`⚠ BLOCKED by Phishing Detector\n\nURL: ${url}\nRisk: ${pct}% phishing probability\n\nThis link has been blocked to protect you.`);
    }, true);
  }
}

async function checkUrl(url, element, nlpScore = 0) {
  try {
    const response = await fetch(`${BACKEND}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!response.ok) return;
    const data = await response.json();

    // Hybrid score: ML probability + NLP boost
    let hybridProb = data.probability;
    if (nlpScore >= 10) hybridProb = Math.min(1, hybridProb + 0.15);
    else if (nlpScore >= 5) hybridProb = Math.min(1, hybridProb + 0.08);

    // Recalculate threat level from hybrid score
    let threatLevel;
    if (hybridProb >= 0.75)      threatLevel = 'DANGEROUS';
    else if (hybridProb >= 0.50) threatLevel = 'SUSPICIOUS';
    else if (hybridProb >= 0.35) threatLevel = 'LOW_RISK';
    else                         threatLevel = 'SAFE';

    addBadge(element, threatLevel, hybridProb, url);
    if (threatLevel !== 'SAFE') totalThreats++;
    chrome.storage.local.set({ totalLinks, totalThreats, totalScanned });

  } catch (err) {
    console.log('Phishing Detector: Backend unreachable.');
  }
}

async function scanEmail() {
  const emailBody = document.querySelector('.a3s.aiL');
  if (!emailBody) return;

  // NLP analysis on email body
  const emailText = emailBody.innerText || '';
  const nlpResult = analyzeEmailText(emailText);
  const sender = getEmailSender();
  const suspiciousSender = isSuspiciousSender(sender);

  if (nlpResult.risk !== 'NONE') {
    console.log(`Phishing Detector NLP: ${nlpResult.risk} risk. Score: ${nlpResult.score}`);
    console.log('Triggered keywords:', nlpResult.triggered.map(t => t.word));
  }

  if (suspiciousSender) {
    console.log(`Phishing Detector: Suspicious sender detected: ${sender}`);
  }

  // Show email-level warning if NLP score is high
  if (nlpResult.risk === 'HIGH' || suspiciousSender) {
    const existing = document.querySelector('.phishing-email-warning');
    if (!existing) {
      const warning = document.createElement('div');
      warning.className = 'phishing-email-warning';
      warning.style.cssText = `
        background: #fff3cd; border: 1px solid #ffc107;
        border-radius: 6px; padding: 10px 14px; margin: 8px 0;
        font-size: 13px; color: #856404; font-family: Arial, sans-serif;
      `;
      const reasons = [];
      if (nlpResult.risk === 'HIGH') reasons.push(`phishing keywords detected (score: ${nlpResult.score})`);
      if (suspiciousSender) reasons.push(`suspicious sender: ${sender}`);
      warning.innerHTML = `⚠ <strong>Email Warning:</strong> This email may be phishing. Reasons: ${reasons.join(', ')}`;
      emailBody.parentNode.insertBefore(warning, emailBody);
    }
  }

  // URL scanning
  const anchors = emailBody.querySelectorAll('a');
  const toScan = [];

  anchors.forEach(link => {
    const url = link.href;
    if (
      url &&
      url.startsWith('http') &&
      !url.includes('mail.google.com') &&
      !scannedUrls.has(url)
    ) {
      scannedUrls.add(url);
      toScan.push({ url, element: link });
    }
  });

  if (toScan.length === 0) return;
  console.log(`Phishing Detector: Scanning ${toScan.length} links...`);

  totalLinks += toScan.length;
  totalScanned++;
  chrome.storage.local.set({ totalLinks, totalThreats, totalScanned });

  for (const { url, element } of toScan) {
    await checkUrl(url, element, nlpResult.score);
    await new Promise(r => setTimeout(r, 150));
  }
}

// MutationObserver
const observer = new MutationObserver(() => {
  if (document.querySelector('.a3s.aiL')) {
    setTimeout(scanEmail, 1000);
  }
});
observer.observe(document.body, { childList: true, subtree: true });
setTimeout(scanEmail, 3000);