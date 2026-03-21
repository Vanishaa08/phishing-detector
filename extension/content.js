console.log('Phishing Detector: Active on Gmail.');

const BACKEND = 'http://127.0.0.1:5000';
const scannedUrls = new Set();
let totalLinks = 0;
let totalThreats = 0;
let totalScanned = 0;

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

async function checkUrl(url, element) {
  try {
    const response = await fetch(`${BACKEND}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    if (!response.ok) return;
    const data = await response.json();
    addBadge(element, data.threat_level, data.probability, url);
    if (data.is_phishing) totalThreats++;
    chrome.storage.local.set({ totalLinks, totalThreats, totalScanned });
  } catch (err) {
    console.log('Phishing Detector: Backend unreachable.');
  }
}

async function scanEmail() {
  const emailBody = document.querySelector('.a3s.aiL');
  if (!emailBody) return;

  const anchors = emailBody.querySelectorAll('a');
  const toScan = [];

  anchors.forEach(link => {
    const url = link.href;
    if (url &&
        url.startsWith('http') &&
        !url.includes('mail.google.com') &&
        !scannedUrls.has(url)) {
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
    await checkUrl(url, element);
    await new Promise(r => setTimeout(r, 150));
  }
  console.log(`Phishing Detector: Scan complete. Threats: ${totalThreats}`);
}

// MutationObserver
const observer = new MutationObserver(() => {
  if (document.querySelector('.a3s.aiL')) {
    setTimeout(scanEmail, 1000);
  }
});
observer.observe(document.body, { childList: true, subtree: true });
setTimeout(scanEmail, 3000);