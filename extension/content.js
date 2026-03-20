console.log('Phishing Detector: Active on Gmail.');

const BACKEND = 'http://127.0.0.1:5000';
const scannedUrls = new Set();
let totalLinks = 0;
let totalThreats = 0;

// Extract links from opened email
function extractLinks() {
  const emailBody = document.querySelector('.a3s.aiL');
  if (!emailBody) return [];

  const anchors = emailBody.querySelectorAll('a');
  const urls = [];

  anchors.forEach(link => {
    const url = link.href;
    if (url &&
        url.startsWith('http') &&
        !url.includes('mail.google.com') &&
        !url.includes('google.com/') &&
        !scannedUrls.has(url)) {
      urls.push({ url, element: link });
    }
  });

  return urls;
}

// Add visual badge next to link
function addBadge(linkElement, threatLevel, probability) {
  const existing = linkElement.parentNode.querySelector('.phishing-badge');
  if (existing) existing.remove();

  const badge = document.createElement('span');
  badge.className = `phishing-badge phishing-${threatLevel.toLowerCase().replace('_','-')}`;

  const pct = Math.round(probability * 100);

  if (threatLevel === 'DANGEROUS')
    badge.textContent = `⚠ PHISHING ${pct}%`;
  else if (threatLevel === 'SUSPICIOUS')
    badge.textContent = `⚠ SUSPICIOUS ${pct}%`;
  else if (threatLevel === 'LOW_RISK')
    badge.textContent = `? LOW RISK ${pct}%`;
  else
    badge.textContent = `✓ SAFE`;

  badge.title = `Phishing probability: ${pct}%`;
  linkElement.parentNode.insertBefore(badge, linkElement.nextSibling);
}

// Send URL to backend
async function checkUrl(url, element) {
  try {
    const response = await fetch(`${BACKEND}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await response.json();

    addBadge(element, data.threat_level, data.probability);

    if (data.is_phishing) {
      totalThreats++;
      // Block dangerous links
      if (data.threat_level === 'DANGEROUS') {
        element.addEventListener('click', (e) => {
          e.preventDefault();
          alert(`⚠ BLOCKED: This link was detected as phishing (${Math.round(data.probability*100)}% confidence).\n\nURL: ${url}`);
        });
        element.style.textDecoration = 'line-through';
        element.style.color = '#ff4444';
      }
    }

    // Update storage
    chrome.storage.local.set({
      totalThreats,
      totalLinks
    });

  } catch (err) {
    console.log('Phishing Detector error:', err);
  }
}

// Scan all links in current email
async function scanEmail() {
  const links = extractLinks();
  if (links.length === 0) return;

  console.log(`Phishing Detector: Found ${links.length} links to scan.`);
  totalLinks += links.length;

  for (const { url, element } of links) {
    scannedUrls.add(url);
    await checkUrl(url, element);
    await new Promise(r => setTimeout(r, 100)); // small delay between requests
  }
}

// MutationObserver — detects when email opens
const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    if (mutation.addedNodes.length > 0) {
      const emailBody = document.querySelector('.a3s.aiL');
      if (emailBody) {
        setTimeout(scanEmail, 1000);
        break;
      }
    }
  }
});

observer.observe(document.body, {
  childList: true,
  subtree: true
});

// Initial scan on load
setTimeout(scanEmail, 3000);