chrome.runtime.onInstalled.addListener(() => {
  console.log('Phishing Detector installed.');
  chrome.storage.local.set({
    totalScanned: 0,
    totalThreats: 0,
    scanHistory: []
  });
});