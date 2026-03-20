chrome.storage.local.get(['totalScanned','totalThreats','totalLinks'], (data) => {
  document.getElementById('scanned').textContent = data.totalScanned || 0;
  document.getElementById('threats').textContent = data.totalThreats || 0;
  document.getElementById('links').textContent = data.totalLinks || 0;
});


