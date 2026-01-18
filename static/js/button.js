document.getElementById('smartBackButton').addEventListener('click', () => {
  if (document.referrer && window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = '/budget';
  }
});