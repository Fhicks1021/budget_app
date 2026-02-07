document.addEventListener("DOMContentLoaded", () => {
  const el = document.getElementById("lockout-timer");
  if (!el) return;

  let ttl = parseInt(el.dataset.ttl, 10);
  if (isNaN(ttl) || ttl <= 0) {
    el.textContent = "0";
    return;
  }

  el.textContent = ttl.toString();

  const interval = setInterval(() => {
    ttl -= 1;

    if (ttl <= 0) {
      clearInterval(interval);
      el.textContent = "0";
      window.location.href = "/login";
      return;
    }

    el.textContent = ttl.toString();
  }, 1000);
});
