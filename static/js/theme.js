const THEME_KEY = "budget_app_theme";

function applyTheme(theme) {
  // Put the theme on <body>, since CSS is watching body[data-theme=...]
  document.body.setAttribute("data-theme", theme);
}

// Run on script load (defer makes this safe once <body> exists)
(function initTheme() {
  const stored = localStorage.getItem(THEME_KEY);

  let theme;
  if (stored === "light" || stored === "dark") {
    theme = stored;
  } else if (
    window.matchMedia &&
    window.matchMedia("(prefers-color-scheme: dark)").matches
  ) {
    theme = "dark";
  } else {
    theme = "light";
  }

  applyTheme(theme);
})();

document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("theme-toggle");
  if (!toggle) return;

  const current = document.body.getAttribute("data-theme") || "light";
  toggle.textContent = current === "dark" ? "Light mode" : "Dark mode";

  toggle.addEventListener("click", () => {
    const current = document.body.getAttribute("data-theme") || "light";
    const next = current === "light" ? "dark" : "light";

    applyTheme(next);
    localStorage.setItem(THEME_KEY, next);
    toggle.textContent = next === "dark" ? "Light mode" : "Dark mode";
  });
});
