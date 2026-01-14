(function () {
  const btn = document.getElementById("theme-toggle");

  function setTheme(theme) {
    document.body.setAttribute("data-theme", theme);
    btn.textContent = theme === "dark" ? "Light mode" : "Dark mode";
  }

  const current = document.body.getAttribute("data-theme") || "dark";
  setTheme(current);

  btn.addEventListener("click", () => {
    const now = document.body.getAttribute("data-theme") || "dark";
    const next = now === "dark" ? "light" : "dark";
    setTheme(next);
  });
})();
