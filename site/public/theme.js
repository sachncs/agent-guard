(() => {
  const storageKey = "agentguard-theme";
  const root = document.documentElement;
  const colorMeta = document.querySelector('meta[name="theme-color"]');
  const media = window.matchMedia("(prefers-color-scheme: dark)");
  const readPreference = () => {
    try {
      const value = localStorage.getItem(storageKey);
      return value === "light" || value === "dark" ? value : null;
    } catch {
      return null;
    }
  };
  let preference = readPreference();

  const apply = (theme) => {
    root.dataset.theme = theme;
    root.classList.toggle("dark", theme === "dark");
    if (colorMeta) colorMeta.content = theme === "dark" ? "#101716" : "#f7faf8";
    const toggle = document.querySelector("[data-theme-toggle]");
    if (toggle) {
      toggle.setAttribute("aria-label", `Switch to ${theme === "dark" ? "light" : "dark"} mode`);
      toggle.setAttribute("aria-pressed", String(theme === "dark"));
    }
  };

  apply(preference ?? (media.matches ? "dark" : "light"));
  document.addEventListener("DOMContentLoaded", () => apply(root.dataset.theme));
  media.addEventListener("change", (event) => {
    preference = readPreference();
    if (!preference) apply(event.matches ? "dark" : "light");
  });
  document.addEventListener("click", (event) => {
    const toggle = event.target?.closest?.("[data-theme-toggle]");
    if (!toggle) return;
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    apply(next);
    preference = next;
    try {
      localStorage.setItem(storageKey, next);
    } catch {
      // The selected theme still applies for this page when storage is blocked.
    }
  });
})();
