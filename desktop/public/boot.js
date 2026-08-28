(() => {
  let cached;
  let background;
  let parsed;
  try {
    cached = window.localStorage.getItem("buzz-theme-cache");
    if (!cached) {
      if (window.matchMedia("(prefers-color-scheme: dark)").matches) {
        document.documentElement.classList.add("dark");
      } else {
        document.documentElement.classList.add("light");
        document.documentElement.style.backgroundColor = "#fff";
      }
      return;
    }
    parsed = JSON.parse(cached);
    background = parsed.vars["--background"];
    if (background) {
      document.documentElement.style.backgroundColor = `hsl(${background})`;
    }
    document.documentElement.classList.add(parsed.isDark ? "dark" : "light");
  } catch {
    // Keep the static boot background when the cached theme is unavailable.
  }
})();
