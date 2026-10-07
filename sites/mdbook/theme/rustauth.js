/* Auto follows the OS. The named themes stay on mdBook's own classes. */
(function () {
    const root = document.documentElement;

    function sync() {
        let saved = null;
        try {
            saved = localStorage.getItem("mdbook-theme");
        } catch {
            saved = null;
        }
        const auto = saved === null || saved === "default_theme";
        root.classList.toggle("rustauth", auto);
    }

    sync();
    document.getElementById("mdbook-theme-list")?.addEventListener("click", function () {
        setTimeout(sync, 0);
    });
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", function () {
        setTimeout(sync, 0);
    });
})();
