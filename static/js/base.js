// CRYPTO-NET — shared frontend helpers.

// Small wrapper around fetch that always sends cookies and parses JSON
// safely. Never sends credentials to third-party origins.
async function cnFetch(url, options = {}) {
    const opts = Object.assign(
        {
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
        },
        options,
    );
    if (opts.body && typeof opts.body !== "string") {
        opts.body = JSON.stringify(opts.body);
    }
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (_e) { /* not JSON */ }
    return { ok: res.ok, status: res.status, data };
}

// Auto-dismiss flash messages after 6 seconds.
document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".flash").forEach((el) => {
        setTimeout(() => {
            el.style.transition = "opacity 0.4s ease";
            el.style.opacity = "0";
            setTimeout(() => el.remove(), 400);
        }, 6000);
    });
});

// Expose globally for later phases.
window.cnFetch = cnFetch;
