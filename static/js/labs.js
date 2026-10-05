// CRYPTO-NET — shared lab helpers.
// All labs are forms that POST JSON and render the response in a <pre>.

async function runLab(formEl, endpoint, outputEl, payloadBuilder) {
    outputEl.textContent = "Running…";
    try {
        const payload = payloadBuilder ? payloadBuilder(formEl) : {};
        const res = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        outputEl.textContent = JSON.stringify(data, null, 2);
    } catch (err) {
        outputEl.textContent = "Error: " + err;
    }
}

window.runLab = runLab;
