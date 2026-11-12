const form = document.getElementById("scan-form");
const input = document.getElementById("domain");
const button = document.getElementById("scan-button");
const loading = document.getElementById("loading");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");

function setText(id, value) {
  document.getElementById(id).textContent = value ?? "Not provided";
}
function showError(message) {
  errorBox.textContent = message;
  errorBox.classList.remove("hidden");
  results.classList.add("hidden");
}
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.classList.add("hidden");
  results.classList.add("hidden");
  loading.classList.remove("hidden");
  button.disabled = true;
  button.querySelector(".button-text").textContent = "Checking…";

  try {
    const response = await fetch("/api/check", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({domain: input.value})
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) throw new Error(payload.error || "The check failed.");
    const r = payload.result;

    setText("result-domain", r.domain);
    setText("days", r.days_remaining < 0 ? `${Math.abs(r.days_remaining)} days ago` : `${r.days_remaining} days`);
    setText("tls", r.tls_version);
    setText("verified", r.domain_verified ? "Match" : "Not verified");
    setText("issuer", r.issuer);
    setText("subject", r.subject);
    setText("valid-from", r.valid_from);
    setText("expiry", r.expiry_date);
    setText("cipher", `${r.cipher_suite} (${r.cipher_bits ?? "?"} bits)`);
    const sans = Array.isArray(r.subject_alt_names) ? r.subject_alt_names : [];
    const sanCount = Number.isInteger(r.subject_alt_names_count)
      ? r.subject_alt_names_count
      : sans.length;
    setText("sans", sans.length ? `${sans.join(", ")} (${sanCount} total)` : "Not provided");

    const pill = document.getElementById("status-pill");
    pill.textContent = r.status.toUpperCase();
    pill.className = `status-pill ${r.severity}`;
    const warning = document.getElementById("warning");
    warning.textContent = r.warning;
    warning.className = `warning ${r.severity}`;
    results.classList.remove("hidden");
    results.scrollIntoView({behavior: "smooth", block: "nearest"});
  } catch (err) {
    showError(err.message || "Something went wrong. Please try again.");
  } finally {
    loading.classList.add("hidden");
    button.disabled = false;
    button.querySelector(".button-text").textContent = "Check certificate";
  }
});
