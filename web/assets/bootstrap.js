const status = document.querySelector("#status");
const build = document.querySelector("#build");
const productVersion = document.querySelector("#product-version");
const redfishVersion = document.querySelector("#redfish-version");

try {
  const response = await fetch("/api/v1/about", {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) throw new Error("metadata unavailable");
  const about = await response.json();
  productVersion.textContent = about.product_version;
  redfishVersion.textContent = about.nv_redfish_baseline;
  build.hidden = false;
  status.textContent = "The embedded console is ready.";
} catch {
  status.textContent = "The local console could not load product metadata.";
}
