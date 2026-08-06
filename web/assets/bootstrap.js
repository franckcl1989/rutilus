import init from "/rutilus_ui.js";

try {
  await init();
} catch {
  document.querySelector("#app")?.remove();

  const main = document.createElement("main");
  main.id = "app";
  main.setAttribute("aria-live", "polite");

  const shell = document.createElement("section");
  shell.className = "shell";

  const eyebrow = document.createElement("p");
  eyebrow.className = "eyebrow";
  eyebrow.textContent = "Local Redfish management";

  const heading = document.createElement("h1");
  heading.textContent = "Rutilus";

  const status = document.createElement("p");
  status.id = "status";
  status.textContent = "The embedded console could not start.";

  shell.append(eyebrow, heading, status);
  main.append(shell);
  document.body.prepend(main);
}
