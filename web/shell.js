import { mountAppShell } from "./app-kit.js";

const header = document.querySelector(".app-header");
const footer = document.getElementById("app-footer");
const refresh = document.getElementById("refresh");
if (!(header instanceof HTMLElement) || !(footer instanceof HTMLElement) || !(refresh instanceof HTMLElement)) {
  throw new Error("The app shell is unavailable.");
}
const shell = mountAppShell({
  name: "FileVault",
  header,
  footer,
  sourceUrl: "https://github.com/jessfraz/ha-filevault",
  brand: [...header.querySelectorAll("#app-brand > img")],
  actions: [refresh],
});
shell.version.id = "app-version";
shell.status.id = "service-status";
// The controller can also be exercised without mounting the browser shell.
await import("./app.js");
