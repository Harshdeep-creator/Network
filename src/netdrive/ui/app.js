const screens = document.querySelectorAll(".screen");
const rail = document.querySelectorAll(".rail button");
let strings = {};
let language = "en";
let latestFiles = [];

rail.forEach((button) => {
  button.addEventListener("click", () => {
    rail.forEach((item) => item.classList.remove("current"));
    button.classList.add("current");
    screens.forEach((screen) => screen.classList.toggle("on", screen.id === button.dataset.screen));
  });
});

async function loadStrings(lang) {
  language = lang;
  const response = await fetch(lang === "hi" ? "/strings_hi.json" : "/strings_en.json");
  strings = await response.json();
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    const key = node.dataset.i18n;
    if (strings[key]) node.textContent = strings[key];
  });
}

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

function showText(id, text) {
  const node = document.getElementById(id);
  node.textContent = text || "";
  node.hidden = !text;
}

function render(state) {
  document.getElementById("status").textContent = state.status || "";
  const compare = (state.incoming && state.incoming.code) || state.sendCode || state.visibleCode || "";
  const banner = document.getElementById("compare");
  banner.hidden = !compare;
  banner.textContent = compare ? `Verification code: ${compare}` : "";
  if (state.incoming && document.querySelector(".screen.on")?.id !== "receive") {
    document.querySelector('[data-screen="receive"]').click();
  }
  document.getElementById("listen").textContent = state.listen || "";
  const peers = state.peers || [];
  document.getElementById("emptyPeers").hidden = peers.length > 0;
  document.getElementById("peers").innerHTML = peers.map((peer) =>
    `<tr><td>${esc(peer.nick)}</td><td class="mono">${esc(peer.ip)}:${esc(peer.port)}</td><td>${esc(peer.via)}</td><td>${esc(peer.seen)}</td><td><button type="button" class="plain" data-to="${esc(peer.ip)}:${esc(peer.port)}">${esc(strings.verify || "Verify")}</button></td></tr>`
  ).join("");
  document.querySelectorAll("[data-to]").forEach((button) => {
    button.addEventListener("click", () => {
      document.getElementById("address").value = button.dataset.to;
      document.querySelector('[data-screen="send"]').click();
    });
  });
  const offer = state.incoming;
  document.getElementById("waiting").hidden = Boolean(offer);
  document.getElementById("offer").hidden = !offer;
  if (offer) {
    document.getElementById("offerSeconds").textContent = `${offer.seconds ?? 60} seconds left.`;
    document.getElementById("offerCode").textContent = offer.code || "";
    document.getElementById("offerText").textContent = offer.summary || "";
    const danger = Boolean(offer.dangerous);
    document.getElementById("danger").hidden = !danger;
    document.getElementById("dangerBox").hidden = !danger;
    document.getElementById("acceptBtn").disabled = danger && !document.getElementById("dangerOk").checked;
  }
  showText("sendCode", state.sendCode || "");
  document.getElementById("sendProgress").textContent = state.progress || "";
  const history = state.history || [];
  document.getElementById("emptyHistory").hidden = history.length > 0;
  document.getElementById("historyRows").innerHTML = history.map((row, index) =>
    `<tr><td>${esc(row.name)}</td><td class="mono">${esc(row.size)}</td><td>${esc(row.result)}</td><td class="mono">${esc(row.time)}</td><td><button type="button" data-del="${index}" class="plain">${esc(strings.delete || "Delete")}</button></td></tr>`
  ).join("");
  document.querySelectorAll("[data-del]").forEach((button) => {
    button.addEventListener("click", () => post("/api/history/delete", { index: Number(button.dataset.del) }));
  });
  if (state.settings) {
    setIdle("nick", state.settings.nick || "");
    setIdle("folderPath", state.settings.directory || "");
    setIdle("maxSize", state.settings.maxSize || "");
    setIdle("autoLimit", state.settings.autoLimit || 10485760);
    if (document.activeElement !== document.getElementById("visibility")) {
      document.getElementById("visibility").value = state.settings.visibility || "Everyone";
    }
    if (document.activeElement !== document.getElementById("language")) {
      document.getElementById("language").value = state.settings.language || "en";
    }
    document.getElementById("relay").checked = Boolean(state.settings.relay);
    document.getElementById("auto").checked = Boolean(state.settings.auto);
    if (state.settings.language && state.settings.language !== language) {
      loadStrings(state.settings.language);
    }
  }
  const qr = state.contactQr || {};
  const left = Number(qr.seconds || 0);
  const timer = left > 0 ? "Same Wi-Fi. The picture opens a normal web page." : "Show a new QR from Settings.";
  document.getElementById("settingsTimer").textContent = timer;
  const shared = state.files || [];
  latestFiles = shared;
  paintShares("shareList", shared);
  paintShares("sendShares", [...shared].reverse());
  const base = shared[0];
  if (base) {
    document.getElementById("receiveFileQr").src = `/api/share/${base.id}.png`;
    document.getElementById("receiveFileName").textContent = base.name;
    setLink("receiveFileUri", base.url);
    const actions = document.getElementById("receiveShare");
    if (actions && !actions.contains(document.activeElement)) {
      actions.innerHTML = shareActions(base);
    }
  }
  setLink("contactUri", qr.uri || "");
  if (qr.stamp && document.getElementById("settingsQr").dataset.stamp !== String(qr.stamp)) {
    document.getElementById("settingsQr").src = `/api/contact/qr.png?t=${qr.stamp}`;
    document.getElementById("settingsQr").dataset.stamp = String(qr.stamp);
  }
  document.getElementById("contactList").innerHTML = (state.contacts || []).map((row) => `<li>${esc(row.nick)}</li>`).join("");
  const pick = document.getElementById("contactPick");
  if (pick && document.activeElement !== pick) {
    const current = pick.value;
    pick.innerHTML = `<option value="">${esc(strings.ephemeral || "No saved contact")}</option>` + (state.contacts || []).map((row) => `<option>${esc(row.nick)}</option>`).join("");
    pick.value = [...pick.options].some((option) => option.value === current) ? current : "";
  }
  const web = state.web || {};
  document.getElementById("webQr").hidden = !web.ready;
  if (web.ready) document.getElementById("webQr").src = `/api/web/qr.png?t=${encodeURIComponent(web.url)}`;
  showText("webCode", web.code || "");
  document.getElementById("webUrl").textContent = web.url || "";
}

function setLink(id, uri) {
  const node = document.getElementById(id);
  node.innerHTML = uri ? `<a href="${esc(uri)}">${esc(uri)}</a>` : "";
}

function setIdle(id, value) {
  const node = document.getElementById(id);
  if (document.activeElement !== node) node.value = value;
}

async function post(url, body) {
  await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  tick();
}

async function tick() {
  const response = await fetch("/api/state");
  render(await response.json());
}

document.getElementById("declineBtn").addEventListener("click", () => post("/api/decision", { accept: false }));
document.getElementById("acceptBtn").addEventListener("click", () => post("/api/decision", { accept: true, danger_ok: document.getElementById("dangerOk").checked }));
document.getElementById("dangerOk").addEventListener("change", tick);
document.getElementById("demoBtn").addEventListener("click", () => post("/api/demo", {}));
document.getElementById("clearBtn").addEventListener("click", () => post("/api/history/clear", {}));
document.getElementById("saveBtn").addEventListener("click", () => post("/api/settings", {
  nick: document.getElementById("nick").value,
  maxSize: Number(document.getElementById("maxSize").value),
  visibility: document.getElementById("visibility").value,
  language: document.getElementById("language").value,
  relay: document.getElementById("relay").checked,
  auto: document.getElementById("auto").checked,
  autoLimit: Number(document.getElementById("autoLimit").value),
}));
async function chosenFiles() {
  const picked = [...document.getElementById("file").files, ...document.getElementById("folder").files];
  const files = [];
  for (const file of picked) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    files.push({ name: file.webkitRelativePath || file.name, b64: btoa(binary) });
  }
  return files;
}
document.getElementById("cancelSend").addEventListener("click", () => post("/api/send/cancel", {}));
document.getElementById("shareFile").addEventListener("change", async () => {
  const file = document.getElementById("shareFile").files[0];
  if (!file) return;
  await shareOne(file);
  document.getElementById("shareFile").value = "";
  tick();
});
document.getElementById("meshBtn").addEventListener("click", () => post("/api/mesh", {}));
async function shareOne(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
  const response = await fetch("/api/share", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      name: file.name,
      b64: btoa(binary),
      limit: Number(document.getElementById("shareLimit").value) || 10000,
    }),
  });
  const body = await response.json();
  return body.file;
}

function shareKey(files) {
  return files.map((file) => [file.id, file.downloads, file.limit, file.url, file.name].join(":")).join("|");
}

function paintShares(id, files) {
  const box = document.getElementById(id);
  if (!box) return;
  const key = shareKey(files);
  if (box.dataset.key === key || box.contains(document.activeElement)) return;
  box.dataset.key = key;
  box.innerHTML = files.map((file) => shareCard(file)).join("");
}

function shareActions(file) {
  const used = Number(file.downloads || 0);
  const limit = Number(file.limit || 10000);
  return `<p class="mono">${esc(strings.noExpire || "This QR does not expire.")} ${used} / ${limit}</p>
    <label><span>${esc(strings.downloadLimit || "Download limit")}</span>
      <input data-limit="${esc(file.id)}" type="number" min="1" max="1000000" value="${limit}">
    </label>
    <p class="actions">
      <button type="button" class="action" data-share="${esc(file.id)}">${esc(strings.shareWa || "Share on WhatsApp")}</button>
      <button type="button" class="plain" data-saveqr="${esc(file.id)}">${esc(strings.saveQr || "Save QR picture")}</button>
    </p>`;
}

function shareCard(file) {
  return `<figure class="qr-card"><img class="qr" alt="${esc(file.name)}" src="/api/share/${esc(file.id)}.png"><figcaption>Scan this. It opens ${esc(file.name)}</figcaption><p class="offer"><a href="${esc(file.url)}">${esc(file.url)}</a></p>${shareActions(file)}</figure>`;
}

function fileById(id) {
  return latestFiles.find((file) => file.id === id);
}

async function shareOnWhatsApp(file) {
  const text = `${file.name}\n${file.url}`;
  const imageUrl = `/api/share/${file.id}.png`;
  if (navigator.share) {
    try {
      const response = await fetch(imageUrl);
      const blob = await response.blob();
      const image = new File([blob], `${file.name}-qr.png`, { type: "image/png" });
      if (navigator.canShare && navigator.canShare({ files: [image] })) {
        await navigator.share({ files: [image], text, title: file.name });
        return;
      }
      await navigator.share({ text, url: file.url, title: file.name });
      return;
    } catch (error) {
      if (error && error.name === "AbortError") return;
    }
  }
  window.open(`https://wa.me/?text=${encodeURIComponent(text)}`, "_blank", "noopener");
}

function saveQr(file) {
  const link = document.createElement("a");
  link.href = `/api/share/${file.id}.png`;
  link.download = `${file.name}-qr.png`;
  link.click();
}

document.getElementById("shareBtn").addEventListener("click", async () => {
  const picked = [...document.getElementById("file").files];
  const box = document.getElementById("sendShares");
  if (!picked.length) {
    document.getElementById("status").textContent = "Choose a file, then press Share.";
    return;
  }
  box.innerHTML = "";
  for (const file of picked) await shareOne(file);
  tick();
});
document.getElementById("sendBtn").addEventListener("click", async () => {
  const address = document.getElementById("address").value;
  const files = await chosenFiles();
  if (!files.length || !address) return;
  await post("/api/send", { to: address, files, contact: document.getElementById("contactPick").value });
});
document.getElementById("webBtn").addEventListener("click", async () => {
  const files = await chosenFiles();
  if (!files.length) return;
  await post("/api/web", { name: files[0].name, b64: files[0].b64 });
});
document.getElementById("webApprove").addEventListener("click", () => post("/api/web/approve", {}));

if (localStorage.getItem("netdrive-onboarded") !== "1") {
  screens.forEach((screen) => screen.classList.toggle("on", screen.id === "onboard"));
  rail.forEach((item) => item.classList.remove("current"));
}
document.getElementById("toStep2").addEventListener("click", () => {
  document.getElementById("step1").hidden = true;
  document.getElementById("step2").hidden = false;
});
document.getElementById("toStep3").addEventListener("click", () => {
  document.getElementById("step2").hidden = true;
  document.getElementById("step3").hidden = false;
});
document.getElementById("finishOnboard").addEventListener("click", async () => {
  const nick = document.getElementById("onboardNick").value || "netdrive";
  await post("/api/settings", { nick, language: "en", visibility: "Everyone", maxSize: 4294967296, relay: false, auto: false });
  localStorage.setItem("netdrive-onboarded", "1");
  document.querySelector('[data-screen="receive"]').click();
});
document.getElementById("contactShow").addEventListener("click", async () => {
  const response = await fetch("/api/contact/show", { method: "POST", body: "{}" });
  const body = await response.json();
  document.getElementById("contactUri").textContent = body.uri || "";
});
document.getElementById("contactAdd").addEventListener("click", () => post("/api/contact/add", {
  link: document.getElementById("contactIn").value,
  nick: document.getElementById("contactNick").value || "Contact",
}));

document.body.addEventListener("click", (event) => {
  const share = event.target.closest("[data-share]");
  const save = event.target.closest("[data-saveqr]");
  const file = fileById((share || save || {}).dataset ? (share || save).dataset.share || (share || save).dataset.saveqr : "");
  if (share && file) shareOnWhatsApp(file);
  if (save && file) saveQr(file);
});
document.body.addEventListener("change", (event) => {
  if (!event.target.matches("[data-limit]")) return;
  post("/api/share/limit", { id: event.target.dataset.limit, limit: Number(event.target.value) || 10000 });
});

loadStrings("en").then(tick);
setInterval(tick, 1000);
