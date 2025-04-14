// @ts-check

import {
  parseFirmware,
  reproduceMrtd,
  bytesToHex,
  reproduceRtmr,
} from "./reproduce.mjs";

const el = {
  firmwareFile: /** @type {HTMLInputElement} */ (
    document.getElementById("firmware-file")
  ),
  firmwareError: /** @type {HTMLInputElement} */ (
    document.getElementById("firmware-error")
  ),
  ram: /** @type {HTMLInputElement} */ (document.getElementById("ram")),
  hardwareConfiguration: /** @type {HTMLSelectElement} */ (
    document.getElementById("hardware-configuration")
  ),
  acpi: /** @type {HTMLInputElement} */ (document.getElementById("acpi")),
  payloadType: /** @type {HTMLSelectElement} */ (
    document.getElementById("payload-type")
  ),
  softwareError: /** @type {HTMLSelectElement} */ (
    document.getElementById("software-error")
  ),
  uki: /** @type {HTMLInputElement} */ (document.getElementById("uki")),
  kernel: /** @type {HTMLInputElement} */ (document.getElementById("kernel")),
  initrd: /** @type {HTMLInputElement} */ (document.getElementById("initrd")),
  cmdline: /** @type {HTMLInputElement} */ (document.getElementById("cmdline")),
  firmwareFileBlock: /** @type {HTMLElement} */ (
    document.getElementById("firmware-file-field")
  ),
  downloadHardwareFiles: /** @type {HTMLElement} */ (
    document.getElementById("download-hardware-files")
  ),
  downloadAcpiTables: /** @type {HTMLAnchorElement} */ (
    document.getElementById("download-acpi-tables")
  ),
  downloadLibvirtXml: /** @type {HTMLAnchorElement} */ (
    document.getElementById("download-libvirt-xml")
  ),
  acpiBlock: /** @type {HTMLElement} */ (document.getElementById("acpi-field")),
  ukiBlock: /** @type {HTMLElement} */ (document.getElementById("uki-field")),
  kernelBlock: /** @type {HTMLElement} */ (
    document.getElementById("kernel-field")
  ),
  initrdBlock: /** @type {HTMLElement} */ (
    document.getElementById("initrd-field")
  ),
  cmdlineBlock: /** @type {HTMLElement} */ (
    document.getElementById("cmdline-field")
  ),
  mrtd: /** @type {HTMLElement} */ (document.getElementById("mrtd")),
  mrtdNone: /** @type {HTMLElement} */ (document.getElementById("mrtd-none")),
  rtmrNone: /** @type {HTMLElement} */ (document.getElementById("rtmr-none")),
  rtmrRegisters: /** @type {HTMLElement} */ (
    document.getElementById("rtmr-registers")
  ),
  rtmrEvents: /** @type {HTMLElement} */ (
    document.getElementById("rtmr-events")
  ),
};

el.hardwareConfiguration.addEventListener("change", () => {
  const isCustom = el.hardwareConfiguration.value == "custom";
  if (!isCustom) {
    el.downloadAcpiTables.href = `/acpi/${el.hardwareConfiguration.value}.bin`;
    el.downloadLibvirtXml.href = `/acpi/${el.hardwareConfiguration.value}.xml`;
  }
  el.acpiBlock.style.display = isCustom ? "" : "none";
  el.downloadHardwareFiles.style.display = isCustom ? "none" : "";
});

el.payloadType.addEventListener("change", () => {
  const isUki = el.payloadType.value === "uki";
  el.ukiBlock.style.display = isUki ? "" : "none";
  el.kernelBlock.style.display = isUki ? "none" : "";
  el.initrdBlock.style.display = isUki ? "none" : "";
  el.cmdlineBlock.style.display = isUki ? "none" : "";
});

el.firmwareFile.addEventListener("change", () => {
  clearAndHide(el.firmwareError);
  clearAndHide(el.softwareError);
  updateMrtd();
  updateRtmr();
});

for (const elem of [
  el.ram,
  el.hardwareConfiguration,
  el.acpi,
  el.payloadType,
  el.uki,
  el.kernel,
  el.initrd,
  el.cmdline,
]) {
  elem.addEventListener("change", () => {
    clearAndHide(el.softwareError);
    updateRtmr();
  });
}

async function updateMrtd() {
  const firmwareBuffer = await el.firmwareFile.files?.[0]?.arrayBuffer();
  el.mrtdNone.style.display = firmwareBuffer ? "none" : "";
  el.mrtd.style.display = "none";
  if (!firmwareBuffer) {
    return;
  }

  let mrtd;
  try {
    const firmware = parseFirmware(new Uint8Array(firmwareBuffer));
    mrtd = await reproduceMrtd(firmware);
  } catch (e) {
    showError(e);
    return;
  }

  el.mrtd.innerText = bytesToHex(mrtd);
  el.mrtd.style.display = "";
}

async function updateRtmr() {
  const firmwareBuffer = await el.firmwareFile.files?.[0]?.arrayBuffer();
  const acpi = await getAcpiTables();
  const uki = await el.uki.files?.[0]?.arrayBuffer();
  const kernel = await el.kernel.files?.[0]?.arrayBuffer();
  const initrd = await el.initrd.files?.[0]?.arrayBuffer();
  const isUki = el.payloadType.value === "uki";

  const filled = Boolean(
    firmwareBuffer && acpi && (isUki ? uki : kernel && initrd)
  );
  el.rtmrNone.style.display = filled ? "none" : "";
  el.rtmrRegisters.style.display = "none";
  el.rtmrEvents.style.display = "none";

  if (!filled) {
    return;
  }
  let rtmr;
  try {
    const firmware = parseFirmware(
      new Uint8Array(/** @type {ArrayBuffer} */ (firmwareBuffer))
    );

    const td = {
      hardware: {
        totalMemoryBytes: parseInt(el.ram.value) * 1024 * 1024,
        acpiTables: new Uint8Array(/** @type {ArrayBuffer} */ (acpi)),
      },
      firmware: firmware,
      software: {
        kernel: new Uint8Array(
          /** @type {Uint8Array} */ (isUki ? uki : kernel)
        ),
        initrd: isUki
          ? undefined
          : new Uint8Array(/** @type {ArrayBuffer} */ (initrd)),
        cmdline: isUki ? undefined : el.cmdline.value,
      },
    };

    rtmr = await reproduceRtmr(td);
  } catch (e) {
    showError(e);
    return;
  }

  el.rtmrRegisters.innerHTML = "";
  el.rtmrEvents.innerHTML = "<h2>Event log</h2>\n";

  for (const register of rtmr.registers) {
    el.rtmrRegisters.innerHTML += `
<li>
  <span class="hash">${bytesToHex(register)}</span>
</li>`;
  }

  for (const ev of rtmr.events) {
    el.rtmrEvents.innerHTML += `
<div>
  <h3>
    ${ev.name} <span class="log-tag">RTMR${ev.register}</span>
  </h3>
  <p class="hash">
    ${bytesToHex(ev.digest)}
  </p>
</div>
  `;
  }

  el.rtmrRegisters.style.display = "";
  el.rtmrEvents.style.display = "";
}

updateMrtd();
updateRtmr();

/**
 * @returns {Promise<ArrayBuffer|undefined>}
 */
async function getAcpiTables() {
  if (el.hardwareConfiguration.value === "custom") {
    return await el.acpi.files?.[0]?.arrayBuffer();
  }

  const response = await fetch(`/acpi/${el.hardwareConfiguration.value}.bin`);
  return await response.arrayBuffer();
}

/**
 * @param {Error} e
 */
function showError(e) {
  if (e.name === "TdFirmwareError") {
    el.firmwareError.style.display = "";
    el.firmwareError.textContent = e.message;
  } else {
    el.softwareError.style.display = "";
    el.softwareError.textContent = e.message;
  }
}

function clearAndHide(elem) {
  elem.style.display = "none";
  elem.innerHTML = "";
}
