// Copyright 2025 Quex Technologies

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// @ts-check

import {
  parseFirmware,
  reproduceMrtd,
  bytesToHex,
  reproduceRtmr,
} from "./reproduce.mjs";

/**
 * @typedef {Object} FirmwareModel
 * @property {File|undefined} file
 */

const firmwareView = {
  file: /** @type {HTMLInputElement} */ (
    document.getElementById("firmware-file")
  ),
  fileBlock: /** @type {HTMLElement} */ (
    document.getElementById("firmware-file-field")
  ),
};

/** @type {FirmwareModel} */
const firmwareModel = {
  file: firmwareView.file.files?.[0],
};

/**
 * @typedef {Object} HardwareModel
 * @property {number|undefined} ramMb
 * @property {string} configuration
 * @property {File|undefined} acpiTables
 * @property {string} acpiTablesId
 * @property {boolean} isCustom
 * @property {boolean} isFilled
 * @property {() => Promise<ArrayBuffer|undefined>} getAcpiTables
 */

const hardwareView = {
  ram: /** @type {HTMLInputElement} */ (document.getElementById("ram")),
  ramBlock: /** @type {HTMLInputElement} */ (
    document.getElementById("ram-field")
  ),
  configuration: /** @type {HTMLSelectElement} */ (
    document.getElementById("hardware-configuration")
  ),
  get selectedConfigurationOption() {
    return hardwareView.configuration.options[
      hardwareView.configuration.selectedIndex
    ];
  },
  acpiTables: /** @type {HTMLInputElement} */ (document.getElementById("acpi")),
  acpiTablesBlock: /** @type {HTMLElement} */ (
    document.getElementById("acpi-field")
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
  /**
   * @param {HardwareModel} model
   */
  render: function (model) {
    if (!model.isCustom) {
      this.downloadAcpiTables.href = `acpi/${model.acpiTablesId}.bin`;
      this.downloadLibvirtXml.href = `acpi/${model.configuration}.xml`;
    }
    toggle(this.acpiTablesBlock, model.isCustom);
    toggle(this.downloadHardwareFiles, !model.isCustom);
    toggle(this.ramBlock, model.isCustom);
  },
};

/** @type {HardwareModel} */
const hardwareModel = {
  ramMb: parseInt(
    hardwareView.configuration.value === "custom"
      ? hardwareView.ram.value
      : hardwareView.selectedConfigurationOption.attributes["data-ram"].value
  ),
  configuration: hardwareView.configuration.value,
  acpiTables: hardwareView.acpiTables.files?.[0],
  acpiTablesId:
    hardwareView.configuration.value === "custom"
      ? "custom"
      : hardwareView.selectedConfigurationOption.attributes["data-tables"]
          .value,
  get isCustom() {
    return this.configuration === "custom";
  },
  get isFilled() {
    return Boolean((!this.isCustom || this.acpiTables) && this.ramMb);
  },
  getAcpiTables: async function () {
    if (this.isCustom) {
      return await this.acpiTables?.arrayBuffer();
    }

    const response = await fetch(`acpi/${this.acpiTablesId}.bin`);
    if (!response.ok) {
      throw new Error("Could not get QEMU ACPI tables file");
    }
    return await response.arrayBuffer();
  },
};

/**
 * @typedef {Object} SoftwareModel
 * @property {string} payloadType
 * @property {File|undefined} uki
 * @property {File|undefined} kernel
 * @property {File|undefined} initrd
 * @property {string} cmdline
 * @property {boolean} isUki
 * @property {boolean} isFilled
 */

const softwareView = {
  payloadType: /** @type {HTMLSelectElement} */ (
    document.getElementById("payload-type")
  ),
  uki: /** @type {HTMLInputElement} */ (document.getElementById("uki")),
  kernel: /** @type {HTMLInputElement} */ (document.getElementById("kernel")),
  initrd: /** @type {HTMLInputElement} */ (document.getElementById("initrd")),
  cmdline: /** @type {HTMLInputElement} */ (document.getElementById("cmdline")),
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
  /**
   * @param {SoftwareModel} model
   */
  render: function (model) {
    toggle(this.ukiBlock, model.isUki);
    toggle(this.kernelBlock, !model.isUki);
    toggle(this.initrdBlock, !model.isUki);
    toggle(this.cmdlineBlock, !model.isUki);
  },
};

const softwareModel = {
  payloadType: softwareView.payloadType.value,
  uki: softwareView.uki.files?.[0],
  kernel: softwareView.kernel.files?.[0],
  initrd: softwareView.initrd.files?.[0],
  cmdline: softwareView.cmdline.value,
  get isUki() {
    return this.payloadType === "uki";
  },
  get isFilled() {
    if (this.isUki) {
      return Boolean(this.uki);
    }
    return Boolean(this.kernel && this.initrd);
  },
};

/**
 * @typedef {Object} MrtdModel
 * @property {Uint8Array|null} value
 * @property {boolean} calculating
 * @property {string} error
 */

/** @type {MrtdModel} */
const mrtdModel = {
  value: null,
  calculating: false,
  error: "",
};

const mrtdView = {
  value: /** @type {HTMLElement} */ (document.getElementById("mrtd")),
  none: /** @type {HTMLElement} */ (document.getElementById("mrtd-none")),
  error: /** @type {HTMLElement} */ (document.getElementById("mrtd-error")),
  /**
   * @param {{mrtd: MrtdModel, firmware: FirmwareModel}} model
   */
  render: function ({ mrtd, firmware }) {
    this.value.innerText = mrtd.value ? bytesToHex(mrtd.value) : "";
    this.error.innerText = mrtd.error;
    toggle(this.value, Boolean(mrtd.value) && !mrtd.calculating && !mrtd.error);
    toggle(this.none, !firmware.file && !mrtd.error);
    toggle(this.error, Boolean(mrtd.error));
  },
};

/**
 * @typedef {Object} RtmrModel
 * @property {import("./reproduce.mjs").RtmrResult|null} value
 * @property {boolean} calculating
 * @property {string} error
 */

/**
 * @type {RtmrModel}
 */
const rtmrModel = {
  value: null,
  calculating: false,
  error: "",
};

const rtmrView = {
  registers: /** @type {HTMLElement} */ (
    document.getElementById("rtmr-registers")
  ),
  events: /** @type {HTMLElement} */ (document.getElementById("rtmr-events")),
  none: /** @type {HTMLElement} */ (document.getElementById("rtmr-none")),
  error: /** @type {HTMLElement} */ (document.getElementById("rtmr-error")),
  /**
   * @param {{
   *   rtmr: RtmrModel,
   *   firmware: FirmwareModel,
   *   hardware: HardwareModel,
   *   software: SoftwareModel
   * }} model
   */
  render: function ({ rtmr, firmware, hardware, software }) {
    if (rtmr.value) {
      this.registers.innerHTML = "";
      this.events.innerHTML = "<h2>Event log</h2>\n";

      for (const register of rtmr.value.registers) {
        this.registers.innerHTML += `
<li>
  <span class="hash">${bytesToHex(register)}</span>
</li>`;
      }

      for (const ev of rtmr.value.events) {
        this.events.innerHTML += `
<div class="field">
  <h3>
    ${ev.name} <span class="log-tag">RTMR${ev.register}</span>
  </h3>
  <h4><code>${ev.type}</code></h4>
  <p class="hash">
    ${bytesToHex(ev.digest)}
  </p>
</div>
      `;
      }
    }
    const isInputMissing =
      !software.isFilled || !firmware.file || !hardware.isFilled;

    this.error.innerText = rtmr.error;

    toggle(
      this.events,
      Boolean(rtmr.value) && !rtmr.calculating && !rtmr.error && !isInputMissing
    );
    toggle(
      this.registers,
      Boolean(rtmr.value) && !rtmr.calculating && !rtmr.error && !isInputMissing
    );
    toggle(this.none, isInputMissing && !rtmr.calculating && !rtmr.error);
    toggle(this.error, Boolean(rtmr.error));
  },
};

firmwareView.file.addEventListener("change", () => {
  firmwareModel.file = firmwareView.file.files?.[0];
  render();
  updateMrtd();
  updateRtmr();
});

hardwareView.ram.addEventListener("change", () => {
  if (hardwareModel.isCustom) {
    hardwareModel.ramMb = parseInt(hardwareView.ram.value);
  }
  render();
  updateRtmr();
});

hardwareView.configuration.addEventListener("change", () => {
  hardwareModel.configuration = hardwareView.configuration.value;
  hardwareModel.ramMb = parseInt(
    hardwareModel.isCustom
      ? hardwareView.ram.value
      : hardwareView.configuration.options[
          hardwareView.configuration.selectedIndex
        ].attributes["data-ram"].value
  );
  hardwareModel.acpiTablesId = hardwareModel.isCustom
    ? ""
    : hardwareView.configuration.options[
        hardwareView.configuration.selectedIndex
      ].attributes["data-tables"].value;
  render();
  updateRtmr();
});

hardwareView.acpiTables.addEventListener("change", () => {
  hardwareModel.acpiTables = hardwareView.acpiTables.files?.[0];
  render();
  updateRtmr();
});

softwareView.payloadType.addEventListener("change", () => {
  softwareModel.payloadType = softwareView.payloadType.value;
  render();
  updateRtmr();
});

softwareView.uki.addEventListener("change", () => {
  softwareModel.uki = softwareView.uki.files?.[0];
  render();
  updateRtmr();
});

softwareView.kernel.addEventListener("change", () => {
  softwareModel.kernel = softwareView.kernel.files?.[0];
  render();
  updateRtmr();
});

softwareView.initrd.addEventListener("change", () => {
  softwareModel.initrd = softwareView.initrd.files?.[0];
  render();
  updateRtmr();
});

softwareView.cmdline.addEventListener("change", () => {
  softwareModel.cmdline = softwareView.cmdline.value;
  render();
  updateRtmr();
});

async function updateMrtd() {
  mrtdModel.calculating = true;
  mrtdModel.error = "";
  render();
  try {
    const firmwareBuffer = await firmwareModel.file?.arrayBuffer();
    if (firmwareBuffer) {
      mrtdModel.value = await reproduceMrtd(
        parseFirmware(new Uint8Array(firmwareBuffer))
      );
    }
  } catch (e) {
    mrtdModel.error = e.message;
  } finally {
    mrtdModel.calculating = false;
    render();
  }
}

async function updateRtmr() {
  rtmrModel.calculating = true;
  rtmrModel.error = "";
  render();
  try {
    const td = await getTd();
    if (td) {
      rtmrModel.value = await reproduceRtmr(td);
    }
  } catch (e) {
    rtmrModel.error = e.message;
  } finally {
    rtmrModel.calculating = false;
    render();
  }
}

/**
 * @returns {Promise<import("./reproduce.mjs").TrustDomain|null>}
 */
async function getTd() {
  const [firmwareBuffer, acpi, uki, kernel, initrd] = await Promise.all([
    firmwareModel.file?.arrayBuffer(),
    hardwareModel.getAcpiTables(),
    softwareModel.uki?.arrayBuffer(),
    softwareModel.kernel?.arrayBuffer(),
    softwareModel.initrd?.arrayBuffer(),
  ]);

  if (
    !firmwareBuffer ||
    !acpi ||
    !hardwareModel.ramMb ||
    hardwareModel.ramMb < 0 ||
    !softwareModel.isFilled
  ) {
    return null;
  }

  const firmware = parseFirmware(new Uint8Array(firmwareBuffer));
  const isUki = softwareModel.isUki;

  return {
    hardware: {
      totalMemoryBytes: hardwareModel.ramMb * 1024 * 1024,
      acpiTables: new Uint8Array(acpi),
    },
    firmware,
    software: {
      kernel: new Uint8Array(/** @type {ArrayBuffer} */ (isUki ? uki : kernel)),
      initrd: isUki
        ? undefined
        : new Uint8Array(/** @type {ArrayBuffer} */ (initrd)),
      cmdline: isUki ? undefined : softwareModel.cmdline,
    },
  };
}

document.addEventListener("DOMContentLoaded", () => {
  render();
  updateMrtd();
  updateRtmr();
});

function render() {
  hardwareView.render(hardwareModel);
  softwareView.render(softwareModel);
  mrtdView.render({ mrtd: mrtdModel, firmware: firmwareModel });
  rtmrView.render({
    rtmr: rtmrModel,
    firmware: firmwareModel,
    hardware: hardwareModel,
    software: softwareModel,
  });
}

/**
 * @param {HTMLElement} elem
 * @param {boolean} shown
 */
function toggle(elem, shown) {
  elem.style.display = shown ? "" : "none";
}
