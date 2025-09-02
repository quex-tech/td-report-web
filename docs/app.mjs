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

import { getAcpi } from "./acpi.mjs";
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
 * @property {number|null} cpuCount
 * @property {number|null} ramMb
 * @property {number|null} ramBytes
 * @property {number|null} diskCount
 * @property {string} configuration
 * @property {File|undefined} acpiTables
 * @property {boolean} isCustom
 * @property {boolean} isFilled
 * @property {boolean} isValid
 * @property {() => Promise<Uint8Array<ArrayBuffer>|null>} getAcpiTables
 */

const hardwareView = {
  cpu: /** @type {HTMLInputElement} */ (document.getElementById("cpu")),
  cpuBlock: /** @type {HTMLInputElement} */ (
    document.getElementById("cpu-field")
  ),
  ram: /** @type {HTMLInputElement} */ (document.getElementById("ram")),
  ramBlock: /** @type {HTMLInputElement} */ (
    document.getElementById("ram-field")
  ),
  disks: /** @type {HTMLInputElement} */ (document.getElementById("disks")),
  disksBlock: /** @type {HTMLInputElement} */ (
    document.getElementById("disks-field")
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
    if (!model.isCustom && model.isFilled && model.isValid) {
      const acpiTables = getAcpi(
        /** @type {number} */ (model.cpuCount),
        /** @type {number} */ (model.ramBytes),
        /** @type {number} */ (model.diskCount)
      );
      const acpiBlob = new Blob([acpiTables], {
        type: "application/octet-stream",
      });
      this.downloadAcpiTables.href = URL.createObjectURL(acpiBlob);
      const libvirtXmlBlob = new Blob(
        [
          getLibvirtXml(
            /** @type {number} */ (model.cpuCount),
            /** @type {number} */ (model.ramMb),
            /** @type {number} */ (model.diskCount)
          ),
        ],
        {
          type: "application/xml",
        }
      );
      this.downloadLibvirtXml.href = URL.createObjectURL(libvirtXmlBlob);
    } else {
      URL.revokeObjectURL(this.downloadAcpiTables.href);
      URL.revokeObjectURL(this.downloadLibvirtXml.href);
    }
    toggle(this.acpiTablesBlock, model.isCustom);
    toggle(
      this.downloadHardwareFiles,
      !model.isCustom && model.isFilled && model.isValid
    );
    toggle(this.cpuBlock, !model.isCustom);
    toggle(this.disksBlock, !model.isCustom);
  },
};

/** @type {HardwareModel} */
const hardwareModel = {
  cpuCount: isNaN(parseInt(hardwareView.cpu.value))
    ? null
    : parseInt(hardwareView.cpu.value),
  ramMb: isNaN(parseInt(hardwareView.ram.value))
    ? null
    : parseInt(hardwareView.ram.value),
  get ramBytes() {
    return this.ramMb === null ? null : this.ramMb * 1024 * 1024;
  },
  diskCount: isNaN(parseInt(hardwareView.disks.value))
    ? null
    : parseInt(hardwareView.disks.value),
  configuration: hardwareView.configuration.value,
  acpiTables: hardwareView.acpiTables.files?.[0],
  get isCustom() {
    return this.configuration === "custom";
  },
  get isFilled() {
    return (
      this.ramMb !== null &&
      (this.isCustom
        ? Boolean(this.acpiTables)
        : this.cpuCount !== null && this.diskCount !== null)
    );
  },
  get isValid() {
    return (
      (this.ramMb === null || this.ramMb >= 256) &&
      (this.isCustom ||
        ((this.cpuCount === null ||
          (this.cpuCount > 0 && this.cpuCount <= 256)) &&
          (this.diskCount === null ||
            (this.diskCount >= 0 && this.diskCount <= 8))))
    );
  },
  getAcpiTables: async function () {
    if (this.isCustom) {
      return this.acpiTables
        ? new Uint8Array(await this.acpiTables.arrayBuffer())
        : null;
    }

    if (!this.isFilled || !this.isValid) {
      return null;
    }

    return getAcpi(
      /** @type {number} */ (this.cpuCount),
      /** @type {number} */ (this.ramBytes),
      /** @type {number} */ (this.diskCount)
    );
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
 * @property {Uint8Array<ArrayBuffer>|null} value
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
      !software.isFilled ||
      !firmware.file ||
      !hardware.isFilled ||
      !hardware.isValid;

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

hardwareView.cpu.addEventListener("change", () => {
  const cpuCount = parseInt(hardwareView.cpu.value);
  hardwareModel.cpuCount = isNaN(cpuCount) ? null : cpuCount;
  render();
  updateRtmr();
});

hardwareView.ram.addEventListener("change", () => {
  const ramMb = parseInt(hardwareView.ram.value);
  hardwareModel.ramMb = isNaN(ramMb) ? null : ramMb;
  render();
  updateRtmr();
});

hardwareView.disks.addEventListener("change", () => {
  const diskCount = parseInt(hardwareView.disks.value);
  hardwareModel.diskCount = isNaN(diskCount) ? null : diskCount;
  render();
  updateRtmr();
});

hardwareView.configuration.addEventListener("change", () => {
  hardwareModel.configuration = hardwareView.configuration.value;
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
    } else {
      rtmrModel.value = null;
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
  if (
    !hardwareModel.isFilled ||
    !hardwareModel.isValid ||
    !softwareModel.isFilled
  ) {
    return null;
  }

  const [firmwareBuffer, acpi, uki, kernel, initrd] = await Promise.all([
    firmwareModel.file?.arrayBuffer(),
    hardwareModel.getAcpiTables(),
    softwareModel.uki?.arrayBuffer(),
    softwareModel.kernel?.arrayBuffer(),
    softwareModel.initrd?.arrayBuffer(),
  ]);

  if (!firmwareBuffer || !acpi) {
    return null;
  }

  const firmware = parseFirmware(new Uint8Array(firmwareBuffer));
  const isUki = softwareModel.isUki;

  return {
    hardware: {
      totalMemoryBytes: /** @type {number} */ (hardwareModel.ramBytes),
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
 * @param {number} cpuCount
 * @param {number} ramMb
 * @param {number} diskCount
 * @returns {string}
 */
function getLibvirtXml(cpuCount, ramMb, diskCount) {
  return `<domain type='kvm' xmlns:qemu='http://libvirt.org/schemas/domain/qemu/1.0'>
  <name>my-td</name>
  <memory unit='MiB'>${ramMb}</memory>
  <memoryBacking>
    <source type='anonymous'/>
    <access mode='private'/>
  </memoryBacking>
  <vcpu placement='static'>${cpuCount}</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <loader>/path/to/OVMF.fd</loader>
    <kernel>/path/to/ukernel.efi</kernel>
  </os>
  <features>
    <acpi/>
    <apic/>
    <vmport state='off'/>
    <ioapic driver='qemu'/>
  </features>
  <cpu mode='host-passthrough'>
    <topology sockets='1' cores='${cpuCount}' threads='1'/>
  </cpu>
  <clock offset='utc'>
    <timer name='hpet' present='no'/>
  </clock>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <pm>
    <suspend-to-mem enabled='no'/>
    <suspend-to-disk enabled='no'/>
  </pm>
  <devices>
    <emulator>/usr/bin/qemu-system-x86_64</emulator>
    <interface type='network'>
      <source network='bridged-network' bridge='brquex0'/>
      <model type='virtio'/>
      <address type='pci' bus='0x00' slot='0x01'/>
    </interface>
    <controller type='usb' model='none'/>
    <memballoon model='none'/>
${[...new Array(diskCount).keys()]
  .map(
    (i) => `    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/path/to/${getDiskDeviceName(i)}.qcow2'/>
      <target dev='${getDiskDeviceName(i)}' bus='virtio'/>
    </disk>
`
  )
  .join("")}  </devices>
  <launchSecurity type='tdx'>
    <policy>0x10000000</policy>
    <quoteGenerationService>
      <SocketAddress type='vsock' cid='2' port='4050'/>
    </quoteGenerationService>
  </launchSecurity>
  <qemu:commandline>
    <qemu:arg value='-machine'/>
    <qemu:arg value='pc-q35-8.2,usb=off,vmport=off,kernel_irqchip=split,dump-guest-core=off,memory-backend=pc.ram,confidential-guest-support=lsec0,hpet=off,i8042=off,smbus=off,sata=off'/>
    <qemu:arg value='-global'/>
    <qemu:arg value='ICH9-LPC.acpi-pci-hotplug-with-bridge-support=off'/>
  </qemu:commandline>
</domain>`;
}

/**
 * @param {number} id
 * @returns {string}
 */
function getDiskDeviceName(id) {
  return `vd${String.fromCharCode(0x61 + id)}`;
}

/**
 * @param {HTMLElement} elem
 * @param {boolean} shown
 */
function toggle(elem, shown) {
  elem.style.display = shown ? "" : "none";
}
