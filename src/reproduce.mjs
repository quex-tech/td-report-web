// @ts-check
"use strict";

/**
 * @typedef {Object} TrustDomain
 * @property {TdHardware} hardware
 * @property {TdFirmware} firmware
 * @property {TdSoftware} software
 */

/**
 * @typedef {Object} TdSoftware
 * @property {Uint8Array} kernel
 * @property {Uint8Array} [initrd]
 * @property {string} [cmdline]
 */

/**
 * @typedef {Object} TdHardware
 * @property {number} totalMemoryBytes
 * @property {Uint8Array} acpiTables
 */

/**
 * @typedef {Object} TdEvent
 * @property {string} name
 * @property {string} type
 * @property {{[key:string]:string}} metadata
 * @property {number} register
 * @property {Uint8Array} digest
 */

const PAGE_SIZE = 0x1000;

/**
 * @param {TdFirmware} firmware
 * @returns {Promise<Uint8Array>}
 */
export async function reproduceMrtd(firmware) {
  /**
   * @type {Uint8Array[]}
   */
  const parts = [];
  for (const section of firmware.tdxMetadataSections) {
    const numPages = section.memSize / PAGE_SIZE;
    for (let i = 0; i < numPages; i++) {
      const bytes = new Uint8Array(128);
      const view = new DataView(bytes.buffer);
      utf8encoder.encodeInto("MEM.PAGE.ADD", bytes);
      view.setBigUint64(16, BigInt(section.memBase + i * PAGE_SIZE), LE);
      parts.push(bytes);
    }
    if (section.extendMr) {
      for (let i = 0; i < numPages; i++) {
        for (let j = 0; j < PAGE_SIZE / 0x100; j++) {
          const bytes = new Uint8Array(128);
          const view = new DataView(bytes.buffer);
          utf8encoder.encodeInto("MR.EXTEND", bytes);
          const offsetVal = i * PAGE_SIZE + j * 0x100;
          view.setBigUint64(16, BigInt(section.memBase + offsetVal), LE);
          parts.push(bytes);
          const fwOffset = section.rawOffset + offsetVal;
          parts.push(firmware.bytes.subarray(fwOffset, fwOffset + 0x80));
          parts.push(
            firmware.bytes.subarray(fwOffset + 0x80, fwOffset + 0x100)
          );
        }
      }
    }
  }
  return await sha384(concatBytes(parts));
}

/**
 * @typedef {Object} RtmrResult
 * @property {Uint8Array[]} registers
 * @property {TdEvent[]} events
 */

/**
 * @param {TrustDomain} td
 * @returns {Promise<RtmrResult>}
 */
export async function reproduceRtmr(td) {
  const registers = [
    new Uint8Array(48),
    new Uint8Array(48),
    new Uint8Array(48),
    new Uint8Array(48),
  ];
  const events = await reproduceEvents(td);
  for (const ev of events) {
    registers[ev.register] = await sha384(
      concatBytes([registers[ev.register], ev.digest])
    );
  }
  return { registers, events };
}

const EFI_ACTIONS = [
  "Calling EFI Application from Boot Option",
  "Exit Boot Services Invocation",
  "Exit Boot Services Returned with Success",
];

const GLOBAL_VAR_GUID = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const SECURITY_DB_GUID = "d719b2cb-3d3a-4596-a3bc-dad00e67656f";

/**
 * @param {TrustDomain} td
 * @returns {Promise<TdEvent[]>}
 */
async function reproduceEvents(td) {
  /**
   * @type {TdEvent[]}
   */
  const events = [];

  /**
   * @param {string} name
   * @param {string} type
   * @param {number} register
   * @param {{[key:string]:string}} metadata
   * @param {Uint8Array<ArrayBuffer>} preimage
   */
  async function addEvent(name, type, register, metadata, preimage) {
    events.push({
      name,
      type,
      register,
      metadata,
      digest: await sha384(preimage),
    });
  }

  const hob = getHobHashPreimage(
    td.firmware.tdxMetadataSections,
    td.hardware.totalMemoryBytes
  );

  await addEvent(
    "TD Hand-Off Block (HOB)",
    "EV_EFI_HANDOFF_TABLES2",
    0,
    {},
    hob
  );

  for (const section of td.firmware.tdxMetadataSections) {
    if (section.sectionType === "CFV") {
      const cfv = td.firmware.bytes.subarray(
        section.rawOffset,
        section.rawOffset + section.rawSize
      );
      await addEvent(
        "Configuration Firmware Volume (CFV)",
        "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
        0,
        {},
        cfv
      );
    }
  }

  // todo: support Secure Boot
  await addEvent(
    "Secure boot mode",
    "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0,
    { name: "SecureBoot", alias: "EFI_SECURE_BOOT_MODE_NAME", value: "0" },
    getEmptyDriverConfigVariable(GLOBAL_VAR_GUID, "SecureBoot")
  );

  await addEvent(
    "Public platform key",
    "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0,
    { name: "PK", alias: "EFI_PLATFORM_KEY_NAME", value: "0" },
    getEmptyDriverConfigVariable(GLOBAL_VAR_GUID, "PK")
  );

  await addEvent(
    "Key exchange key signature database",
    "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0,
    {
      name: "KEK",
      alias: "EFI_KEY_EXCHANGE_KEY_NAME",
      value: "0",
    },
    getEmptyDriverConfigVariable(GLOBAL_VAR_GUID, "KEK")
  );
  await addEvent(
    "Authorized signature database",
    "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0,
    {
      name: "db",
      alias: "EFI_IMAGE_SECURITY_DATABASE",
      value: "0",
    },
    getEmptyDriverConfigVariable(SECURITY_DB_GUID, "db")
  );
  await addEvent(
    "Forbidden signature database",
    "EV_EFI_VARIABLE_DRIVER_CONFIG",
    0,
    {
      name: "dbx",
      alias: "EFI_IMAGE_SECURITY_DATABASE1",
      value: "0",
    },
    getEmptyDriverConfigVariable(SECURITY_DB_GUID, "dbx")
  );

  await addEvent("Separator", "EV_SEPARATOR", 0, {}, new Uint8Array(4));

  const acpiTables = parseAcpiTables(td.hardware.acpiTables);
  await addEvent(
    "QEMU ACPI table loader",
    "EV_PLATFORM_CONFIG_FLAGS",
    0,
    { fileName: "etc/table-loader" },
    getTableLoader(acpiTables)
  );
  await addEvent(
    "Root System Description Pointer (RSDP)",
    "EV_PLATFORM_CONFIG_FLAGS",
    0,
    { fileName: "etc/acpi/rsdp" },
    getRsdp(acpiTables)
  );
  await addEvent(
    "ACPI tables",
    "EV_PLATFORM_CONFIG_FLAGS",
    0,
    { fileName: "etc/acpi/tables" },
    td.hardware.acpiTables
  );

  qemuPatchKernel(td.software, td.hardware.totalMemoryBytes);

  const kernelPe = parsePe(td.software.kernel);
  const linuxSection = kernelPe.sections.find((x) => x.name === ".linux\0\0");
  const isUki = Boolean(linuxSection);

  await addEvent(
    isUki ? "Linux unified kernel image" : "Linux kernel",
    "EV_EFI_BOOT_SERVICES_APPLICATION",
    1,
    {},
    getPeHashPreimage(td.software.kernel)
  );

  await addEvent(
    "BootOrder boot variable",
    "EV_EFI_VARIABLE_BOOT",
    0,
    {},
    new Uint8Array(2)
  );
  await addEvent(
    "Boot0000 boot variable",
    "EV_EFI_VARIABLE_BOOT",
    0,
    {},
    getUiAppBootOption()
  );
  await addEvent(
    EFI_ACTIONS[0],
    "EV_EFI_ACTION",
    1,
    {},
    utf8encoder.encode(EFI_ACTIONS[0])
  );

  await addEvent("Separator", "EV_SEPARATOR", 0, {}, new Uint8Array(4));

  if (linuxSection) {
    await addEvent(
      "Linux kernel",
      "EV_EFI_BOOT_SERVICES_APPLICATION",

      1,
      {},
      getPeHashPreimage(linuxSection.body)
    );
  }

  let initrd = null;
  let cmdline = null;

  if (isUki) {
    initrd = kernelPe.sections.find((x) => x.name === ".initrd\0")?.body;
    const cmdlineSection = kernelPe.sections.find((x) => x.name === ".cmdline");
    if (cmdlineSection) {
      cmdline = utf8decoder.decode(cmdlineSection.body);
    }
  } else {
    initrd = td.software.initrd;
    cmdline = td.software.cmdline
      ? td.software.cmdline + (td.software.initrd ? " initrd=initrd" : "")
      : null;
  }

  if (cmdline !== null) {
    await addEvent(
      "Linux kernel command-line parameters",
      "EV_EVENT_TAG",
      2,
      { cmdline: cmdline, tagName: "LOADED_IMAGE::LoadOptions" },
      utf16LeEncoder.encode(cmdline + "\0")
    );
  }
  if (initrd) {
    await addEvent("Linux initial ramdisk", "EV_EVENT_TAG", 2, {}, initrd);
  }

  await addEvent(
    EFI_ACTIONS[1],
    "EV_EFI_ACTION",
    1,
    {},
    utf8encoder.encode(EFI_ACTIONS[1])
  );

  await addEvent(
    EFI_ACTIONS[2],
    "EV_EFI_ACTION",
    1,
    {},
    utf8encoder.encode(EFI_ACTIONS[2])
  );

  return events;
}

/**
 * @param {string} uuid
 * @param {string} name
 * @returns {Uint8Array}
 */
function getEmptyDriverConfigVariable(uuid, name) {
  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, BigInt(name.length), LE);
  return concatBytes([uuidToBytes(uuid), bytes, utf16LeEncoder.encode(name)]);
}

/**
 * @returns {Uint8Array}
 */
function getUiAppBootOption() {
  return concatBytes([
    new Uint8Array([0x09, 0x01, 0x00, 0x00, 0x2c, 0x00]),
    utf16LeEncoder.encode("UiApp\0"),
    new Uint8Array([0x04, 0x07, 0x14, 0x00]),
    uuidToBytes("7cb8bdc9-f8eb-4f34-aaea-3ee4af6516a1"),
    new Uint8Array([0x04, 0x06, 0x14, 0x00]),
    uuidToBytes("462caa21-7614-4503-836e-8ab6f4662331"),
    new Uint8Array([0x7f, 0xff, 0x04, 0x00]),
  ]);
}

// ------------------------------------------------------------------------------
// ACPI
// ------------------------------------------------------------------------------

/**
 * @typedef {Object} AcpiTable
 * @property {string} signature
 * @property {number} offset
 * @property {number} length
 */

/**
 * @param {Uint8Array} bytes
 * @returns {AcpiTable[]}
 */
function parseAcpiTables(bytes) {
  let offset = 0;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  /**
   * @type {AcpiTable[]}
   */
  const result = [];

  while (offset < bytes.length) {
    if (offset + 8 > bytes.length) {
      break;
    }

    const signature = utf8decoder.decode(bytes.subarray(offset, offset + 4));
    if (signature === "\0\0\0\0") {
      break;
    }
    const length = view.getUint32(offset + 4, LE);

    result.push({ signature, offset, length });
    offset += length;
  }

  return result;
}

/**
 * @param {AcpiTable[]} tables
 * @returns {Uint8Array}
 */
function getRsdp(tables) {
  let rsdtOffset = 0;
  for (const table of tables) {
    if (table.signature === "RSDT") {
      rsdtOffset = table.offset;
      break;
    }
  }

  const result = new Uint8Array(20);
  const view = new DataView(result.buffer);
  utf8encoder.encodeInto("RSD PTR ", result);
  result[8] = 0;
  utf8encoder.encodeInto("BOCHS ", result.subarray(9));
  result[15] = 0;
  view.setUint32(16, rsdtOffset, LE);
  return result;
}

/**
 * @param {AcpiTable[]} tables
 * @returns {Uint8Array}
 */
function getTableLoader(tables) {
  const commands = [
    serializeAllocate("etc/acpi/rsdp", 16, 2),
    serializeAllocate("etc/acpi/tables", 64, 1),
  ];

  for (const table of tables) {
    if (table.signature === "FACP") {
      commands.push(
        serializeAddPointer(
          "etc/acpi/tables",
          "etc/acpi/tables",
          table.offset + 36,
          4
        )
      );
      commands.push(
        serializeAddPointer(
          "etc/acpi/tables",
          "etc/acpi/tables",
          table.offset + 40,
          4
        )
      );
      commands.push(
        serializeAddPointer(
          "etc/acpi/tables",
          "etc/acpi/tables",
          table.offset + 140,
          8
        )
      );
    }

    if (table.signature === "RSDT") {
      commands.push(
        serializeAddPointer(
          "etc/acpi/tables",
          "etc/acpi/tables",
          table.offset + 36,
          4
        )
      );
      commands.push(
        serializeAddPointer(
          "etc/acpi/tables",
          "etc/acpi/tables",
          table.offset + 40,
          4
        )
      );
      commands.push(
        serializeAddPointer(
          "etc/acpi/tables",
          "etc/acpi/tables",
          table.offset + 44,
          4
        )
      );
      commands.push(
        serializeAddPointer(
          "etc/acpi/tables",
          "etc/acpi/tables",
          table.offset + 48,
          4
        )
      );
    }

    if (table.signature !== "FACS") {
      commands.push(
        serializeAddChecksum(
          "etc/acpi/tables",
          table.offset + 9,
          table.offset,
          table.length
        )
      );
    }
  }

  commands.push(serializeAddPointer("etc/acpi/rsdp", "etc/acpi/tables", 16, 4));
  commands.push(serializeAddChecksum("etc/acpi/rsdp", 8, 0, 20));

  return concatBytes(commands, 4096);
}

/**
 * @param {string} filename
 * @param {number} align
 * @param {number} zone
 * @returns {Uint8Array}
 */
function serializeAllocate(filename, align, zone) {
  const result = new Uint8Array(128);
  const view = new DataView(result.buffer);
  view.setUint32(0, 1, LE);
  utf8encoder.encodeInto(filename, result.subarray(4));
  view.setUint32(60, align, LE);
  view.setUint8(64, zone);
  return result;
}

/**
 * @param {string} destFile
 * @param {string} srcFile
 * @param {number} offset
 * @param {number} size
 * @returns {Uint8Array}
 */
function serializeAddPointer(destFile, srcFile, offset, size) {
  const result = new Uint8Array(128);
  const view = new DataView(result.buffer);
  view.setUint32(0, 2, LE);
  utf8encoder.encodeInto(destFile, result.subarray(4));
  utf8encoder.encodeInto(srcFile, result.subarray(60));
  view.setUint32(116, offset, LE);
  view.setUint8(120, size);
  return result;
}

/**
 * @param {string} filename
 * @param {number} offset
 * @param {number} start
 * @param {number} length
 * @returns {Uint8Array}
 */
function serializeAddChecksum(filename, offset, start, length) {
  const result = new Uint8Array(128);
  const view = new DataView(result.buffer);
  view.setUint32(0, 3, LE);
  utf8encoder.encodeInto(filename, result.subarray(4));
  view.setUint32(60, offset, LE);
  view.setUint32(64, start, LE);
  view.setUint32(68, length, LE);
  return result;
}

// ------------------------------------------------------------------------------
// HOB
// ------------------------------------------------------------------------------

const HOB_TABLE_SIZE = 56;
const HOB_RESOURCE_DESCRIPTOR_SIZE = 48;
const HOB_END_SIZE = 8;

/**
 * @param {TdxMetadataSection[]} tdxMetadataSections
 * @param {number} totalMemoryBytes
 * @returns {Uint8Array}
 */
function getHobHashPreimage(tdxMetadataSections, totalMemoryBytes) {
  let memOffset = 0;
  /**
   * @type {[number, number, number][]}
   */
  const entries = [];

  const hobSection = tdxMetadataSections.find(
    (section) => section.sectionType === "TD_HOB"
  );
  if (!hobSection) {
    throw new Error("TD_HOB section not found");
  }

  const sortedSections = tdxMetadataSections
    .filter(
      (section) =>
        section.sectionType === "TD_HOB" || section.sectionType === "TempMem"
    )
    .sort((a, b) => a.memBase - b.memBase);

  for (const section of sortedSections) {
    if (section.memBase > memOffset) {
      entries.push([memOffset, section.memBase, 0]);
    }
    entries.push([section.memBase, section.memBase + section.memSize, 1]);
    memOffset = section.memBase + section.memSize;
  }
  if (memOffset < totalMemoryBytes) {
    entries.push([memOffset, totalMemoryBytes, 0]);
  }

  const hob = new Uint8Array(hobSection.memSize);
  const view = new DataView(hob.buffer);

  view.setUint16(0, 0x0001, LE);
  view.setUint16(2, HOB_TABLE_SIZE, LE);
  view.setUint32(8, 0x0009, LE);
  let hobOffset = HOB_TABLE_SIZE;

  for (const entry of entries) {
    const resourceType = entry[2] === 1 ? 0x00000000 : 0x00000007;
    view.setUint16(hobOffset, 0x0003, LE);
    view.setUint16(hobOffset + 2, HOB_RESOURCE_DESCRIPTOR_SIZE, LE);
    view.setUint32(hobOffset + 24, resourceType, LE);
    view.setUint32(hobOffset + 28, 0x00000007, LE);
    view.setBigUint64(hobOffset + 32, BigInt(entry[0]), LE);
    view.setBigUint64(hobOffset + 40, BigInt(entry[1] - entry[0]), LE);
    hobOffset += 48;
  }

  const preimageEnd = hobOffset;

  view.setUint16(hobOffset, 0xffff, LE);
  view.setUint16(hobOffset + 2, HOB_END_SIZE, LE);
  hobOffset += HOB_END_SIZE;

  view.setBigUint64(48, BigInt(hobSection.memBase + hobOffset), LE);

  // End block is not hashed
  return hob.subarray(0, preimageEnd);
}

// ------------------------------------------------------------------------------
// Firmware
// ------------------------------------------------------------------------------

const TDX_METADATA_SECTION_TYPES = [
  "BFV",
  "CFV",
  "TD_HOB",
  "TempMem",
  "PermMem",
  "Payload",
  "PayloadParam",
  "TD_INFO",
  "TD_PARAMS",
];

/**
 * @typedef {Object} TdFirmware
 * @property {Uint8Array} bytes
 * @property {TdxMetadataSection[]} tdxMetadataSections
 */

/**
 * @typedef {Object} TdxMetadataSection
 * @property {number} rawOffset
 * @property {number} rawSize
 * @property {number} memBase
 * @property {number} memSize
 * @property {string} sectionType
 * @property {boolean} extendMr
 */

/**
 *
 * @param {Uint8Array} bytes
 * @returns {TdFirmware}
 */
export function parseFirmware(bytes) {
  return { bytes, tdxMetadataSections: getTdxMetadataSections(bytes) };
}

/**
 * @param {Uint8Array} firmware
 * @returns {TdxMetadataSection[]}
 */
function getTdxMetadataSections(firmware) {
  const footerOffset = firmware.length - 0x30;
  const footerGuid = bytesToUuid(firmware.subarray(footerOffset));
  if (footerGuid !== "96b582de-1fb2-45f7-baea-a366c55a082d") {
    throw new Error("Wrong table footer guid");
  }

  return parseTdxMetadataSections(
    firmware.subarray(getTdxMetadataOffset(firmware) - 16)
  );
}

/**
 * @param {Uint8Array} metadataTable
 * @returns {TdxMetadataSection[]}
 */
function parseTdxMetadataSections(metadataTable) {
  if (metadataTable.length < 32) {
    throw new Error("Data too short for TdxMetadata header");
  }

  if (bytesToUuid(metadataTable) !== "e9eaf9f3-168e-44d5-a8eb-7f4d8738f6ae") {
    throw new Error("Wrong metadata guid");
  }

  const view = new DataView(
    metadataTable.buffer,
    metadataTable.byteOffset,
    metadataTable.byteLength
  );

  const signature = utf8decoder.decode(metadataTable.subarray(16, 20));
  if (signature !== "TDVF") {
    throw new Error(`Invalid signature: ${signature}`);
  }
  const version = view.getUint32(24, LE);
  if (version !== 1) {
    throw new Error(`Unsupported version: ${version}`);
  }

  const sectionCount = view.getUint32(28, LE);
  /**
   * @type {TdxMetadataSection[]}
   */
  const sections = [];
  const sectionSize = 32;
  let offset = 32;
  for (let i = 0; i < sectionCount; i++) {
    if (offset + sectionSize > metadataTable.length) {
      throw new Error(`Not enough data for section ${i}`);
    }
    const rawOffset = view.getUint32(offset, LE);
    const rawSize = view.getUint32(offset + 4, LE);
    const memBase = view.getBigUint64(offset + 8, LE);
    const memSize = view.getBigUint64(offset + 16, LE);
    const sectionTypeIndex = view.getUint32(offset + 24, LE);
    const attributes = view.getUint32(offset + 28, LE);

    const sectionType = TDX_METADATA_SECTION_TYPES[sectionTypeIndex];
    if (sectionType === undefined) {
      throw new Error(`Invalid section type index: ${sectionTypeIndex}`);
    }
    sections.push({
      rawOffset,
      rawSize,
      memBase: Number(memBase),
      memSize: Number(memSize),
      sectionType,
      extendMr: Boolean(attributes & 1),
    });
    offset += sectionSize;
  }
  return sections;
}

/**
 * @param {Uint8Array} image
 * @returns {number}
 */
function getTdxMetadataOffset(image) {
  const view = new DataView(image.buffer, image.byteOffset, image.byteLength);
  let offset = image.byteLength - 0x30 - 2;
  const tableLength = view.getUint16(offset, LE);
  const tableStart = image.byteLength - 0x30 - tableLength;

  while (offset > tableStart) {
    const entryGuid = bytesToUuid(image.subarray(offset - 16));
    if (entryGuid === "e47a6535-984a-4798-865e-4685a7bf8ec2") {
      return image.byteLength - view.getUint32(offset - 16 - 2 - 4, LE);
    }

    const entryLength = view.getUint16(offset - 16 - 2, LE);
    offset -= entryLength;
  }
  throw new Error("TDX metadata offset not found");
}

// ------------------------------------------------------------------------------
// QEMU
// ------------------------------------------------------------------------------

const ACPI_DATA_SIZE = 0x20000 + 0x8000;

/**
 * @param {TdSoftware} software
 * @param {number} totalMemoryBytes
 */
function qemuPatchKernel(software, totalMemoryBytes) {
  const kernel = software.kernel;
  const view = new DataView(
    kernel.buffer,
    kernel.byteOffset,
    kernel.byteLength
  );
  const ramSize = totalMemoryBytes;
  const cmdlineSize = ((software.cmdline || "").length + 16) & ~15;

  const lowmem = ramSize >= 0xb0000000 ? 0x80000000 : 0xb0000000;
  const below4gMemSize = ramSize >= lowmem ? lowmem : ramSize;

  const magic = utf8decoder.decode(kernel.subarray(0x202, 0x206));
  let protocol = 0;
  if (magic === "HdrS") {
    protocol = view.getUint16(0x206, LE);
  }

  let realAddr, cmdlineAddr;
  if (protocol < 0x202 || !(kernel[0x211] & 0x01)) {
    realAddr = 0x90000;
    cmdlineAddr = 0x9a000 - cmdlineSize;
  } else {
    realAddr = 0x10000;
    cmdlineAddr = 0x20000;
  }

  let initrdMax;
  if (protocol >= 0x20c && view.getUint16(0x236, LE) & 2) {
    initrdMax = 0xffffffff;
  } else if (protocol >= 0x203) {
    initrdMax = view.getUint32(0x22c, LE);
  } else {
    initrdMax = 0x37ffffff;
  }

  if (initrdMax >= below4gMemSize - ACPI_DATA_SIZE) {
    initrdMax = below4gMemSize - ACPI_DATA_SIZE - 1;
  }

  if (protocol >= 0x202) {
    view.setUint32(0x228, cmdlineAddr, LE);
  } else {
    view.setUint16(0x20, 0xa33f, LE);
    view.setUint16(0x22, cmdlineAddr - realAddr, LE);
  }

  if (protocol >= 0x200) {
    kernel[0x210] = 0xb0;
  }

  if (protocol >= 0x201) {
    kernel[0x211] |= 0x80;
    view.setUint16(0x224, cmdlineAddr - realAddr - 0x200, LE);
  }

  if (software.initrd) {
    if (protocol < 0x200) {
      throw new Error(
        "RAM disk is already in kernel image or kernel is too old"
      );
    }
    if (software.initrd.length >= initrdMax) {
      throw new Error("RAM disk is too large");
    }
    const initrdAddr = (initrdMax - software.initrd.length) & ~4095;
    view.setUint32(0x218, initrdAddr, LE);
    view.setUint32(0x21c, software.initrd.length, LE);
  }
}

// ------------------------------------------------------------------------------
// PE
// ------------------------------------------------------------------------------

/**
 * Compute the preimage for hashing a PE file.
 *
 * Excludes the CheckSum field and the Certificate Directory, and then
 * takes each section (sorted by raw file offset) and any extra data
 * (beyond the headers/sections) excluding the certificate blob.
 * The procedure follows the algorithm used in OVMF for PE/COFF measurement.
 *
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
function getPeHashPreimage(bytes) {
  const { optionalHeader, sections } = parsePe(bytes);
  /**
   * @type {Uint8Array[]}
   */
  const hashParts = [];

  const checksumFieldOffset = optionalHeader.offset + 0x40;

  if (checksumFieldOffset > bytes.byteLength) {
    throw new Error(
      "Invalid PE file: Checksum field offset exceeds file size."
    );
  }

  hashParts.push(bytes.subarray(0, checksumFieldOffset));

  const afterChecksumOffset = checksumFieldOffset + 4;
  const securityDirIndex = 4;
  if (optionalHeader.numberOfRvaAndSizes <= securityDirIndex) {
    hashParts.push(
      bytes.subarray(afterChecksumOffset, optionalHeader.sizeOfHeaders)
    );
  } else {
    const certDirEntryOffset =
      optionalHeader.offset +
      optionalHeader.fixedOptionalHeaderSize +
      securityDirIndex * 8;
    if (certDirEntryOffset > optionalHeader.sizeOfHeaders) {
      throw new Error(
        "Invalid PE file: Certificate Directory entry offset exceeds header size."
      );
    }
    hashParts.push(bytes.subarray(afterChecksumOffset, certDirEntryOffset));
    const afterCertDir = certDirEntryOffset + 8;
    hashParts.push(bytes.subarray(afterCertDir, optionalHeader.sizeOfHeaders));
  }

  let sumOfBytesHashed = optionalHeader.sizeOfHeaders;

  const validSections = sections.filter((s) => s.rawBody.byteLength !== 0);
  validSections.sort((a, b) => a.rawBody.byteOffset - b.rawBody.byteOffset);
  for (const section of validSections) {
    hashParts.push(section.rawBody);
    sumOfBytesHashed += section.rawBody.byteLength;
  }

  const imageSize = bytes.byteLength;
  if (imageSize > sumOfBytesHashed) {
    let certSize = 0;
    if (optionalHeader.numberOfRvaAndSizes > securityDirIndex) {
      const certDirSizeOffset =
        optionalHeader.offset +
        optionalHeader.fixedOptionalHeaderSize +
        securityDirIndex * 8 +
        4;
      if (certDirSizeOffset + 4 <= bytes.byteLength) {
        certSize = new DataView(
          bytes.buffer,
          bytes.byteOffset,
          bytes.byteLength
        ).getUint32(certDirSizeOffset, LE);
      }
    }
    if (imageSize > sumOfBytesHashed + certSize) {
      hashParts.push(bytes.subarray(sumOfBytesHashed, imageSize - certSize));
    } else if (imageSize < sumOfBytesHashed + certSize) {
      throw new Error(
        "Unsupported: File size is less than SUM_OF_BYTES_HASHED + CertSize."
      );
    }
  }

  return concatBytes(hashParts);
}

/**
 * @typedef {Object} PortableExecutable
 * @property {PeOptionalHeader} optionalHeader
 * @property {PeSection[]} sections
 */

/**
 * @typedef {Object} PeSection
 * @property {string} name
 * @property {Uint8Array} body Body without zero-padding
 * @property {Uint8Array} rawBody Body with zero-padding
 */

/**
 * @typedef {Object} PeOptionalHeader
 * @property {number} sizeOfHeaders
 * @property {number} numberOfRvaAndSizes
 * @property {number} offset
 * @property {number} fixedOptionalHeaderSize
 */

/**
 * @param {Uint8Array} bytes
 * @returns {PortableExecutable}
 */
function parsePe(bytes) {
  const dataView = new DataView(
    bytes.buffer,
    bytes.byteOffset,
    bytes.byteLength
  );

  if (bytes.byteLength < 0x40) {
    throw new Error("Invalid PE file: too small for DOS header.");
  }

  const e_lfanew = dataView.getUint32(0x3c, LE);
  if (e_lfanew + 4 > bytes.byteLength) {
    throw new Error("Invalid PE file: incomplete PE header.");
  }

  const signature = utf8decoder.decode(bytes.subarray(e_lfanew, e_lfanew + 4));
  if (signature !== "PE\0\0") {
    throw new Error("Invalid PE signature");
  }

  const fileHeaderOffset = e_lfanew + 4;
  const numberOfSections = dataView.getUint16(fileHeaderOffset + 2, LE);
  const sizeOfOptionalHeader = dataView.getUint16(fileHeaderOffset + 16, LE);
  const optionalHeaderOffset = fileHeaderOffset + 20;

  const magic = dataView.getUint16(optionalHeaderOffset, LE);
  let fixedOptionalHeaderSize;
  if (magic === 0x10b) {
    fixedOptionalHeaderSize = 96;
  } else if (magic === 0x20b) {
    fixedOptionalHeaderSize = 112;
  } else {
    throw new Error("Unknown Optional Header Magic: 0x" + magic.toString(16));
  }

  const sizeOfHeaders = dataView.getUint32(optionalHeaderOffset + 60, LE);
  const numberOfRvaAndSizes = dataView.getUint32(
    optionalHeaderOffset + fixedOptionalHeaderSize - 4,
    LE
  );

  const optionalHeader = {
    sizeOfHeaders,
    numberOfRvaAndSizes,
    offset: optionalHeaderOffset,
    fixedOptionalHeaderSize,
  };

  const sectionHeadersStart = optionalHeaderOffset + sizeOfOptionalHeader;
  const sectionHeaderSize = 40;
  /**
   * @type {PeSection[]}
   */
  const sections = [];

  for (let i = 0; i < numberOfSections; i++) {
    const sectionHeaderOffset = sectionHeadersStart + i * sectionHeaderSize;
    if (sectionHeaderOffset + sectionHeaderSize > bytes.byteLength) {
      throw new Error("Invalid PE file: incomplete section header.");
    }

    const nameBytes = bytes.subarray(
      sectionHeaderOffset,
      sectionHeaderOffset + 8
    );
    const sectionName = utf8decoder.decode(nameBytes);

    const virtualSize = dataView.getUint32(sectionHeaderOffset + 8, LE);
    const sizeOfRawData = dataView.getUint32(sectionHeaderOffset + 16, LE);
    const pointerToRawData = dataView.getUint32(sectionHeaderOffset + 20, LE);
    const actualSize = Math.min(virtualSize, sizeOfRawData);

    if (pointerToRawData + actualSize > bytes.byteLength) {
      throw new Error(
        `Invalid PE file: section ${sectionName} exceeds file size.`
      );
    }

    sections.push({
      name: sectionName,
      body: bytes.subarray(pointerToRawData, pointerToRawData + actualSize),
      rawBody: bytes.subarray(
        pointerToRawData,
        pointerToRawData + sizeOfRawData
      ),
    });
  }

  return { optionalHeader, sections };
}

// ------------------------------------------------------------------------------
// Utilities
// ------------------------------------------------------------------------------

const LE = true;
const BE = false;

class TextEncoderUtf16Le {
  /**
   * @param {string} str
   * @returns {Uint8Array}
   */
  encode(str) {
    const buffer = new ArrayBuffer(str.length * 2);
    const view = new DataView(buffer);
    for (let i = 0; i < str.length; i++) {
      view.setUint16(i * 2, str.charCodeAt(i), LE);
    }
    return new Uint8Array(buffer);
  }
}

const utf8decoder = new TextDecoder();
const utf8encoder = new TextEncoder();
const utf16LeEncoder = new TextEncoderUtf16Le();

/**
 * @param {Uint8Array} bytes
 * @returns {Promise<Uint8Array>}
 */
async function sha384(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-384", bytes));
}

/**
 * @param {string} uuid
 * @returns {Uint8Array}
 */
function uuidToBytes(uuid) {
  const parts = uuid.split("-");
  const result = new Uint8Array(16);
  const view = new DataView(result.buffer);
  view.setUint32(0, parseInt(parts[0], 16), LE);
  view.setUint16(4, parseInt(parts[1], 16), LE);
  view.setUint16(6, parseInt(parts[2], 16), LE);
  view.setBigUint64(8, BigInt("0x" + parts[4]), BE);
  view.setUint16(8, parseInt(parts[3], 16), BE);
  return result;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToUuid(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, 16);
  return [
    view.getUint32(0, LE).toString(16).padStart(8, "0"),
    "-",
    view.getUint16(4, LE).toString(16).padStart(4, "0"),
    "-",
    view.getUint16(6, LE).toString(16).padStart(4, "0"),
    "-",
    view.getUint16(8, BE).toString(16).padStart(4, "0"),
    "-",
    view.getUint32(10, BE).toString(16).padStart(8, "0"),
    view.getUint16(14, BE).toString(16).padStart(4, "0"),
  ].join("");
}

/**
 * @param {Uint8Array[]} byteArrays
 * @param {number=} length
 * @returns {Uint8Array}
 */
function concatBytes(
  byteArrays,
  length = byteArrays.reduce((len, bytes) => len + bytes.length, 0)
) {
  const result = new Uint8Array(length);
  let offset = 0;
  for (const bytes of byteArrays) {
    result.set(bytes, offset);
    offset += bytes.length;
  }
  return result;
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
