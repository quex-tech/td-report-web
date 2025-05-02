# tdx-measurement-verify

A JS module to reproduce Intel® TDX RTMR and MRTD measurements.

Use online: [verify.quex.tech](https://verify.quex.tech/)

## Example usage

```js
import {
  parseFirmware,
  reproduceMrtd,
  reproduceRtmr,
} from 'tdx-measurement-verify';

const td = {
  hardware: {
    totalMemoryBytes: 2*1024*1024*1024,
    acpiTables: acpiTablesBytes, // contents of /sys/firmware/qemu_fw_cfg/by_name/etc/acpi/tables/raw
  },
  parseFirmware(firmwareBytes), // OVMF.fd
  software: {
    kernel: ukiBytes
  },
};

const mrtd = await reproduceMrtd(td.firmware);
const { rtmrRegisters, rtmrEvents } = await reproduceRtmr(td);
```
