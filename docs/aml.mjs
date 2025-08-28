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

/**
 * @typedef {Uint8Array<ArrayBuffer>} bytes
 */

/**
 * @param {string} name
 * @param {bytes[]} terms
 * @returns {bytes}
 */
export function defineDevice(name, terms) {
  return concatBytes([
    ops.device,
    encodePackage(concatBytes([makeNameString(name), ...terms])),
  ]);
}

/**
 * @param {string} name
 * @param {bytes[]} terms
 * @returns {bytes}
 */
export function defineScope(name, terms) {
  return concatBytes([
    ops.scope,
    encodePackage(concatBytes([makeNameString(name), ...terms])),
  ]);
}

/**
 * @param {string} name
 * @param {bytes} data
 * @returns {bytes}
 */
export function defineName(name, data) {
  return concatBytes([new Uint8Array([0x08]), makeNameString(name), data]);
}

/**
 * @param {string} name
 * @param {number} argCount
 * @param {boolean} isSerialized
 * @param {number} syncLevel
 * @param {bytes[]} terms
 * @returns {bytes}
 */
export function defineMethod(name, argCount, isSerialized, syncLevel, terms) {
  const flags =
    (syncLevel & (0x0f << 4)) | (isSerialized ? 0x08 : 0) | (argCount & 0x07);

  return concatBytes([
    ops.method,
    encodePackage(
      concatBytes([makeNameString(name), new Uint8Array([flags]), ...terms])
    ),
  ]);
}

/**
 * @param {string} name
 * @param {number} id
 * @param {number} publicAddress
 * @param {publicLength} publicAddress
 * @param {bytes[]} terms
 * @returns {bytes}
 * @param {number} publicLength
 */
export function defineProcessor(name, id, publicAddress, publicLength, terms) {
  const header = new Uint8Array(6);
  const headerView = new DataView(header.buffer);
  header[0] = id & 0xff;
  headerView.setUint32(1, publicAddress, LE);
  header[5] = publicLength & 0xff;
  return concatBytes([
    ops.processor,
    encodePackage(concatBytes([makeNameString(name), header, ...terms])),
  ]);
}

/**
 * @param {bytes} term
 * @returns {bytes}
 */
export function defineReturn(term) {
  return concatBytes([ops.return, term]);
}

/**
 * @param {string} name
 * @param {bytes[]} args
 * @returns {bytes}
 */
export function invokeMethod(name, args) {
  return concatBytes([makeNameString(name), ...args]);
}

/**
 * @param {bytes} data
 * @returns {bytes}
 */
export function defineBuffer(data) {
  return concatBytes([
    ops.buffer,
    encodePackage(concatBytes([makeInteger(data.length), data])),
  ]);
}

/**
 * @param {bytes} predicate
 * @param {bytes[]} terms
 * @returns {bytes}
 */
export function defineIf(predicate, terms) {
  return concatBytes([
    new Uint8Array([0xa0]),
    encodePackage(concatBytes([predicate, ...terms])),
  ]);
}

/**
 * @param {bytes} obj
 * @param {bytes} value
 */
export function defineNotify(obj, value) {
  return concatBytes([new Uint8Array([0x86]), obj, value]);
}

/**
 * @param {bytes} predicate
 * @param {bytes[]} terms
 * @returns {bytes}
 */
export function defineWhile(predicate, terms) {
  return concatBytes([
    new Uint8Array([0xa2]),
    encodePackage(concatBytes([predicate, ...terms])),
  ]);
}

/**
 * @param {bytes} left
 * @param {bytes} right
 * @returns {bytes}
 */
export function defineEqual(left, right) {
  return concatBytes([ops.equal, left, right]);
}

/**
 * @param {bytes} left
 * @param {bytes} right
 * @returns {bytes}
 */
export function defineLess(left, right) {
  return concatBytes([ops.less, left, right]);
}

/**
 * @param {bytes} left
 * @param {bytes} right
 * @returns {bytes}
 */
export function defineAnd(left, right) {
  return concatBytes([ops.and, left, right]);
}

/**
 * @param {boolean} isCacheable
 * @param {number} granularity
 * @param {number} rangeMin
 * @param {number} rangeMax
 * @param {number} translationOffset
 * @param {number} length
 * @returns {bytes}
 */
export function defineDWordMemory(
  isCacheable,
  granularity,
  rangeMin,
  rangeMax,
  translationOffset,
  length
) {
  const result = new Uint8Array(26);
  const view = new DataView(result.buffer);
  result[0] = 0x87;
  view.setUint16(1, 23, LE);
  result[3] = 0x00;
  result[4] = 0x0c;
  result[5] = isCacheable ? 0x03 : 0x01;
  view.setUint32(6, granularity, LE);
  view.setUint32(10, rangeMin, LE);
  view.setUint32(14, rangeMax, LE);
  view.setUint32(18, translationOffset, LE);
  view.setUint32(22, length, LE);
  return result;
}

/**
 * @param {boolean} isCacheable
 * @param {bigint} granularity
 * @param {bigint} rangeMin
 * @param {bigint} rangeMax
 * @param {bigint} translationOffset
 * @param {bigint} length
 * @returns {bytes}
 */
export function defineQWordMemory(
  isCacheable,
  granularity,
  rangeMin,
  rangeMax,
  translationOffset,
  length
) {
  const result = new Uint8Array(46);
  const view = new DataView(result.buffer);
  result[0] = 0x8a;
  view.setUint16(1, 43, LE);
  result[3] = 0x00;
  result[4] = 0x0c;
  result[5] = isCacheable ? 0x03 : 0x01;
  view.setBigUint64(6, granularity, LE);
  view.setBigUint64(14, rangeMin, LE);
  view.setBigUint64(22, rangeMax, LE);
  view.setBigUint64(30, translationOffset, LE);
  view.setBigUint64(38, length, LE);
  return result;
}

/**
 * @param {string} name
 * @returns {bytes}
 */
export function makeNameString(name) {
  let segments = name.split(".");

  const result = [];
  if (
    (segments.length > 0 && segments[0].startsWith("\\")) ||
    segments[0].startsWith("^")
  ) {
    result.push(new Uint8Array([segments[0].charCodeAt(0)]));
    segments[0] = segments[0].slice(1);
    if (!segments[0]) {
      segments = segments.slice(1);
    }
  }

  switch (segments.length) {
    case 0:
      result.push(new Uint8Array([0x00]));
      break;
    case 1:
      result.push(encodeNameSegment(segments[0]));
      break;
    case 2:
      result.push(new Uint8Array([0x2e]));
      result.push(encodeNameSegment(segments[0]));
      result.push(encodeNameSegment(segments[1]));
      break;
    default:
      result.push(new Uint8Array([0x2f]));
      result.push(new Uint8Array([segments.length]));
      for (let segment of segments) {
        result.push(encodeNameSegment(segment));
      }
  }

  return concatBytes(result);
}

/**
 * @param {string} segment
 * @returns {bytes}
 */
function encodeNameSegment(segment) {
  return utf8encoder.encode(segment.padEnd(4, "_"));
}

/**
 * @param {bytes} payload
 * @returns {bytes}
 */
function encodePackage(payload) {
  return concatBytes([encodePackageLength(payload.length), payload]);
}

/**
 * @param {number} payloadLength
 * @returns {bytes}
 */
function encodePackageLength(payloadLength) {
  /**
   * @param {number} length
   * @returns {number[]}
   */
  function encode(length) {
    if (length < 0x40) {
      return [length & 0x3f];
    }

    if (length < 0x1000) {
      return [0x40 | (length & 0x0f), (length >> 4) & 0xff];
    }

    if (length < 0x100000) {
      return [
        0x80 | (length & 0x0f),
        (length >> 4) & 0xff,
        (length >> 12) & 0xff,
      ];
    }

    if (length < 0x10000000) {
      return [
        0xc0 | (length & 0x0f),
        (length >> 4) & 0xff,
        (length >> 12) & 0xff,
        (length >> 20) & 0xff,
      ];
    }

    throw new Error("Package is too large");
  }

  let encoded = encode(payloadLength);
  let totalLength = payloadLength + encoded.length;
  let newEncoded = encode(totalLength);

  if (newEncoded.length !== encoded.length) {
    totalLength = payloadLength + newEncoded.length;
    newEncoded = encode(totalLength);
  }

  return new Uint8Array(newEncoded);
}

/**
 * @param {number} i
 * @returns {bytes}
 */
export function makeInteger(i) {
  if (i < 0) {
    throw new Error("expected non-negative");
  }
  if (i <= 1) {
    return new Uint8Array([i]);
  }
  if (i <= 0xff) {
    return new Uint8Array([0x0a, i]);
  }
  if (i <= 0xffff) {
    const result = new Uint8Array(3);
    const view = new DataView(result.buffer);
    result[0] = 0x0b;
    view.setUint16(1, i, LE);
    return result;
  }
  if (i <= 0xffffffff) {
    const result = new Uint8Array(5);
    const view = new DataView(result.buffer);
    result[0] = 0x0c;
    view.setUint32(1, i, LE);
    return result;
  }
  const result = new Uint8Array(9);
  const view = new DataView(result.buffer);
  result[0] = 0x0e;
  view.setBigUint64(1, BigInt(i), LE);
  return result;
}

export const ops = {
  scope: new Uint8Array([0x10]),
  buffer: new Uint8Array([0x11]),
  method: new Uint8Array([0x14]),
  device: new Uint8Array([0x5b, 0x82]),
  processor: new Uint8Array([0x5b, 0x83]),
  local0: new Uint8Array([0x60]),
  local1: new Uint8Array([0x61]),
  local2: new Uint8Array([0x62]),
  local3: new Uint8Array([0x63]),
  local4: new Uint8Array([0x64]),
  local5: new Uint8Array([0x65]),
  local6: new Uint8Array([0x66]),
  local7: new Uint8Array([0x67]),
  arg0: new Uint8Array([0x68]),
  arg1: new Uint8Array([0x69]),
  arg2: new Uint8Array([0x6a]),
  arg3: new Uint8Array([0x6b]),
  arg4: new Uint8Array([0x6c]),
  arg5: new Uint8Array([0x6d]),
  arg6: new Uint8Array([0x6e]),
  and: new Uint8Array([0x90]),
  equal: new Uint8Array([0x93]),
  less: new Uint8Array([0x95]),
  return: new Uint8Array([0xa4]),
};

const utf8encoder = new TextEncoder();
const LE = true;

/**
 * @param {bytes[]} byteArrays
 * @param {number=} length
 * @returns {bytes}
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
