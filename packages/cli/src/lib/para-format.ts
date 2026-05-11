/**
 * .para binary container format.
 *
 *   [4B]  magic   "PARA"
 *   [1B]  version 0x01
 *   [1B]  mode    0x01=pqc | 0x02=p521 | 0x03=hybrid
 *   [4B]  hdrLen  big-endian uint32
 *   [N]   JSON header (UTF-8)
 *   [M]   AES-256-GCM ciphertext + 16-byte auth tag
 */

import { basename, join, dirname } from 'path';

const MAGIC = Buffer.from('PARA');
const VERSION = 0x01;

export const MODE_PQC = 0x01;
export const MODE_P521 = 0x02;
export const MODE_HYBRID = 0x03;

export interface ParaHeader {
  originalName: string;
  originalSize: number;
  timestamp: number;
  nonce: string; // base64(12B)
  mlkemCt?: string; // base64(1568B)
  p521EphPk?: string; // base64(67B)
}

const b64e = (u: Uint8Array) => Buffer.from(u).toString('base64');
const b64d = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

// ─── Encode ───────────────────────────────────────────────────────────────────

export function encodePara(mode: number, header: ParaHeader, ciphertext: Uint8Array): Buffer {
  const hdrJson = Buffer.from(JSON.stringify(header), 'utf8');
  const hdrLen = Buffer.alloc(4);
  hdrLen.writeUInt32BE(hdrJson.length, 0);
  return Buffer.concat([
    MAGIC,
    Buffer.from([VERSION, mode]),
    hdrLen,
    hdrJson,
    Buffer.from(ciphertext),
  ]);
}

export function defaultParaPath(input: string): string {
  return `${input}.para`;
}
export function defaultOpenPath(para: string, originalName: string, outDir: string): string {
  return join(outDir || dirname(para), originalName);
}

// ─── Decode ───────────────────────────────────────────────────────────────────

export interface ParsedPara {
  mode: number;
  header: ParaHeader;
  payload: Uint8Array;
}

export function decodePara(data: Buffer): ParsedPara {
  if (!data.subarray(0, 4).equals(MAGIC)) throw new Error('Not a .para file (invalid magic)');
  if (data[4] !== VERSION)
    throw new Error(`Unsupported .para version: 0x${(data[4] as number).toString(16)}`);

  const mode = data[5] as number;
  const hdrLen = data.readUInt32BE(6);
  const hdrEnd = 10 + hdrLen;

  if (data.length < hdrEnd + 1) throw new Error('Truncated .para file');

  return {
    mode,
    header: JSON.parse(data.subarray(10, hdrEnd).toString('utf8')) as ParaHeader,
    payload: new Uint8Array(data.subarray(hdrEnd)),
  };
}

// ─── Header builders ──────────────────────────────────────────────────────────

export function buildHeader(
  file: string,
  size: number,
  nonce: Uint8Array,
  mlkemCt?: Uint8Array,
  p521EphPk?: Uint8Array,
): ParaHeader {
  return {
    originalName: basename(file),
    originalSize: size,
    timestamp: Date.now(),
    nonce: b64e(nonce),
    ...(mlkemCt && { mlkemCt: b64e(mlkemCt) }),
    ...(p521EphPk && { p521EphPk: b64e(p521EphPk) }),
  };
}

// ─── Header extractors ────────────────────────────────────────────────────────

export const getNonce = (h: ParaHeader) => b64d(h.nonce);
export const getMlkemCt = (h: ParaHeader) => {
  if (!h.mlkemCt) throw new Error('No ML-KEM ciphertext in .para header');
  return b64d(h.mlkemCt);
};
export const getP521EphPk = (h: ParaHeader) => {
  if (!h.p521EphPk) throw new Error('No P-521 ephemeral key in .para header');
  return b64d(h.p521EphPk);
};
