/**
 * Overwrite every byte of each buffer with zeros to reduce the window during
 * which sensitive key material lives in RAM.  JavaScript GC may still hold
 * copies in optimised JIT code, but this is the best we can do without a
 * native allocator.
 */
export function wipe(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const buf of buffers) {
    if (buf instanceof Uint8Array) buf.fill(0);
  }
}

/**
 * Constant-time byte-array comparison.  Returns true only when both arrays
 * are identical in length and content.  The loop always runs to completion so
 * timing reveals neither the position of the first mismatch nor the length
 * difference beyond the boolean return value.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Length check reveals length, which is acceptable for our use-cases
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= (a[i] as number) ^ (b[i] as number);
  }
  return diff === 0;
}

/** Concatenate an arbitrary number of Uint8Arrays into a single new buffer. */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const arr of arrays) {
    out.set(arr, off);
    off += arr.length;
  }
  return out;
}

/** Write a big-endian uint24 into `buf` at `offset`. */
export function writeUint24BE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset]     = (value >>> 16) & 0xff;
  buf[offset + 1] = (value >>> 8)  & 0xff;
  buf[offset + 2] =  value         & 0xff;
}

/** Read a big-endian uint24 from `buf` at `offset`. */
export function readUint24BE(buf: Uint8Array, offset: number): number {
  return ((buf[offset] as number) << 16) |
         ((buf[offset + 1] as number) << 8) |
          (buf[offset + 2] as number);
}

/** Write a big-endian uint32 into `buf` at `offset`. */
export function writeUint32BE(buf: Uint8Array, offset: number, value: number): void {
  buf[offset]     = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8)  & 0xff;
  buf[offset + 3] =  value         & 0xff;
}

/** Read a big-endian uint32 from `buf` at `offset`. */
export function readUint32BE(buf: Uint8Array, offset: number): number {
  return (((buf[offset] as number)     >>> 0) * 0x1000000) +
          ((buf[offset + 1] as number) << 16) +
          ((buf[offset + 2] as number) << 8)  +
           (buf[offset + 3] as number);
}
