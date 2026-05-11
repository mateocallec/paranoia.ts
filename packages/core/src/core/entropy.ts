import { sha3_256 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { wipe } from './memory';

// ─── Internal state ───────────────────────────────────────────────────────────

let webcamPool: Uint8Array | null = null;
let webcamActive = false;
let webcamRefreshTimer: ReturnType<typeof setInterval> | null = null;

// ─── Core entropy function ────────────────────────────────────────────────────

/**
 * Return `length` bytes of cryptographically secure random data.
 *
 * When webcam entropy is active, the output is:
 *   HMAC-SHA3-256(key=systemRandom, data=webcamPool) XOR systemRandom
 *
 * This construction is additive — it can only increase entropy compared to
 * the raw system PRNG, never decrease it, even if the webcam feed is
 * constant or adversarially controlled.
 */
export function getSecureRandom(length: number): Uint8Array {
  const sys = new Uint8Array(length);
  crypto.getRandomValues(sys);

  if (!webcamActive || webcamPool === null) return sys;

  // HMAC(key=sys, data=pool) ensures webcam input cannot cancel system randomness
  const contribution = hmac(sha3_256, sys, webcamPool);
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    out[i] = (sys[i] as number) ^ (contribution[i % contribution.length] as number);
  }
  wipe(sys);
  return out;
}

// ─── Webcam entropy harvesting ────────────────────────────────────────────────

/**
 * Capture pixel noise from several webcam frames, hash them with SHA-3-256,
 * and mix in fresh system randomness so the result has forward security even
 * if the camera feed is dark or static.
 */
export async function harvestWebcamEntropy(stream: MediaStream): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const video = document.createElement('video');
    video.srcObject = stream;
    video.muted = true;
    video.playsInline = true;

    video.onerror = () => reject(new Error('Video element error during entropy harvest'));

    video.onloadedmetadata = () => {
      video.play().catch(reject);

      const FRAMES = 8;
      const W = Math.min(video.videoWidth  || 64, 64);
      const H = Math.min(video.videoHeight || 64, 64);
      const frames: Uint8Array[] = [];

      const captureFrame = () => {
        const canvas = document.createElement('canvas');
        canvas.width = W;
        canvas.height = H;
        const ctx = canvas.getContext('2d');
        if (!ctx) { reject(new Error('Canvas 2D unavailable')); return; }
        ctx.drawImage(video, 0, 0, W, H);
        frames.push(new Uint8Array(ctx.getImageData(0, 0, W, H).data.buffer));

        if (frames.length < FRAMES) {
          requestAnimationFrame(captureFrame);
          return;
        }

        video.pause();

        // Hash all frames together with SHA-3-256
        const h = sha3_256.create();
        for (const f of frames) h.update(f);

        // Mix in fresh system randomness — forward security even if frames leak
        const sysRand = new Uint8Array(32);
        crypto.getRandomValues(sysRand);
        h.update(sysRand);
        wipe(sysRand);

        resolve(h.digest());
      };

      requestAnimationFrame(captureFrame);
    };
  });
}

/**
 * Start mixing webcam-derived entropy into every `getSecureRandom` call.
 * The pool is refreshed every 10 s; each refresh is XOR-mixed with the
 * existing pool so old randomness is never fully discarded.
 *
 * Requires a live `MediaStream` (obtained via `getUserMedia`).
 */
export async function enableWebcamEntropy(stream: MediaStream): Promise<void> {
  // M1: clear any existing timer before starting a new one to prevent leaks
  if (webcamRefreshTimer !== null) {
    clearInterval(webcamRefreshTimer);
    webcamRefreshTimer = null;
  }
  const initial = await harvestWebcamEntropy(stream);
  webcamPool = initial;
  webcamActive = true;

  webcamRefreshTimer = setInterval(async () => {
    if (!webcamActive) return;
    try {
      const fresh = await harvestWebcamEntropy(stream);
      if (webcamPool !== null) {
        // Mix: HMAC(key=existingPool, data=freshEntropy) — ratchets forward
        const mixed = hmac(sha3_256, webcamPool, fresh);
        wipe(webcamPool);
        webcamPool = mixed;
      } else {
        webcamPool = fresh;
      }
    } catch {
      disableWebcamEntropy();
    }
  }, 10_000);
}

/**
 * Inject external entropy into the pool used by `getSecureRandom`.
 *
 * Use this in environments where `enableWebcamEntropy` is unavailable
 * (e.g. Node.js CLI) after harvesting entropy through another mechanism.
 * The injection is additive — it cannot reduce the existing entropy level.
 *
 *   new pool = HMAC-SHA3-256(key=existingPool || systemRandom, data=entropy)
 */
export function injectEntropy(entropy: Uint8Array): void {
  const sys = new Uint8Array(32);
  crypto.getRandomValues(sys);
  // L2: concatenated key is a separate buffer that must be wiped after HMAC
  const key = webcamPool !== null
    ? new Uint8Array([...webcamPool, ...sys])
    : sys;
  const newPool = hmac(sha3_256, key, entropy);
  if (webcamPool) wipe(webcamPool);
  if (key !== sys) wipe(key); // wipe the concatenated buffer (not when key === sys)
  wipe(sys);
  webcamPool   = newPool;
  webcamActive = true;
}

/** Stop webcam entropy collection and wipe the pool from memory. */
export function disableWebcamEntropy(): void {
  if (webcamRefreshTimer !== null) {
    clearInterval(webcamRefreshTimer);
    webcamRefreshTimer = null;
  }
  if (webcamPool) {
    wipe(webcamPool);
    webcamPool = null;
  }
  webcamActive = false;
}

export function isWebcamEntropyActive(): boolean {
  return webcamActive;
}
