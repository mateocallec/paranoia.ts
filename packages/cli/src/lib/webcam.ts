/**
 * Node.js webcam entropy via ffmpeg.
 * Captures pixel noise from camera frames, hashes with SHA-3-256,
 * and mixes with crypto.randomBytes() via HMAC so the result is always
 * at least as strong as system CSPRNG alone.
 */

import { spawnSync } from 'child_process';
import { tmpdir }    from 'os';
import { join }      from 'path';
import { readFileSync, unlinkSync, existsSync } from 'fs';
import { randomBytes } from 'crypto';
import { sha3_256 } from '@noble/hashes/sha3';
import { hmac }     from '@noble/hashes/hmac';

const FRAME_COUNT   = 8;
const CAPTURE_SIZE  = '64x64';

const PLATFORM_CONFIGS: Array<{
  format:    string;
  deviceFn:  (i: number) => string;
  platforms: NodeJS.Platform[];
}> = [
  { format: 'v4l2',        deviceFn: i => `/dev/video${i}`,  platforms: ['linux']  },
  { format: 'avfoundation', deviceFn: i => String(i),         platforms: ['darwin'] },
  { format: 'dshow',       deviceFn: i => `video=${i}`,       platforms: ['win32']  },
];

function captureFrames(deviceIndex: number): Uint8Array[] {
  const cfg = PLATFORM_CONFIGS.find(c => c.platforms.includes(process.platform));
  if (!cfg) throw new Error(`Webcam capture not supported on ${process.platform}`);

  const frames: Uint8Array[] = [];
  for (let i = 0; i < FRAME_COUNT; i++) {
    const out = join(tmpdir(), `paranoia-entropy-${Date.now()}-${i}.raw`);
    spawnSync('ffmpeg', [
      '-hide_banner', '-loglevel', 'error',
      '-f', cfg.format, '-i', cfg.deviceFn(deviceIndex),
      '-frames:v', '1', '-vf', `scale=${CAPTURE_SIZE}`,
      '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-y', out,
    ], { stdio: 'pipe', timeout: 8000 });
    if (existsSync(out)) {
      try { frames.push(new Uint8Array(readFileSync(out))); } finally { unlinkSync(out); }
    }
  }
  return frames;
}

export function harvestWebcamEntropy(deviceIndex = 0): Uint8Array {
  const frames = captureFrames(deviceIndex);
  if (!frames.length) throw new Error('No webcam frames captured — is ffmpeg installed and a camera connected?');

  const h = sha3_256.create();
  for (const f of frames) h.update(f);
  const sysRand = randomBytes(32);
  h.update(sysRand);
  const digest = h.digest();

  // HMAC(key=fresh_sys_rand, data=digest): can only add entropy, never remove it
  const sysRand2 = randomBytes(32);
  const mixed    = hmac(sha3_256, sysRand2, digest);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = (sysRand2[i] as number) ^ (mixed[i] as number);
  return out;
}

export function ffmpegAvailable(): boolean {
  return spawnSync('ffmpeg', ['-version'], { stdio: 'pipe', timeout: 2000 }).status === 0;
}
