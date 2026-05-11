import { writeFileSync } from 'node:fs';
import * as clack from '@clack/prompts';
import pc from 'picocolors';
import { getSecureRandom, injectEntropy } from 'paranoia-ts';
import { harvestWebcamEntropy, ffmpegAvailable } from '../lib/webcam.js';

interface EntropyOptions { webcam: boolean; output?: string }

export async function entropyCommand(bytesArg: string, opts: EntropyOptions): Promise<void> {
  const bytes = parseInt(bytesArg, 10);
  if (isNaN(bytes) || bytes < 1 || bytes > 65536) {
    clack.log.error('bytes must be an integer between 1 and 65536');
    process.exit(1);
  }

  // Optionally inject webcam entropy into the library's pool before sampling.
  // After injectEntropy(), every getSecureRandom() call uses the mixed pool.
  if (opts.webcam) {
    if (!ffmpegAvailable()) {
      clack.log.warn('ffmpeg not found — using system CSPRNG only.');
    } else {
      const s = clack.spinner();
      s.start('Capturing webcam frames…');
      try {
        const digest = harvestWebcamEntropy();
        injectEntropy(digest);  // library handles the HMAC-SHA3-256 mixing
        digest.fill(0);
        s.stop(pc.green('✓') + ' Webcam entropy injected into library pool.');
      } catch (e) {
        s.stop(pc.yellow('⚠') + ` ${e instanceof Error ? e.message : e}`);
      }
    }
  }

  // Use library's getSecureRandom — now webcam-enhanced if --webcam was passed
  const random = getSecureRandom(bytes);
  const hex    = Buffer.from(random).toString('hex');
  random.fill(0);

  if (opts.output) {
    writeFileSync(opts.output, hex + '\n', 'utf8');
    clack.log.success(`${bytes} bytes written to ${opts.output}`);
  } else {
    process.stdout.write(hex + '\n');
  }
}
