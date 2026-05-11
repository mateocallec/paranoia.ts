import { existsSync } from 'node:fs';
import { resolve as pathResolve } from 'node:path';
import * as clack from '@clack/prompts';
import pc from 'picocolors';
import { getSecureRandom, wipe, STRONG_ARGON2_PARAMS } from 'paranoia-ts';
import { buildKeysJson, saveKeys, type KeyAlgorithm } from '../lib/keys.js';
import { askPassphraseConfirmed, askConfirm, bail } from '../lib/ui.js';
import { harvestWebcamEntropy, ffmpegAvailable } from '../lib/webcam.js';

interface KeygenOptions { pqc: boolean; trad: boolean; output: string; webcam: boolean }

const LABEL: Record<KeyAlgorithm, string> = {
  'hybrid-mlkem1024-p521': 'Hybrid ML-KEM-1024 + P-521',
  'pqc-mlkem1024':         'ML-KEM-1024 only',
  'classical-p521':        'P-521 only',
};

export async function keygenCommand(opts: KeygenOptions): Promise<void> {
  clack.intro(pc.bold('paranoia keygen'));

  const algo: KeyAlgorithm = opts.pqc && !opts.trad ? 'pqc-mlkem1024'
    : opts.trad && !opts.pqc                         ? 'classical-p521'
    :                                                  'hybrid-mlkem1024-p521';

  clack.log.info(`Algorithm : ${pc.cyan(LABEL[algo])}`);

  const outPath = pathResolve(opts.output);
  if (existsSync(outPath) && !await askConfirm(`${outPath} already exists. Overwrite?`, false))
    bail();

  // ── Webcam TRNG (optional, additive) ─────────────────────────────────────
  let webcamDigest: Uint8Array | null = null;
  if (opts.webcam) {
    if (!ffmpegAvailable()) {
      clack.log.warn('ffmpeg not found — skipping webcam entropy.');
    } else {
      const s = clack.spinner();
      s.start('Harvesting webcam entropy…');
      try {
        webcamDigest = harvestWebcamEntropy();
        s.stop(pc.green('✓') + ' Webcam entropy collected.');
      } catch (e) {
        s.stop(pc.yellow('⚠') + ` ${e instanceof Error ? e.message : e}`);
      }
    }
  }

  // ── Derivation nonce = CSPRNG XOR webcam digest ───────────────────────────
  const sysNonce = getSecureRandom(32);
  const nonce    = new Uint8Array(32);
  for (let i = 0; i < 32; i++)
    nonce[i] = (sysNonce[i] as number) ^ ((webcamDigest?.[i] ?? 0));
  wipe(sysNonce);
  if (webcamDigest) wipe(webcamDigest);

  // ── Passphrase ────────────────────────────────────────────────────────────
  const passphrase = await askPassphraseConfirmed('Master passphrase:');

  // ── Derive + encrypt ──────────────────────────────────────────────────────
  const s = clack.spinner();
  s.start(`Deriving keypair via Argon2id (${STRONG_ARGON2_PARAMS.memory / 1024} MB)…`);

  try {
    const { keysJson, keyPair } = await buildKeysJson(algo, passphrase, nonce, STRONG_ARGON2_PARAMS);
    wipe(keyPair.privateKey.mlkem, keyPair.privateKey.p521);
    saveKeys(outPath, keysJson);

    s.stop(pc.green('✓') + ' Done.');
    clack.note(
      [
        `Algorithm : ${LABEL[algo]}`,
        keysJson.public.mlkem ? `ML-KEM pk  : ${keysJson.public.mlkem.slice(0, 32)}…` : '',
        keysJson.public.p521  ? `P-521  pk  : ${keysJson.public.p521.slice(0, 32)}…`  : '',
        `File      : ${outPath}`,
      ].filter(Boolean).join('\n'),
      'Keys saved',
    );
    clack.outro(pc.green('✓ keys.json written.'));
  } catch (e) {
    s.stop(pc.red('✗') + ' Failed.');
    clack.log.error(e instanceof Error ? e.message : String(e));
    process.exit(1);
  }
}
