import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import * as clack from '@clack/prompts';
import pc from 'picocolors';
import {
  hybridEncapsulate,
  encapsulatePqc,
  encapsulateP521,
  aesGcmEncrypt,
  getSecureRandom,
  wipe,
} from 'paranoia-ts';
import { loadKeys, detectMode, getPublicKeyBytes } from '../lib/keys.js';
import {
  encodePara, buildHeader, defaultParaPath,
  MODE_PQC, MODE_P521, MODE_HYBRID,
} from '../lib/para-format.js';

interface SealOptions { keys: string; output?: string }

export async function sealCommand(inputPath: string, opts: SealOptions): Promise<void> {
  const absInput  = resolve(inputPath);
  const absKeys   = resolve(opts.keys);

  clack.intro(pc.bold('paranoia seal'));

  if (!existsSync(absInput)) { clack.log.error(`Not found: ${absInput}`); process.exit(1); }
  if (!existsSync(absKeys))  { clack.log.error(`Not found: ${absKeys}`);  process.exit(1); }

  const plaintext = readFileSync(absInput);
  const keysJson  = loadKeys(absKeys);
  const mode      = detectMode(keysJson);
  const pubKey    = getPublicKeyBytes(keysJson);
  const absOutput = resolve(opts.output ?? defaultParaPath(absInput));

  clack.log.info(`Input  : ${absInput} (${plaintext.length} B)`);
  clack.log.info(`Mode   : ${pc.cyan(mode)} (auto-detected)`);

  const s = clack.spinner();
  s.start('Encrypting…');

  try {
    const nonce = getSecureRandom(12);
    let paraBuffer: Buffer;

    if (mode === 'hybrid') {
      // library hybridEncapsulate: ML-KEM-1024 + P-521 → shared secret
      const { ciphertext: kemCt, sharedSecret } = await hybridEncapsulate(pubKey);
      const ct  = await aesGcmEncrypt(new Uint8Array(plaintext), sharedSecret, nonce);
      wipe(sharedSecret);
      const mlkemCt   = kemCt.slice(0, 1568);
      const p521EphPk = kemCt.slice(1568);
      paraBuffer = encodePara(MODE_HYBRID, buildHeader(absInput, plaintext.length, nonce, mlkemCt, p521EphPk), ct);

    } else if (mode === 'pqc') {
      // library encapsulatePqc: ML-KEM-1024 only
      const { ciphertext: mlkemCt, sharedSecret } = await encapsulatePqc(pubKey.mlkem);
      const ct = await aesGcmEncrypt(new Uint8Array(plaintext), sharedSecret, nonce);
      wipe(sharedSecret);
      paraBuffer = encodePara(MODE_PQC, buildHeader(absInput, plaintext.length, nonce, mlkemCt), ct);

    } else {
      // library encapsulateP521: P-521 ephemeral ECDH only
      const { ephemeralPublicKey, sharedSecret } = await encapsulateP521(pubKey.p521);
      const ct = await aesGcmEncrypt(new Uint8Array(plaintext), sharedSecret, nonce);
      wipe(sharedSecret);
      paraBuffer = encodePara(MODE_P521, buildHeader(absInput, plaintext.length, nonce, undefined, ephemeralPublicKey), ct);
    }

    writeFileSync(absOutput, paraBuffer);
    s.stop(pc.green('✓') + ' File sealed.');
    clack.outro(`${pc.green('✓')} ${absOutput}  ${pc.dim(`(${paraBuffer.length} B)`)}`);
  } catch (e) {
    s.stop(pc.red('✗') + ' Failed.');
    clack.log.error(e instanceof Error ? e.message : String(e));
    process.exit(1);
  }
}
