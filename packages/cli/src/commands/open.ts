import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import * as clack from '@clack/prompts';
import pc from 'picocolors';
import {
  hybridDecapsulate,
  decapsulatePqc,
  decapsulateP521,
  aesGcmDecrypt,
  wipe,
} from 'paranoia-ts';
import { loadKeys, unlockPrivateKey } from '../lib/keys.js';
import {
  decodePara,
  getMlkemCt,
  getP521EphPk,
  getNonce,
  MODE_PQC,
  MODE_P521,
  MODE_HYBRID,
} from '../lib/para-format.js';
import { askPassphrase, askConfirm, bail } from '../lib/ui.js';

interface OpenOptions {
  keys: string;
  output?: string;
}

export async function openCommand(inputPath: string, opts: OpenOptions): Promise<void> {
  const absInput = resolve(inputPath);
  const absKeys = resolve(opts.keys);

  clack.intro(pc.bold('paranoia open'));

  if (!existsSync(absInput)) {
    clack.log.error(`Not found: ${absInput}`);
    process.exit(1);
  }
  if (!existsSync(absKeys)) {
    clack.log.error(`Not found: ${absKeys}`);
    process.exit(1);
  }

  const { mode, header, payload } = decodePara(readFileSync(absInput));

  const modeLabel: Record<number, string> = {
    [MODE_PQC]: 'ML-KEM-1024',
    [MODE_P521]: 'P-521 ECDH',
    [MODE_HYBRID]: 'Hybrid ML-KEM-1024 + P-521',
  };
  clack.log.info(`Sealed with: ${pc.cyan(modeLabel[mode] ?? `0x${mode.toString(16)}`)}`);
  clack.log.info(`Original   : ${header.originalName} (${header.originalSize} B)`);

  const absOutput = resolve(opts.output ?? join(dirname(absInput), header.originalName));
  if (existsSync(absOutput) && !(await askConfirm(`${absOutput} exists. Overwrite?`, false)))
    bail();

  const passphrase = await askPassphrase('Master passphrase:');

  const s = clack.spinner();
  s.start('Deriving key material…');

  try {
    const keysJson = loadKeys(absKeys);
    const privKey = await unlockPrivateKey(keysJson, passphrase);
    s.stop(pc.green('✓') + ' Private key unlocked.');

    const s2 = clack.spinner();
    s2.start('Decrypting…');

    const nonce = getNonce(header);
    let plaintext: Uint8Array;

    if (mode === MODE_HYBRID) {
      // library hybridDecapsulate: ML-KEM-1024 + P-521
      const mlkemCt = getMlkemCt(header);
      const p521EphPk = getP521EphPk(header);
      const kemCt = new Uint8Array(mlkemCt.length + p521EphPk.length);
      kemCt.set(mlkemCt);
      kemCt.set(p521EphPk, mlkemCt.length);
      const sharedSecret = await hybridDecapsulate(kemCt, privKey);
      wipe(privKey.mlkem, privKey.p521);
      plaintext = await aesGcmDecrypt(payload, sharedSecret, nonce);
      wipe(sharedSecret);
    } else if (mode === MODE_PQC) {
      // library decapsulatePqc: ML-KEM-1024 only
      const sharedSecret = await decapsulatePqc(getMlkemCt(header), privKey.mlkem);
      wipe(privKey.mlkem);
      plaintext = await aesGcmDecrypt(payload, sharedSecret, nonce);
      wipe(sharedSecret);
    } else {
      // library decapsulateP521: P-521 only
      const sharedSecret = await decapsulateP521(getP521EphPk(header), privKey.p521);
      wipe(privKey.p521);
      plaintext = await aesGcmDecrypt(payload, sharedSecret, nonce);
      wipe(sharedSecret);
    }

    writeFileSync(absOutput, plaintext);
    wipe(plaintext);

    s2.stop(pc.green('✓') + ' Decrypted.');
    clack.outro(`${pc.green('✓')} ${absOutput}  ${pc.dim(`(${header.originalSize} B)`)}`);
  } catch (e) {
    s.stop(pc.red('✗') + ' Failed.');
    clack.log.error(e instanceof Error ? e.message : String(e));
    clack.log.warn('Wrong passphrase, wrong keys.json, or corrupted .para file.');
    process.exit(1);
  }
}
