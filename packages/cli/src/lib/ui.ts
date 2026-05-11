import * as clack from '@clack/prompts';
import pc from 'picocolors';

export { clack, pc };

export async function askPassphrase(message: string): Promise<string> {
  const value = await clack.password({ message });
  if (clack.isCancel(value)) bail();
  return value as string;
}

export async function askPassphraseConfirmed(message: string): Promise<string> {
  while (true) {
    const pass    = await clack.password({ message });
    if (clack.isCancel(pass)) bail();
    const confirm = await clack.password({ message: 'Confirm passphrase:' });
    if (clack.isCancel(confirm)) bail();
    if (pass === confirm) return pass as string;
    clack.log.warn('Passphrases do not match — try again.');
  }
}

export async function askConfirm(message: string, initialValue = false): Promise<boolean> {
  const value = await clack.confirm({ message, initialValue });
  if (clack.isCancel(value)) bail();
  return value as boolean;
}

export function bail(message = 'Cancelled.'): never {
  clack.cancel(message);
  process.exit(0);
}
