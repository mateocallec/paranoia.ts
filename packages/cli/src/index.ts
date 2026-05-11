import { Command } from 'commander';
import pc from 'picocolors';
import { bootstrap } from './lib/bootstrap.js';

bootstrap();

import { keygenCommand }  from './commands/keygen.js';
import { entropyCommand } from './commands/entropy.js';
import { sealCommand }    from './commands/seal.js';
import { openCommand }    from './commands/open.js';

const program = new Command();

program
  .name('paranoia')
  .description(
    pc.bold('paranoia') + ' — post-quantum hybrid encryption\n\n' +
    pc.dim(
      '  Algorithms : ML-KEM-1024 (FIPS 203) + P-521 ECDH + AES-256-GCM\n' +
      '  KDF        : Argon2id  (512 MB · 5 iterations)\n' +
      '  Entropy    : CSPRNG + optional webcam TRNG (HMAC-SHA3-256)\n' +
      '  Requires   : Node.js ≥ 18',
    ),
  )
  .version(
    '1.0.1\n' +
    pc.dim('Author : Matéo Florian Callec <mateo@callec.net>'),
    '-V, --version',
  );

program
  .command('keygen')
  .description('Generate a keypair and save to keys.json')
  .option('--pqc',    'ML-KEM-1024 only')
  .option('--trad',   'P-521 only')
  .option('--both',   'Hybrid ML-KEM-1024 + P-521 (default)')
  .option('--webcam', 'Mix webcam pixel noise into the derivation nonce')
  .option('-o, --output <path>', 'Output path', 'keys.json')
  .action((opts: { pqc: boolean; trad: boolean; output: string; webcam: boolean }) =>
    keygenCommand(opts).catch(e => { console.error(e); process.exit(1); }),
  );

program
  .command('entropy <bytes>')
  .description('Generate N bytes of entropy and print as hex')
  .option('--webcam', 'Mix webcam pixel noise (HMAC-SHA3-256, additive only)')
  .option('-o, --output <path>', 'Write to file instead of stdout')
  .action((bytes: string, opts: { webcam: boolean; output?: string }) =>
    entropyCommand(bytes, opts).catch(e => { console.error(e); process.exit(1); }),
  );

program
  .command('seal <file>')
  .description('Encrypt a file → <file>.para  (auto-detects algorithm from keys.json)')
  .option('-k, --keys <path>', 'Path to keys.json', 'keys.json')
  .option('-o, --output <path>', 'Output .para path')
  .action((file: string, opts: { keys: string; output?: string }) =>
    sealCommand(file, opts).catch(e => { console.error(e); process.exit(1); }),
  );

program
  .command('open <file>')
  .description('Decrypt a .para file (asks for master passphrase)')
  .option('-k, --keys <path>', 'Path to keys.json', 'keys.json')
  .option('-o, --output <path>', 'Output file path')
  .action((file: string, opts: { keys: string; output?: string }) =>
    openCommand(file, opts).catch(e => { console.error(e); process.exit(1); }),
  );

program.parseAsync(process.argv).catch(e => {
  console.error(pc.red('Fatal:'), e instanceof Error ? e.message : e);
  process.exit(1);
});
