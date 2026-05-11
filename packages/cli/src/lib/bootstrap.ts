export function bootstrap(): void {
  const [major] = process.version.replace('v', '').split('.').map(Number);
  if ((major ?? 0) < 18) {
    console.error(`\n  paranoia requires Node.js ≥ 18 (you have ${process.version})\n`);
    process.exit(1);
  }

  // CJS output: require() is globally available — no createRequire(import.meta.url) needed.
  // This branch only runs on Node.js 15-17 which the version guard above already rejects.
  if (typeof globalThis.crypto === 'undefined') {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const nodeCrypto = require('crypto') as { webcrypto: typeof globalThis.crypto };
    Object.defineProperty(globalThis, 'crypto', {
      value: nodeCrypto.webcrypto,
      writable: false,
      configurable: true,
    });
  }

  if (typeof globalThis.crypto?.subtle === 'undefined') {
    console.error('\n  SubtleCrypto is not available in this environment.\n');
    process.exit(1);
  }
}
