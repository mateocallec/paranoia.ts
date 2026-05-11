import { argon2id } from 'hash-wasm';
import { wipe } from './memory';
import { DEFAULT_ARGON2_PARAMS, type Argon2Params } from '../types';

/**
 * Derive key material from a passphrase using Argon2id.
 *
 * @param hashLength  Output size in bytes (default 32). Pass 64 to get both a
 *                    derivation seed and a wrapping key in a single KDF call.
 */
export async function deriveKey(
  passphrase: string | Uint8Array,
  salt: Uint8Array,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
  hashLength = 32,
): Promise<Uint8Array> {
  const ownedPassword =
    typeof passphrase === 'string' ? new TextEncoder().encode(passphrase) : passphrase;

  const key = await argon2id({
    password: ownedPassword,
    salt,
    iterations: params.iterations,
    memorySize: params.memory,
    parallelism: params.parallelism,
    hashLength,
    outputType: 'binary',
  });

  if (typeof passphrase === 'string') wipe(ownedPassword);

  return key;
}
