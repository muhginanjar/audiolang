import { hash } from '@node-rs/argon2';

// OWASP-recommended Argon2id parameters (19 MiB, t=2, p=1). Library default algorithm is Argon2id.
export const ARGON_OPTS = { memoryCost: 19456, timeCost: 2, parallelism: 1 };

export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128; // caps hashing cost (DoS protection)

export const hashPassword = (password: string) => hash(password, ARGON_OPTS);
