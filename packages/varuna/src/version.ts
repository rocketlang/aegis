/**
 * The version that is installed, read from the package itself.
 * Through 0.2.0 /health and the state face said 0.1.0 in every release.
 */
import { readFileSync } from 'node:fs';

export const VERSION: string = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
).version;
