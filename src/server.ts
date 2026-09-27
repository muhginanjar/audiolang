import { buildApp } from './app.js';
import { config } from './config.js';

const app = await buildApp();

for (const sig of ['SIGINT', 'SIGTERM'] as const) {
  process.on(sig, async () => {
    app.log.info(`${sig} received, shutting down`);
    await app.close();
    process.exit(0);
  });
}

try {
  await app.listen({ port: config.port, host: config.host });
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
