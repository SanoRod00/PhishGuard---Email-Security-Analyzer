const { buildConfig, assertRuntimeConfig } = require("./src/config");
const { createApp } = require("./src/app");
const { PostgresRepository } = require("./src/repositories/postgresRepository");
const { createEmailService } = require("./src/emailService");

const config = buildConfig();
assertRuntimeConfig(config);

const repository = new PostgresRepository(config.databaseUrl);
const emailService = createEmailService(config);
const app = createApp({ config, repository, emailService });

app.listen(config.port, config.host, () => {
  console.log(`PhishGuard is running on http://${config.host}:${config.port}`);
});
