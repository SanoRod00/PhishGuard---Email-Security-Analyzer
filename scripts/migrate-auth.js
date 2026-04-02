const fs = require("fs");
const path = require("path");
const { Client } = require("pg");
const { buildConfig, assertRuntimeConfig, ROOT_DIR } = require("../src/config");

async function main() {
  const config = buildConfig();
  assertRuntimeConfig(config, { requireDatabase: true });

  const sql = fs.readFileSync(
    path.join(ROOT_DIR, "db", "migrations", "001_auth_schema.sql"),
    "utf8"
  );

  const client = new Client({
    connectionString: config.databaseUrl
  });

  await client.connect();
  await client.query(sql);
  await client.end();

  console.log("Auth schema migration applied.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
