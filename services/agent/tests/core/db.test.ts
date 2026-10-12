import { afterEach, describe, expect, it } from "vitest";
import { poolConfig, redisConfig } from "../../core/db.js";

const changed = [
  "DATABASE_URL", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_USER",
  "POSTGRES_PASSWORD", "POSTGRES_SSL_MODE", "REDIS_HOST", "REDIS_URL",
] as const;

afterEach(() => {
  for (const name of changed) delete process.env[name];
});

describe("managed data service configuration", () => {
  it("requires certificate verification for an external PostgreSQL service", () => {
    process.env["POSTGRES_HOST"] = "tenant.cluster.example";
    process.env["POSTGRES_SSL_MODE"] = "require";
    expect(poolConfig()).toMatchObject({
      host: "tenant.cluster.example",
      ssl: { rejectUnauthorized: true },
    });
  });

  it("preserves Valkey ACL identity and TLS from a rediss URL", () => {
    process.env["REDIS_URL"] = "rediss://tenant%2Dworker:p%40ss@cache.example:6380/3";
    expect(redisConfig()).toEqual({
      host: "cache.example",
      port: 6380,
      db: 3,
      username: "tenant-worker",
      password: "p@ss",
      tls: {},
    });
  });
});
