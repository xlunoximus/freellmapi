import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest';
import { initDb, getDb } from '../../db/index.js';
import { encrypt } from '../../lib/crypto.js';
import {
  getAllPenalties,
  recordRateLimitHit,
  routeRequest,
  setRoutingStrategy,
} from '../../services/router.js';

describe('Router', () => {
  beforeAll(() => {
    process.env.ENCRYPTION_KEY = '0'.repeat(64);
    initDb(':memory:');
  });

  beforeEach(() => {
    const db = getDb();
    // These cases assert the manual priority order specifically; pin it so the
    // bandit (now the default strategy) doesn't reorder by score.
    setRoutingStrategy('priority');
    db.prepare('DELETE FROM api_keys').run();
    // Disable active profile so the router falls back to fallback_config
    db.prepare("DELETE FROM settings WHERE key = 'active_profile_id'").run();
    // Reset fallback order to intelligence ranking
    const models = db.prepare('SELECT id, intelligence_rank FROM models ORDER BY intelligence_rank ASC').all() as any[];
    const update = db.prepare('UPDATE fallback_config SET priority = ? WHERE model_db_id = ?');
    for (let i = 0; i < models.length; i++) {
      update.run(i + 1, models[i].id);
    }
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should throw when no keys are configured', () => {
    expect(() => routeRequest()).toThrow(/exhausted/i);
  });

  it('should route to highest priority model with available key', () => {
    const db = getDb();
    const { encrypted, iv, authTag } = encrypt('test-groq-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('groq', 'test', encrypted, iv, authTag, 'healthy', 1);

    const result = routeRequest();
    expect(result.platform).toBe('groq');
    expect(result.apiKey).toBe('test-groq-key');
  });

  it('should prefer higher-priority model when keys exist for multiple platforms', () => {
    const db = getDb();

    const googleKey = encrypt('test-google-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('google', 'test', googleKey.encrypted, googleKey.iv, googleKey.authTag, 'healthy', 1);

    const groqKey = encrypt('test-groq-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('groq', 'test', groqKey.encrypted, groqKey.iv, groqKey.authTag, 'healthy', 1);

    // Post-V6: Google's gemini-3.1-pro-preview (rank 1, free-tier-eligible per
    // probe on 2026-04-25) outranks Groq's best free-tier model openai/gpt-oss-120b
    // (rank 6). With keys for both platforms, Google wins.
    const result = routeRequest();
    expect(result.platform).toBe('google');
  });

  it('should skip disabled keys', () => {
    const db = getDb();

    const googleKey = encrypt('test-google-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('google', 'disabled', googleKey.encrypted, googleKey.iv, googleKey.authTag, 'healthy', 0);

    const groqKey = encrypt('test-groq-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('groq', 'test', groqKey.encrypted, groqKey.iv, groqKey.authTag, 'healthy', 1);

    const result = routeRequest();
    expect(result.platform).toBe('groq');
  });

  it('should skip invalid keys', () => {
    const db = getDb();

    const invalidKey = encrypt('invalid-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('google', 'invalid', invalidKey.encrypted, invalidKey.iv, invalidKey.authTag, 'invalid', 1);

    const groqKey = encrypt('test-groq-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('groq', 'test', groqKey.encrypted, groqKey.iv, groqKey.authTag, 'healthy', 1);

    const result = routeRequest();
    expect(result.platform).toBe('groq');
  });

  it('skips a model whose context window cannot hold the request (#167)', () => {
    const db = getDb();
    const groqKey = encrypt('test-groq-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('groq', 'test', groqKey.encrypted, groqKey.iv, groqKey.authTag, 'healthy', 1);

    // Remove token rate-limit interference so we isolate the context-window
    // behavior (canUseTokens would otherwise also skip on a large estimate).
    db.prepare("UPDATE models SET tpm_limit = NULL, tpd_limit = NULL WHERE platform = 'groq'").run();

    // Whatever model a small request lands on, give it a tiny context window.
    const baseline = routeRequest(5);
    db.prepare('UPDATE models SET context_window = 10 WHERE id = ?').run(baseline.modelDbId);

    // A small request still lands on it (5 < 10) ...
    expect(routeRequest(5).modelDbId).toBe(baseline.modelDbId);

    // ... but a request larger than its window is routed elsewhere (2000 > 10).
    const large = routeRequest(2000);
    expect(large.modelDbId).not.toBe(baseline.modelDbId);
  });

  it('still routes a model with an unknown (null) context window (#167)', () => {
    const db = getDb();
    const groqKey = encrypt('test-groq-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('groq', 'test', groqKey.encrypted, groqKey.iv, groqKey.authTag, 'healthy', 1);
    db.prepare("UPDATE models SET tpm_limit = NULL, tpd_limit = NULL WHERE platform = 'groq'").run();
    // A null context_window means "unknown" — never filtered out, even for a huge request.
    db.prepare("UPDATE models SET context_window = NULL WHERE platform = 'groq'").run();
    expect(() => routeRequest(500000)).not.toThrow();
  });

  it('should skip keys that cannot be decrypted and use a valid fallback key', () => {
    const db = getDb();

    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('google', 'corrupt', 'not-hex', 'not-hex', 'not-hex', 'healthy', 1);

    const groqKey = encrypt('test-groq-key');
    db.prepare(`
      INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('groq', 'test', groqKey.encrypted, groqKey.iv, groqKey.authTag, 'healthy', 1);

    const result = routeRequest();
    const corruptKey = db.prepare("SELECT status FROM api_keys WHERE label = 'corrupt'").get() as { status: string };

    expect(result.platform).toBe('groq');
    expect(result.apiKey).toBe('test-groq-key');
    expect(corruptKey.status).toBe('error');
  });

  it('applies elapsed decay before adding a new 429 penalty', () => {
    vi.useFakeTimers();
    const modelDbId = 987654321;

    recordRateLimitHit(modelDbId);
    vi.advanceTimersByTime(10 * 60 * 1000);
    recordRateLimitHit(modelDbId);

    expect(getAllPenalties()).toContainEqual({
      modelDbId,
      count: 2,
      penalty: 3,
    });
  });
});

describe('Router - Multi-key round-robin', () => {
  beforeEach(() => {
    const db = getDb();
    setRoutingStrategy('priority');
    db.prepare('DELETE FROM api_keys').run();
    db.prepare("DELETE FROM settings WHERE key = 'active_profile_id'").run();
    // Ensure we have a groq model with known id
    const models = db.prepare("SELECT id, model_id FROM models WHERE platform = 'groq' ORDER BY intelligence_rank ASC LIMIT 1").get() as any;
    if (!models) return;
    // Set ALL models to same priority (1) to make routing deterministic by key_id
    const update = db.prepare('UPDATE fallback_config SET priority = 1 WHERE model_db_id = ?');
    for (const m of db.prepare('SELECT id FROM models').all() as any[]) {
      update.run(m.id);
    }
  });

  it('should round-robin between multiple keys for the same platform', () => {
    const db = getDb();
    const groqModel = db.prepare("SELECT id FROM models WHERE platform = 'groq' ORDER BY intelligence_rank ASC LIMIT 1").get() as any;
    if (!groqModel) return; // skip if no groq model

    // Add 3 keys for the same platform
    const key1 = encrypt('groq-key-1');
    db.prepare(`INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run('groq', 'key1', key1.encrypted, key1.iv, key1.authTag, 'healthy', 1);

    const key2 = encrypt('groq-key-2');
    db.prepare(`INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run('groq', 'key2', key2.encrypted, key2.iv, key2.authTag, 'healthy', 1);

    const key3 = encrypt('groq-key-3');
    db.prepare(`INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run('groq', 'key3', key3.encrypted, key3.iv, key3.authTag, 'healthy', 1);

    // Three consecutive calls should rotate through all 3 keys
    const r1 = routeRequest();
    expect(r1.platform).toBe('groq');
    expect(r1.apiKey).toBe('groq-key-1');

    const r2 = routeRequest();
    expect(r2.apiKey).toBe('groq-key-2');

    const r3 = routeRequest();
    expect(r3.apiKey).toBe('groq-key-3');

    // Fourth call wraps back to key 1
    const r4 = routeRequest();
    expect(r4.apiKey).toBe('groq-key-1');
  });

  it('should skip failed keys and use the next available one for same platform', () => {
    const db = getDb();
    const groqModel = db.prepare("SELECT id FROM models WHERE platform = 'groq' ORDER BY intelligence_rank ASC LIMIT 1").get() as any;
    if (!groqModel) return;

    // Add 2 keys — one will be failed/cooldowned
    const key1 = encrypt('groq-key-1');
    db.prepare(`INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run('groq', 'key1', key1.encrypted, key1.iv, key1.authTag, 'healthy', 1);

    const key2 = encrypt('groq-key-2');
    db.prepare(`INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run('groq', 'key2', key2.encrypted, key2.iv, key2.authTag, 'healthy', 1);

    // First call gets key 1
    const r1 = routeRequest();
    expect(r1.apiKey).toBe('groq-key-1');

    // Second call with key 1 skipped — should get key 2
    const skipKeys = new Set<string>();
    skipKeys.add(`groq:${r1.modelId}:${r1.keyId}`);
    const r2 = routeRequest(1000, skipKeys);
    expect(r2.apiKey).toBe('groq-key-2');
  });

  it('should distribute keys across the chain when multiple platforms have keys', () => {
    const db = getDb();

    // Add keys for both platforms
    const googleKey = encrypt('google-key');
    db.prepare(`INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run('google', 'gk', googleKey.encrypted, googleKey.iv, googleKey.authTag, 'healthy', 1);

    const groqKey1 = encrypt('groq-key-a');
    db.prepare(`INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run('groq', 'gk1', groqKey1.encrypted, groqKey1.iv, groqKey1.authTag, 'healthy', 1);

    const groqKey2 = encrypt('groq-key-b');
    db.prepare(`INSERT INTO api_keys (platform, label, encrypted_key, iv, auth_tag, status, enabled) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run('groq', 'gk2', groqKey2.encrypted, groqKey2.iv, groqKey2.authTag, 'healthy', 1);

    // Google is higher priority, so first call gets google
    // (only has 1 key, so it gets that one)
    const r1 = routeRequest();
    expect(r1.platform).toBe('google');
    expect(r1.apiKey).toBe('google-key');
  });
});
