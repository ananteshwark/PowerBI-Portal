-- =============================================================================
-- Distinguish "revoked because it was rotated" from "revoked because the family
-- was compromised".
--
-- Rotation revokes tokens constantly and harmlessly. Compromise revokes them as
-- a security response. Before this column both looked identical (revoked_at set),
-- which made the reuse-leeway check unsafe: immediately after a family
-- revocation every token is *freshly* revoked, so a leeway keyed on "how long
-- ago was this revoked" would hand an attacker a brand-new live token inside a
-- family we had just killed.
-- =============================================================================

ALTER TABLE refresh_tokens
    ADD COLUMN compromised_at TIMESTAMPTZ;

COMMENT ON COLUMN refresh_tokens.compromised_at IS
    'Set on every row in a family when token reuse is detected. A token whose '
    'family carries this is never renewable, regardless of the reuse leeway.';

-- Partial index: the rotate path checks this on every refresh, and the column
-- is NULL for virtually every row.
CREATE INDEX refresh_tokens_compromised_idx
    ON refresh_tokens (family_id)
    WHERE compromised_at IS NOT NULL;
