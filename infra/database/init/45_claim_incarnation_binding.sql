-- Bind every managed worker claim to the exact deployment incarnation that
-- authenticated it.  A deployment replacement must never cause an old claim
-- to inherit the replacement's authority through a join on deployment_id.

ALTER TABLE managed_execution_claims
  ADD COLUMN IF NOT EXISTS deployment_incarnation uuid;

-- Existing claims predate this binding and cannot be proven to belong to the
-- current incarnation.  They must reclaim through a signed envelope.
UPDATE managed_execution_claims
SET status = 'fenced'
WHERE status = 'active' AND deployment_incarnation IS NULL;

CREATE INDEX IF NOT EXISTS idx_managed_claim_incarnation
  ON managed_execution_claims (execution_id, deployment_incarnation, status);

COMMENT ON COLUMN managed_execution_claims.deployment_incarnation IS
  'Exact deployment incarnation authenticated when this claim was issued; authorization requires it to remain current.';
