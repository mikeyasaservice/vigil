BEGIN;

ALTER TABLE management_account_bindings
  ADD COLUMN IF NOT EXISTS execution_profile TEXT NOT NULL DEFAULT 'aws';

ALTER TABLE management_account_bindings
  DROP CONSTRAINT IF EXISTS management_account_bindings_role_arn_check;

ALTER TABLE management_account_bindings
  DROP CONSTRAINT IF EXISTS management_account_bindings_execution_profile_check;

ALTER TABLE management_account_bindings
  ADD CONSTRAINT management_account_bindings_execution_profile_check
  CHECK (
    (execution_profile = 'aws' AND account_id <> '000000000000'
     AND role_arn ~ '^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$')
    OR
    (execution_profile = 'localstack' AND account_id = '000000000000' AND role_arn = '')
    OR
    (execution_profile = 'byoc' AND account_id <> '000000000000' AND role_arn = '')
    OR
    (execution_profile = 'byoc-localstack' AND account_id ~ '^[0-9]{12}$' AND role_arn = '')
  );

COMMIT;
