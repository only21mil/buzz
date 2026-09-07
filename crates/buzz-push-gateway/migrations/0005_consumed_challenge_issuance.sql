-- Retain every issuance through its rolling quota window after single use.
-- Existing rows are unconsumed; keep their original issuance and expiry times.
ALTER TABLE push_gateway_challenges
    ADD COLUMN consumed BOOLEAN NOT NULL DEFAULT false;
