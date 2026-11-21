-- Encryption helpers; used by the integration test and as an example for _enc columns.

-- name: Encrypt :one
SELECT asi_enc(@plaintext::text)::bytea AS ciphertext;

-- name: Decrypt :one
SELECT asi_dec(@ciphertext::bytea)::text AS plaintext;
