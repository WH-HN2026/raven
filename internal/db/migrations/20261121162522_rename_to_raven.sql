-- N1: project renamed to RAVEN. Encryption helpers become raven_enc/raven_dec and read
-- the GUC raven.enc_key, set per connection by the pgx pool (architecture §5, D8).

-- +goose Up
DROP FUNCTION asi_dec(bytea);
DROP FUNCTION asi_enc(text);

-- +goose StatementBegin
CREATE FUNCTION raven_enc(t text) RETURNS bytea
LANGUAGE sql VOLATILE AS $$
    SELECT CASE WHEN t IS NULL THEN NULL
                ELSE pgp_sym_encrypt(t, current_setting('raven.enc_key')) END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION raven_dec(b bytea) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN b IS NULL THEN NULL
                ELSE pgp_sym_decrypt(b, current_setting('raven.enc_key')) END
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION raven_dec(bytea);
DROP FUNCTION raven_enc(text);

-- +goose StatementBegin
CREATE FUNCTION asi_enc(t text) RETURNS bytea
LANGUAGE sql VOLATILE AS $$
    SELECT CASE WHEN t IS NULL THEN NULL
                ELSE pgp_sym_encrypt(t, current_setting('asi.enc_key')) END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION asi_dec(b bytea) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN b IS NULL THEN NULL
                ELSE pgp_sym_decrypt(b, current_setting('asi.enc_key')) END
$$;
-- +goose StatementEnd
