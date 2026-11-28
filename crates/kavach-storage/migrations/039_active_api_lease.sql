-- Owner-controlled lease state for the approved active/passive API topology.
-- The runtime role may use the bounded functions below, but cannot inspect or
-- mutate the lease row directly.
CREATE TABLE active_api_leases (
    tenant_id TEXT PRIMARY KEY CHECK (tenant_id <> ''),
    holder_id TEXT NOT NULL CHECK (holder_id <> ''),
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    token_hash BYTEA NOT NULL CHECK (octet_length(token_hash) = 32),
    lease_expires_at TIMESTAMPTZ NOT NULL
);

DO $migration$
DECLARE
    schema_name TEXT := current_schema();
BEGIN
    EXECUTE format($function$
        CREATE FUNCTION %1$I.kavach_claim_active_lease(
            p_tenant_id TEXT, p_holder_id TEXT, p_token_hash BYTEA, p_ttl INTERVAL
        ) RETURNS TABLE(epoch BIGINT, lease_expires_at TIMESTAMPTZ)
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog
        AS $body$
        BEGIN
            IF p_tenant_id IS NULL OR p_tenant_id = '' OR p_holder_id IS NULL
                OR p_holder_id = '' OR p_token_hash IS NULL
                OR octet_length(p_token_hash) <> 32 OR p_ttl IS NULL
                OR p_ttl <= interval '0 seconds' THEN
                RAISE EXCEPTION 'invalid active lease claim' USING ERRCODE = '22023';
            END IF;
            RETURN QUERY
            INSERT INTO %1$I.active_api_leases AS lease
                (tenant_id, holder_id, epoch, token_hash, lease_expires_at)
            VALUES (p_tenant_id, p_holder_id, 1, p_token_hash,
                clock_timestamp() + p_ttl)
            ON CONFLICT (tenant_id) DO UPDATE SET
                holder_id = EXCLUDED.holder_id,
                epoch = lease.epoch + 1,
                token_hash = EXCLUDED.token_hash,
                lease_expires_at = clock_timestamp() + p_ttl
            WHERE lease.lease_expires_at <= clock_timestamp()
            RETURNING lease.epoch, lease.lease_expires_at;
        END
        $body$
    $function$, schema_name);

    EXECUTE format($function$
        CREATE FUNCTION %1$I.kavach_renew_active_lease(
            p_tenant_id TEXT, p_holder_id TEXT, p_epoch BIGINT,
            p_token_hash BYTEA, p_ttl INTERVAL
        ) RETURNS BOOLEAN
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog
        AS $body$
        DECLARE changed_rows BIGINT;
        BEGIN
            IF p_tenant_id IS NULL OR p_tenant_id = '' OR p_holder_id IS NULL
                OR p_holder_id = '' OR p_epoch IS NULL OR p_epoch <= 0
                OR p_token_hash IS NULL OR octet_length(p_token_hash) <> 32
                OR p_ttl IS NULL OR p_ttl <= interval '0 seconds' THEN
                RAISE EXCEPTION 'invalid active lease renewal' USING ERRCODE = '22023';
            END IF;
            UPDATE %1$I.active_api_leases AS lease
            SET lease_expires_at = clock_timestamp() + p_ttl
            WHERE lease.tenant_id = p_tenant_id
                AND lease.holder_id = p_holder_id
                AND lease.epoch = p_epoch
                AND lease.token_hash = p_token_hash
                AND lease.lease_expires_at > clock_timestamp();
            GET DIAGNOSTICS changed_rows = ROW_COUNT;
            RETURN changed_rows = 1;
        END
        $body$
    $function$, schema_name);

    EXECUTE format('REVOKE ALL ON active_api_leases FROM PUBLIC');
    EXECUTE format('REVOKE ALL ON FUNCTION %I.kavach_claim_active_lease(TEXT, TEXT, BYTEA, INTERVAL) FROM PUBLIC', schema_name);
    EXECUTE format('REVOKE ALL ON FUNCTION %I.kavach_renew_active_lease(TEXT, TEXT, BIGINT, BYTEA, INTERVAL) FROM PUBLIC', schema_name);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', schema_name);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %I.kavach_claim_active_lease(TEXT, TEXT, BYTEA, INTERVAL) TO kavach_runtime', schema_name);
        EXECUTE format('GRANT EXECUTE ON FUNCTION %I.kavach_renew_active_lease(TEXT, TEXT, BIGINT, BYTEA, INTERVAL) TO kavach_runtime', schema_name);
    END IF;
END
$migration$;
