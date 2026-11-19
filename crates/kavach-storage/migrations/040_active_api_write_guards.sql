-- Fence every runtime write against the Postgres-backed active API lease.
-- With no HA identity in the session, existing single-instance deployments
-- retain their current write behavior.
DO $migration$
DECLARE
    schema_name TEXT := current_schema();
    table_name TEXT;
    writable_tables TEXT[] := ARRAY[
        'admin_audit_log', 'decision_events', 'evaluate_incidents',
        'evidence_tombstones', 'agent_decisions', 'agent_outcomes',
        'evidence_checkpoints', 'mandate_revocations', 'agent_state_changes',
        'agent_outcome_resolutions', 'human_review_releases',
        'evidence_chain_meta', 'tenant_settings', 'batch_jobs', 'change_requests',
        'mandates', 'model_state', 'runtime_pointers', 'agent_evidence_chains',
        'contact_counters', 'agent_states', 'principals', 'role_bindings',
        'human_review_approvals', 'human_review_step_up_challenges',
        'human_review_snapshots', 'replay_guard', 'authority_updates',
        'consent_current', 'contact_preference_current', 'reference_destinations'
    ];
BEGIN
    EXECUTE format($function$
        CREATE FUNCTION %1$I.kavach_guard_active_write() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog
        AS $body$
        DECLARE
            fencing_enabled TEXT := current_setting('kavach.fencing_enabled', true);
            tenant_value TEXT;
            holder_value TEXT;
            epoch_text TEXT;
            epoch_value BIGINT;
            token_hash_value TEXT;
            lease_row RECORD;
        BEGIN
            -- An unset value means HA was not configured for this process.
            -- An explicit enabled value with missing identity fails closed.
            IF fencing_enabled IS NULL THEN
                IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
                RETURN NEW;
            END IF;
            IF fencing_enabled <> 'on' THEN
                RAISE EXCEPTION 'active API lease is not valid' USING ERRCODE = '55000';
            END IF;

            tenant_value := nullif(current_setting('kavach.tenant_id', true), '');
            holder_value := nullif(current_setting('kavach.holder_id', true), '');
            token_hash_value := current_setting('kavach.token_hash', true);
            IF tenant_value IS NULL OR holder_value IS NULL OR token_hash_value IS NULL
                OR token_hash_value !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'active API lease is not valid' USING ERRCODE = '55000';
            END IF;
            epoch_text := nullif(current_setting('kavach.lease_epoch', true), '');
            IF epoch_text IS NULL THEN
                RAISE EXCEPTION 'active API lease is not valid' USING ERRCODE = '55000';
            END IF;
            BEGIN
                epoch_value := epoch_text::BIGINT;
            EXCEPTION WHEN invalid_text_representation OR null_value_not_allowed THEN
                RAISE EXCEPTION 'active API lease is not valid' USING ERRCODE = '55000';
            END;
            IF epoch_value IS NULL OR epoch_value <= 0 THEN
                RAISE EXCEPTION 'active API lease is not valid' USING ERRCODE = '55000';
            END IF;

            SELECT lease.holder_id, lease.epoch, lease.token_hash, lease.lease_expires_at
            INTO lease_row
            FROM %1$I.active_api_leases AS lease
            WHERE lease.tenant_id = tenant_value
            FOR SHARE;
            IF NOT FOUND OR lease_row.holder_id <> holder_value
                OR lease_row.epoch <> epoch_value
                OR lease_row.token_hash <> decode(token_hash_value, 'hex')
                OR lease_row.lease_expires_at <= clock_timestamp() THEN
                RAISE EXCEPTION 'active API lease is not valid' USING ERRCODE = '55000';
            END IF;

            IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END
        $body$
    $function$, schema_name);

    FOREACH table_name IN ARRAY writable_tables LOOP
        EXECUTE format(
            'CREATE TRIGGER kavach_active_write_guard BEFORE INSERT OR UPDATE OR DELETE ON %I.%I FOR EACH ROW EXECUTE FUNCTION %I.kavach_guard_active_write()',
            schema_name, table_name, schema_name
        );
    END LOOP;

    EXECUTE format($function$
        CREATE FUNCTION %1$I.kavach_assert_active_write_guards() RETURNS VOID
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog
        AS $body$
        DECLARE
            schema_name TEXT := %1$L;
            missing_tables TEXT;
            guard_oid OID := '%1$I.kavach_guard_active_write()'::regprocedure;
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
                RETURN;
            END IF;
            SELECT string_agg(format('%%I', relation.relname), ', ' ORDER BY relation.relname)
            INTO missing_tables
            FROM pg_class AS relation
            JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
            WHERE namespace.nspname = schema_name
                AND relation.relkind IN ('r', 'p')
                AND (has_table_privilege('kavach_runtime', relation.oid, 'INSERT')
                    OR has_table_privilege('kavach_runtime', relation.oid, 'UPDATE')
                    OR has_table_privilege('kavach_runtime', relation.oid, 'DELETE'))
                AND NOT EXISTS (
                    SELECT 1 FROM pg_trigger AS trigger_row
                    WHERE trigger_row.tgrelid = relation.oid
                        AND NOT trigger_row.tgisinternal
                        AND trigger_row.tgfoid = guard_oid
                        AND (trigger_row.tgtype & 31) = 31
                );
            IF missing_tables IS NOT NULL THEN
                RAISE EXCEPTION 'runtime write tables lack active guards: %%', missing_tables;
            END IF;
        END
        $body$
    $function$, schema_name);

    EXECUTE format('REVOKE ALL ON FUNCTION %I.kavach_guard_active_write() FROM PUBLIC', schema_name);
    EXECUTE format('REVOKE ALL ON FUNCTION %I.kavach_assert_active_write_guards() FROM PUBLIC', schema_name);
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'kavach_runtime') THEN
        EXECUTE format('GRANT EXECUTE ON FUNCTION %I.kavach_guard_active_write() TO kavach_runtime', schema_name);
        EXECUTE format('GRANT USAGE ON SCHEMA %I TO kavach_runtime', schema_name);
    END IF;

    EXECUTE format('SELECT %I.kavach_assert_active_write_guards()', schema_name);
END
$migration$;
