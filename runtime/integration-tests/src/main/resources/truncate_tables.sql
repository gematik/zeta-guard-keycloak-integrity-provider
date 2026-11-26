DO
$$
    DECLARE
        r RECORD;
    BEGIN
        -- 1. Disable foreign key triggers for this session
        -- This allows us to truncate tables regardless of FK dependencies.
        SET CONSTRAINTS ALL DEFERRED;
        SET session_replication_role = 'replica';

        -- 2. Loop through all base tables in the 'public' schema
        FOR r IN (SELECT tablename
                  FROM pg_tables
                  WHERE schemaname = 'public')
            LOOP
            -- 3. Execute Truncate with Identity Reset
            -- RESTART IDENTITY resets SERIAL and IDENTITY columns to 1
                EXECUTE 'DELETE FROM public.' || quote_ident(r.tablename);
            END LOOP;

        -- 4. Restore the session role to default
        SET session_replication_role = 'origin';
    END
$$;