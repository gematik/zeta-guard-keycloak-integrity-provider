SELECT pg_cancel_backend(pid)
FROM pg_locks l
         JOIN pg_class t on l.relation = t.oid
WHERE t.relkind = 'r'
  AND t.relname IN ('spree_row_checksum', 'spree_table_checksum');
