-- Removes the data created by seed.sql (run as the database superuser).
\set ON_ERROR_STOP on
BEGIN;
DELETE FROM repositories WHERE scm_connection_id = '0000000a-0000-7000-8000-0000000000c1';
DELETE FROM scm_connections WHERE id = '0000000a-0000-7000-8000-0000000000c1';
DELETE FROM secrets WHERE id IN ('0000000a-0000-7000-8000-000000000001', '0000000a-0000-7000-8000-000000000002');
COMMIT;
