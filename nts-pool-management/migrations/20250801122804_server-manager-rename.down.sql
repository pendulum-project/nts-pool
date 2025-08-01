-- Add down migration script here
ALTER TYPE user_role RENAME VALUE 'manager' TO 'server-manager';
