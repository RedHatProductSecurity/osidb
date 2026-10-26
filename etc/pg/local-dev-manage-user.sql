CREATE ROLE osidb_manage_user WITH
	SUPERUSER
	CREATEDB
	NOCREATEROLE
	NOINHERIT
	NOREPLICATION
	BYPASSRLS
	LOGIN ENCRYPTED PASSWORD 'passw0rd';
-- Grant app_user access to all current and future tables/sequences created by manage_user
GRANT ALL ON ALL TABLES IN SCHEMA public TO osidb_app_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO osidb_app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE osidb_manage_user IN SCHEMA public GRANT ALL ON TABLES TO osidb_app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE osidb_manage_user IN SCHEMA public GRANT ALL ON SEQUENCES TO osidb_app_user;
