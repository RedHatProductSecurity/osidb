CREATE ROLE osidb_app_user WITH
	CREATEDB
	NOCREATEROLE
	NOINHERIT
	NOREPLICATION
	NOBYPASSRLS
	LOGIN ENCRYPTED PASSWORD 'passw0rd';
GRANT CREATE ON DATABASE osidb TO osidb_app_user;
