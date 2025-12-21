-- Connect to template1 to ensure all FUTURE databases (like Django test DBs) 
-- inherit this permission.
\c template1

-- Grant the permission to the 'public' role (everyone) 
GRANT ALL ON SCHEMA public TO PUBLIC;
