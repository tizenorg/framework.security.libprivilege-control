--PRAGMA journal_mode = PERSIST;

BEGIN EXCLUSIVE TRANSACTION;

--assume, that database is in version V2
PRAGMA user_version = 3;

COMMIT TRANSACTION;
