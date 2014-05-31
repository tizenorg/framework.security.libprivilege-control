.load librules-db-sql-udf.so
.separator " "

PRAGMA journal_mode = DELETE;


BEGIN TRANSACTION;

-- Delete volatile rules
DELETE FROM app_permission WHERE is_volatile = 1;


.output "/opt/etc/smack/boot-rules.smack"
SELECT subject, object, access_to_str(access), "-"
FROM   all_smack_binary_rules
WHERE  all_smack_binary_rules.is_volatile = 0;
COMMIT TRANSACTION;