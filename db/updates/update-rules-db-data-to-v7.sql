-- PUBLIC FOLDERS ----------------------------------------------------------------------------------
-- PUBLIC_PATH
.load librules-db-sql-udf.so

UPDATE permission_app_path_type_rule SET access=str_to_access("rxl") WHERE permission_id IN (
    SELECT permission_id FROM permission_app_path_type_rule_view WHERE
        app_path_type_name="PUBLIC_PATH" AND
        permission_name="ALL_APPS" AND
        permission_type_name="ALL_APPS");

VACUUM;