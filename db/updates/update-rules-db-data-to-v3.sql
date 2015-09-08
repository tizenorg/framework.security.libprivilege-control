.load librules-db-sql-udf.so
--PRAGMA journal_mode = PERSIST;
PRAGMA foreign_keys = ON;

BEGIN EXCLUSIVE TRANSACTION;

--assume, that database is in version V2

-- From now on all_smack_binary_rules keeps SMACK rules, that are neither grouped nor ordered.
DROP VIEW IF EXISTS all_smack_binary_rules_view;
CREATE VIEW all_smack_binary_rules_view AS
SELECT  subject,
        object,
        access,
        is_volatile
FROM   (SELECT subject, object, access, is_volatile
        FROM   ltl_permission_permission_rule_view
        UNION ALL
        SELECT subject, object, access, is_volatile
        FROM   ltl_permission_label_rule_view
        UNION ALL
        SELECT subject, object, access, is_volatile
        FROM   ltl_permission_app_path_type_rule_view
        UNION ALL
        SELECT subject, object, access, is_volatile
        FROM   ltl_label_app_path_type_rule_view
        UNION ALL
        SELECT subject, object, access, 0
        FROM   ltl_app_path_view
        UNION ALL
        SELECT subject, object, access, 0
        FROM   ltl_app_path_reverse_view
       );

DELETE FROM all_smack_binary_rules;

INSERT INTO all_smack_binary_rules
SELECT subject, object, access, is_volatile
FROM   all_smack_binary_rules_view;


COMMIT TRANSACTION;
