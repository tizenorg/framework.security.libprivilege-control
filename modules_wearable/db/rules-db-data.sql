-- !!! CAUTION !!!
-- Beware of updating!
-- Remember that you might insert things to a filled database.

.load librules-db-sql-udf.so
PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

-- PERMISSION TYPES --------------------------------------------------------------------------------
INSERT OR IGNORE INTO permission_type(type_name) VALUES("ALL_APPS"); -- Automatically added to all apps.
INSERT OR IGNORE INTO permission_type(type_name) VALUES("WRT");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("OSP");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("EFL");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("WRT_partner");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("WRT_platform");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("OSP_partner");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("OSP_platform");

-- APP PATH TYPES ----------------------------------------------------------------------------------
INSERT OR IGNORE INTO app_path_type(name) VALUES("GROUP_PATH");
INSERT OR IGNORE INTO app_path_type(name) VALUES("PUBLIC_PATH");
INSERT OR IGNORE INTO app_path_type(name) VALUES("SETTINGS_PATH");
INSERT OR IGNORE INTO app_path_type(name) VALUES("NPRUNTIME_PATH");

INSERT OR IGNORE INTO permission_view(name, type_name) VALUES
		("ALL_APPS", 	"ALL_APPS"),
		("WRT", 	"WRT"),
		("WRT_partner", "WRT_partner"),
		("WRT_platform","WRT_platform"),
		("OSP", 	"OSP"),
		("OSP_partner", "OSP_partner"),
		("OSP_platform","OSP_platform"),
		("EFL", 	"EFL");

-- PUBLIC FOLDERS ----------------------------------------------------------------------------------
-- PUBLIC_PATH
INSERT OR IGNORE INTO permission_app_path_type_rule_view(permission_name,
						permission_type_name,
						app_path_type_name,
						access,
						is_reverse) VALUES
	("ALL_APPS", "ALL_APPS", "PUBLIC_PATH", "rx", 0);

COMMIT TRANSACTION;

VACUUM;
