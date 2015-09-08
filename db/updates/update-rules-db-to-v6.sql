--PRAGMA journal_mode = PERSIST;

BEGIN EXCLUSIVE TRANSACTION;

CREATE TABLE IF NOT EXISTS friends (
	label_id1 INTEGER NOT NULL,
	label_id2 INTEGER NOT NULL,

	UNIQUE (label_id1, label_id2),

	FOREIGN KEY(label_id1) REFERENCES label(label_id),
	FOREIGN KEY(label_id2) REFERENCES label(label_id)
);

--assume, that database is in version V5
PRAGMA user_version = 6;

COMMIT TRANSACTION;
