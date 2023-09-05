PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "Mofs" (
	"ID"	INTEGER NOT NULL UNIQUE,
	-- SHA256 hash of MOF file
	"Hash"	TEXT NOT NULL UNIQUE,
	"Name"	TEXT NOT NULL,
	"PublishDate"	TEXT NOT NULL DEFAULT (datetime('now')),
	"Mode"	TEXT NOT NULL DEFAULT 'ApplyAndMonitor',
	"Active" NUMERIC DEFAULT '1',
	PRIMARY KEY("ID" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "Jobs" (
	"ID"	INTEGER NOT NULL UNIQUE,
	-- Comma separated list of MOFs
	"Mof"	INTEGER NOT NULL,
	"Mode"	TEXT,
	"StartDate"	TEXT NOT NULL DEFAULT (datetime('now')),
	"EndDate" TEXT,
	FOREIGN KEY("Mof") REFERENCES "Mofs"("ID"),
	PRIMARY KEY("ID" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "CimInstances" (
	"ID"	INTEGER NOT NULL UNIQUE,
	"ResourceId"	TEXT,
	-- SHA256 Hash of Mof file
	"Mof"	INTEGER NOT NULL,
	-- Instance Type - NTFSAccessEntry, RegisteryPolicyFile, etc
	"Type"	TEXT,
	-- DSC Module containing the type
	"ModuleName"	TEXT,
	-- The Module version specific in the MOF
	"ModuleVersion"	TEXT,
	-- Array of strings separated by comma
	"DependsOn"	TEXT,
	-- The CIMInstance serialized by PSSerializer to a depth of 100
	"RawInstance"	BLOB,
	FOREIGN KEY("Mof") REFERENCES "Mofs"("ID"),
	PRIMARY KEY("ID" AUTOINCREMENT)
);
CREATE TABLE IF NOT EXISTS "Results" (
	"ID"	INTEGER NOT NULL UNIQUE,
	"Job"	INTEGER NOT NULL,
	"CimInstance"	INTEGER,
	"InDesiredState"	NUMERIC,
	"Error"	TEXT,
	"RunType"	NUMERIC,
	FOREIGN KEY("CimInstance") REFERENCES "CimInstances"("ID"),
	FOREIGN KEY("Job") REFERENCES "Jobs"("ID"),
	PRIMARY KEY("ID" AUTOINCREMENT)
);
COMMIT;
