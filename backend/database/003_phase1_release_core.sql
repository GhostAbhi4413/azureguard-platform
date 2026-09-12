/* AzureGuard Phase 1 upgrade. Safe to run repeatedly on an existing database. */
IF OBJECT_ID('dbo.ScanFindings') IS NULL
BEGIN
  CREATE TABLE dbo.ScanFindings (Id BIGINT IDENTITY PRIMARY KEY, ReleaseId BIGINT NOT NULL, ScanResultId BIGINT NULL, ScanType NVARCHAR(40) NOT NULL, Severity NVARCHAR(20) NOT NULL, RuleId NVARCHAR(120) NULL, Title NVARCHAR(500) NULL, Description NVARCHAR(MAX) NULL, FilePath NVARCHAR(1000) NULL, LineNumber INT NULL, Fingerprint NVARCHAR(200) NULL, CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME());
  CREATE INDEX IX_ScanFindings_ReleaseId ON dbo.ScanFindings(ReleaseId);
END;
IF OBJECT_ID('dbo.Policies') IS NULL
BEGIN
  CREATE TABLE dbo.Policies (Id BIGINT IDENTITY PRIMARY KEY, ProjectId BIGINT NOT NULL, Name NVARCHAR(200) NOT NULL, IsActive BIT NOT NULL DEFAULT 1, CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME());
END;
IF OBJECT_ID('dbo.PolicyRules') IS NULL
BEGIN
  CREATE TABLE dbo.PolicyRules (Id BIGINT IDENTITY PRIMARY KEY, PolicyId BIGINT NOT NULL, RuleCode NVARCHAR(80) NOT NULL, Description NVARCHAR(500) NOT NULL, IsActive BIT NOT NULL DEFAULT 1, Threshold DECIMAL(10,2) NOT NULL DEFAULT 0, Action NVARCHAR(30) NOT NULL);
END;
IF OBJECT_ID('dbo.AuditLogs') IS NULL
BEGIN
  CREATE TABLE dbo.AuditLogs (Id BIGINT IDENTITY PRIMARY KEY, UserId BIGINT NULL, ProjectId BIGINT NULL, ReleaseId BIGINT NULL, Action NVARCHAR(100) NOT NULL, DetailsJson NVARCHAR(MAX) NULL, CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME());
  CREATE INDEX IX_AuditLogs_CreatedAt ON dbo.AuditLogs(CreatedAt);
END;
IF OBJECT_ID('dbo.AuditLogs') IS NOT NULL AND COL_LENGTH('dbo.AuditLogs', 'Action') IS NULL
  ALTER TABLE dbo.AuditLogs ADD Action NVARCHAR(100) NULL;
IF OBJECT_ID('dbo.AuditLogs') IS NOT NULL AND COL_LENGTH('dbo.AuditLogs', 'DetailsJson') IS NULL
  ALTER TABLE dbo.AuditLogs ADD DetailsJson NVARCHAR(MAX) NULL;
IF OBJECT_ID('dbo.PolicyRules') IS NOT NULL AND COL_LENGTH('dbo.PolicyRules', 'Description') IS NULL
  ALTER TABLE dbo.PolicyRules ADD Description NVARCHAR(500) NULL;
IF OBJECT_ID('dbo.PolicyRules') IS NOT NULL AND COL_LENGTH('dbo.PolicyRules', 'Threshold') IS NULL
  ALTER TABLE dbo.PolicyRules ADD Threshold DECIMAL(10,2) NULL;
IF OBJECT_ID('dbo.PolicyRules') IS NOT NULL AND COL_LENGTH('dbo.PolicyRules', 'Action') IS NULL
  ALTER TABLE dbo.PolicyRules ADD Action NVARCHAR(30) NULL;
IF OBJECT_ID('dbo.PolicyDecisions') IS NOT NULL AND COL_LENGTH('dbo.PolicyDecisions', 'RiskScore') IS NULL
  ALTER TABLE dbo.PolicyDecisions ADD RiskScore DECIMAL(10,2) NULL;
IF OBJECT_ID('dbo.AuditLogs') IS NOT NULL AND COL_LENGTH('dbo.AuditLogs', 'ActionName') IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sys.default_constraints WHERE parent_object_id = OBJECT_ID('dbo.AuditLogs') AND parent_column_id = COLUMNPROPERTY(OBJECT_ID('dbo.AuditLogs'), 'ActionName', 'ColumnId'))
  ALTER TABLE dbo.AuditLogs ADD CONSTRAINT DF_AuditLogs_ActionName DEFAULT ('SYSTEM') FOR ActionName;
/* Seed a default policy for every existing project without changing user policy data. */
INSERT dbo.Policies(ProjectId, Name) SELECT p.Id, 'Default' FROM dbo.Projects p WHERE NOT EXISTS (SELECT 1 FROM dbo.Policies x WHERE x.ProjectId = p.Id AND x.IsActive = 1);
INSERT dbo.PolicyRules(PolicyId, RuleCode, Description, Threshold, Action)
SELECT p.Id, v.RuleCode, v.Description, v.Threshold, v.Action FROM dbo.Policies p CROSS APPLY (VALUES
 ('SECRET','Block leaked secrets',1,'BLOCKED'),('CRITICAL','Block critical findings',1,'BLOCKED'),('HIGH_REVIEW','Review elevated high findings',5,'MANUAL_REVIEW')) v(RuleCode,Description,Threshold,Action)
WHERE p.Name = 'Default' AND p.IsActive = 1 AND NOT EXISTS (SELECT 1 FROM dbo.PolicyRules r WHERE r.PolicyId = p.Id);
GO
