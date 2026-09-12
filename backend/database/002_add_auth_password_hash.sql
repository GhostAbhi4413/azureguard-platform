/* Required once for JWT signup/login. Safe to run repeatedly. */
IF COL_LENGTH('dbo.AppUsers', 'PasswordHash') IS NULL
BEGIN
    ALTER TABLE dbo.AppUsers ADD PasswordHash NVARCHAR(500) NULL;
END;
GO
