-- SQL query to create and/or upgrade the database and tables for ConfigMgr Client Health

-- IF CREATING DATABASE FOR FIRST TIME:
-- Remember to grant 'domain\domain computers' DATAREADER and DATAWRITER rights on the ClientHealth database
-- after you execute this query and database is created.


-- START QUERY
-- Create database if not exist:
GO
IF NOT EXISTS (SELECT [name] FROM sys.databases WHERE [name] = 'ClientHealth')
CREATE DATABASE ClientHealth

GO
USE ClientHealth

-- Create Configuration table if not exist:
GO
IF NOT EXISTS (SELECT [name] FROM sys.tables WHERE [name] = 'Configuration')
CREATE TABLE dbo.Configuration
(
    Name varchar(50) NOT NULL UNIQUE,
    Version varchar (10) NOT NULL
)

-- Create ClientConfiguration table if not exist:
GO
IF NOT EXISTS (SELECT [name] FROM sys.tables WHERE [name] = 'ClientConfiguration')
CREATE TABLE dbo.ClientConfiguration
(
    Id varchar(100) NOT NULL PRIMARY KEY,
    Configuration varchar(max) NOT NULL
)

-- Create Clients table if not exist:
IF NOT EXISTS (SELECT [name] FROM sys.tables WHERE [name] = 'Clients')
CREATE TABLE dbo.Clients
(
    ClientHealthId varchar(36) NOT NULL PRIMARY KEY,
    Hostname varchar(100) NOT NULL,
    OperatingSystem varchar (100) NOT NULL,
    Architecture varchar(10) NOT NULL,
    Build varchar(50) NOT NULL,
    Manufacturer varchar(50),
    Model varchar(50),
    InstallDate smalldatetime,
    OSUpdates smalldatetime,
    LastLoggedOnUser varchar(50),
    ClientVersion varchar(20),
    PSVersion float,
    PSBuild int,
    Sitecode varchar(3),
    Domain varchar(50),
    MaxLogSize int,
    MaxLogHistory int,
    CacheSize int,
    ClientCertificate varchar(50),
    ProvisioningMode varchar(50),
    DNS varchar(100),
    Drivers varchar(100),
    Updates varchar(100),
    PendingReboot varchar(50),
    LastBootTime smalldatetime,
    OSDiskFreeSpace float,
    Services varchar(50),
    AdminShare varchar(50),
    StateMessages varchar(50),
    WUAHandler varchar(50),
    WMI varchar(50),
    RefreshComplianceState smalldatetime,
    ClientInstalled smalldatetime,
    Version varchar(10),
    Timestamp datetime,
    HWInventory smalldatetime,
    SWMetering varchar(50),
    BITS varchar(50),
    PatchLevel int,
    ClientInstalledReason varchar(200),
    Extension_000 varchar(max),
    Extension_001 varchar(max),
    Extension_002 varchar(max),
    Extension_003 varchar(max),
    Extension_004 varchar(max),
    Extension_005 varchar(max),
    Extension_006 varchar(max),
    Extension_007 varchar(max),
    Extension_008 varchar(max),
    Extension_009 varchar(max),
    Extension_010 varchar(max),
    Extension_011 varchar(max),
    Extension_012 varchar(max),
    Extension_013 varchar(max),
    Extension_014 varchar(max),
    Extension_015 varchar(max),
    Extension_016 varchar(max),
    Extension_017 varchar(max),
    Extension_018 varchar(max),
    Extension_019 varchar(max)
)
--else

-- START Changes to database --
-- Add columns if needed
--IF NOT EXISTS (SELECT * FROM sys.columns WHERE  object_id = OBJECT_ID(N'[dbo].[Clients]') AND name = 'HWInventory') ALTER TABLE dbo.Clients ADD HWInventory smalldatetime


-- Modify columns if needed
--IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = 'Clients' AND COLUMN_NAME = 'Hostname' AND DATA_TYPE = 'varchar' AND CHARACTER_MAXIMUM_LENGTH = 100) ALTER TABLE dbo.Clients ALTER COLUMN Hostname VARCHAR(100) NOT NULL

-- Set latest ConfigMgr Client Health database version:
GO
begin tran
if exists (SELECT * FROM dbo.Configuration WITH (updlock,serializable) WHERE Name='ClientHealth')
begin
    IF EXISTS (SELECT * FROM dbo.Configuration WITH (updlock,serializable) WHERE Name='ClientHealth' AND Version < '2.0.0')
    UPDATE dbo.Configuration SET Version='2.0.0' WHERE Name = 'ClientHealth'
end
else
begin
    INSERT INTO dbo.Configuration (Name, Version)
    VALUES ('ClientHealth', '2.0.0')
end
commit tran

-- End of query
