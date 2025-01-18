CREATE TABLE [dbo].[Users] (
    [Id] UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWID(),
    [FirstName] NVARCHAR(50) NOT NULL,
    [LastName] NVARCHAR(50) NOT NULL,
    [Email] NVARCHAR(256) NOT NULL UNIQUE,
    [PhoneNumber] NVARCHAR(20) NULL,
    [IsAdmin] BIT NOT NULL DEFAULT 0,
    [IssueCertificate] BIT NOT NULL DEFAULT 1,
    [PasswordHash] NVARCHAR(MAX) NULL,
    [CertificateSerialNumber] NVARCHAR(100) NULL,
    [CertificateDownloaded] BIT NOT NULL DEFAULT 0,
    [CertificateIssuedAt] DATETIME2 NULL,
    [CertificateExpiresAt] DATETIME2 NULL,
    [EmployeeId] NVARCHAR(100) NOT NULL UNIQUE,
    [IsActive] BIT NOT NULL DEFAULT 0,
    [CreatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE(),
    [UpdatedAt] DATETIME2 NOT NULL DEFAULT GETUTCDATE()
);

-- Create index on Email
CREATE UNIQUE NONCLUSTERED INDEX [IX_Users_Email] ON [dbo].[Users] ([Email]);

-- Create index on EmployeeId
CREATE UNIQUE NONCLUSTERED INDEX [IX_Users_EmployeeId] ON [dbo].[Users] ([EmployeeId]); 