$SLConfigs= '\\vaslnas\Deploys\SLConfigs'

$instance = "MSSQLSERVER"

# ----- add to the PSModule Path so we can load the SQLServer Module
$env:PSModulePath += ";$SLConfigs\Powershell\Modules"

Import-Module SQLServer


# ----- different servers have different  file locations ( yeah, I know ).  Restoring to the default location of the specific server
$DefaultLocation = Invoke-Sqlcmd -Query "select SERVERPROPERTY('instancedefaultdatapath') AS [DefaultFile], SERVERPROPERTY('instancedefaultlogpath') AS [DefaultLog]"

# ----- This query will create the WGP_importProcessor DB. 
$Query = @"
USE [master]
GO
CREATE DATABASE [WGP_importProcessor]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'WPG_importProcessor', FILENAME = N'$($DefaultLocation.DefaultFile)WPG_importProcessor.mdf' , SIZE = 61504KB , MAXSIZE = UNLIMITED, FILEGROWTH = 1024KB ), 
 FILEGROUP [WPG_importProcessor_fs] CONTAINS FILESTREAM  DEFAULT
( NAME = N'WPG_importProcessor_fs', FILENAME = N'$($DefaultLocation.DefaultFile)WPG_importProcessor_fs' , MAXSIZE = UNLIMITED)
 LOG ON 
( NAME = N'WPG_importProcessor_log', FILENAME = N'$($DefaultLocation.DefaultLog)WPG_importProcessor_log.ldf' , SIZE = 478464KB , MAXSIZE = 2048GB , FILEGROWTH = 10%)
GO
ALTER DATABASE [WGP_importProcessor] SET COMPATIBILITY_LEVEL = 110
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [WGP_importProcessor].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [WGP_importProcessor] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET ARITHABORT OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [WGP_importProcessor] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [WGP_importProcessor] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET  ENABLE_BROKER 
GO
ALTER DATABASE [WGP_importProcessor] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [WGP_importProcessor] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET RECOVERY FULL 
GO
ALTER DATABASE [WGP_importProcessor] SET  MULTI_USER 
GO
ALTER DATABASE [WGP_importProcessor] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [WGP_importProcessor] SET DB_CHAINING OFF 
GO
ALTER DATABASE [WGP_importProcessor] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [WGP_importProcessor] SET TARGET_RECOVERY_TIME = 0 SECONDS 
GO
ALTER DATABASE [WGP_importProcessor] SET DELAYED_DURABILITY = DISABLED 
GO
EXEC sys.sp_db_vardecimal_storage_format N'WGP_importProcessor', N'ON'
GO
USE [WGP_importProcessor]
GO
/****** Object:  Table [dbo].[Files]    Script Date: 3/22/2017 11:56:27 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[Files](
	[Id] [uniqueidentifier] ROWGUIDCOL  NOT NULL,
	[Data] [varbinary](max) FILESTREAM  NOT NULL,
 CONSTRAINT [PK_Data] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY] FILESTREAM_ON [WPG_importProcessor_fs],
UNIQUE NONCLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] FILESTREAM_ON [WPG_importProcessor_fs]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[Jobs]    Script Date: 3/22/2017 11:56:27 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[Jobs](
	[Id] [uniqueidentifier] NOT NULL,
	[TenantId] [uniqueidentifier] NOT NULL,
	[Status] [int] NOT NULL,
	[Begin] [datetime] NULL,
	[Finished] [datetime] NULL,
	[CreatedOn] [datetime] NOT NULL,
	[ExecuteAt] [datetime] NULL,
	[Result] [varchar](max) NULL,
	[Instructions] [nvarchar](max) NULL,
	[Source_Id] [uniqueidentifier] NOT NULL,
 CONSTRAINT [PK_dbo.Jobs] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
/****** Object:  Table [dbo].[Steps]    Script Date: 3/22/2017 11:56:27 AM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
SET ANSI_PADDING ON
GO
CREATE TABLE [dbo].[Steps](
	[Id] [uniqueidentifier] NOT NULL,
	[StepNumber] [nvarchar](max) NULL,
	[Status] [int] NOT NULL,
	[CreatedOn] [datetime] NOT NULL,
	[Begin] [datetime] NULL,
	[Finished] [datetime] NULL,
	[Properties] [varchar](max) NULL,
	[Service] [int] NOT NULL,
	[Job_Id] [uniqueidentifier] NULL,
	[Source_Id] [uniqueidentifier] NOT NULL,
	[Result_Id] [uniqueidentifier] NULL,
 CONSTRAINT [PK_dbo.Steps] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]

GO
SET ANSI_PADDING OFF
GO
ALTER TABLE [dbo].[Jobs]  WITH CHECK ADD  CONSTRAINT [FK_Jobs_Data] FOREIGN KEY([Source_Id])
REFERENCES [dbo].[Files] ([Id])
GO
ALTER TABLE [dbo].[Jobs] CHECK CONSTRAINT [FK_Jobs_Data]
GO
ALTER TABLE [dbo].[Steps]  WITH CHECK ADD  CONSTRAINT [FK_dbo.Steps_dbo.Jobs_Job_Id] FOREIGN KEY([Job_Id])
REFERENCES [dbo].[Jobs] ([Id])
GO
ALTER TABLE [dbo].[Steps] CHECK CONSTRAINT [FK_dbo.Steps_dbo.Jobs_Job_Id]
GO
ALTER TABLE [dbo].[Steps]  WITH CHECK ADD  CONSTRAINT [FK_Steps_Data] FOREIGN KEY([Source_Id])
REFERENCES [dbo].[Files] ([Id])
GO
ALTER TABLE [dbo].[Steps] CHECK CONSTRAINT [FK_Steps_Data]
GO
ALTER TABLE [dbo].[Steps]  WITH CHECK ADD  CONSTRAINT [FK_Steps_Data1] FOREIGN KEY([Result_Id])
REFERENCES [dbo].[Files] ([Id])
GO
ALTER TABLE [dbo].[Steps] CHECK CONSTRAINT [FK_Steps_Data1]
GO
USE [master]
GO
ALTER DATABASE [WGP_importProcessor] SET  READ_WRITE 
GO
"@



# ----- Determine the path version number.  Assuming we will be working with the highest version installed.
$SQLVersionNum = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where Displayname -like "SQL*Database Engine*" | Sort-Object VersionMajor | Select-object -ExpandProperty VersionMajor -First 1


# ----- https://haydenhancock.wordpress.com/2013/03/12/enable-filestream-via-powershell/
# ----- Check if FileStream is enabled
$FileStream = Get-WmiObject -Namespace "ROOT\Microsoft\SqlServer\ComputerManagement$SQLVersionNum" -Class FilestreamSettings | where {$_.InstanceName -eq $instance}

<# 
    AccessLevel
            0 = Disabled
            1 = Enabled for TSQL access only
            2 = Level 1 and I/O streaming access
            3 = Level 2 and Allow Remote Clients
#>

if ( $FileStream.AccessLevel -ne 3 ) {

    Write-output "Enabling FileStream on SQL"
    $FileStream.EnableFileStream(3,'WGP_FileStream' )

    Invoke-Sqlcmd "EXEC sp_configure filestream_access_level, 2"
    Invoke-Sqlcmd "RECONFIGURE"

    Write-output "Restarting the SQL Service"
    Get-Service -Name $Instance | Restart-Service -Force
}

if ( -Not (Get-SQLDatabase -Name WGP_importProcessor -path "SQLSERVER:\SQL\$($env:ComputerName)\default" -ErrorAction SilentlyContinue) ) {
    Write-Output "WGP_importProcessor doesn't exist.  Create it"
    Invoke-Sqlcmd -Query $Query
}




