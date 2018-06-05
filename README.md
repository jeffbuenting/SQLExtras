# SQLExtras

Powershell SQL Cmdlets and SQL Scripts wrapped in a SQLExtras module

## Branches

### Master

Version: 5.0.11

[![Build status](https://ci.appveyor.com/api/projects/status/3r3ejc8y9pvjh9f3?svg=true)](https://ci.appveyor.com/project/jeffbuenting/sqlextras)

This is the branch containing the latest version.

### Dev

Developement branch.  Periodically merged with Master.  The version will be updated when this happens.

## Installation

Download the SQLExtras.PSM1 and PSD1 files.  Copy them to your C:\Program Files\WindowsPowershell\Modules directory or a directory that is in the PSModulePath.  Then you can either explicitly import it or let powershells autoload take care if it if you use one of the cmdlets.

## Cmdlets

### SQL

- **Install-SQLServer** : Install SQL Server.  
- **Get-SQLDBLoginRoles** :  Name of the SQL server you want login information about.  
- **Set-SQLDBLoginRoles** :  Adds SQL login to the Database security Roles.  
- **Get-SQLDatabase** :  Gets Database information for DBs on a SQL Server.  
- **Remove-SQLDatabase** : Deletes a database.  
- **Refresh-SQLDatabase** :  Deletes and Restores a DB on a SQL Server.  
- **Get-SQLJob** :  Gets a list of jobs on a sql server.  
- **Set-SQLJob** :  Allows edit / changes to a SQL Job.  
- **New-SQLSchedule** :  Creates new SQL Job Schedule.  
- **Get-SQLSchedule** :  Returns a list of SQL Job Schedules.  
- **Get-SQLClientProtocol** :  lists SQL Protocol Client status.  
- **Get-SQLNetworkProtocol** : Lists SQL Server Protocol Status.
- **Set-SQLNetworkProtocol** :   Changes SQL Network Protocol Settings.  
- **Get-SQLDBMail** :  Retrieves the SQL DB Mail Settings.  
- **Get-SQLDBMailAccount** :  Retrieves a SQL DB Mail Account. 

### SSRS

- **Backup-SSRSReport**(#backup-ssrsreport) : Backs up / saves an SSRS Report file (RDL) to a folder.
- **Import-SSRSReport**(#import-ssrsreport) : Uploads an SSRS Report ( RDL File ) to SQL SSRS Server.  
- **Get-SSRSFolderSettings**(#get-ssrsfoldersettings) : Gets the assigned roles for each folder specified.
- **Get-SSRSReport**(#get-ssrsreport) : Gets a list of SSRS Reports ( RDL File ) on the SQL SSRS Server.  
- **New-SSRSFolderSettings**(#new-ssrsFolderSettings) : Creates an SSRS Folder Settings (New user role assignment).
- **Set-SSRSFolderSettings**(#set-ssrsfoldersettings) : Used to set the folder permissions on an SSRS Server.

***

###Backup-SSRSReport

Backs up / saves an SSRS Report file (RDL) to a folder.

#### Parameters

- **`[String]`SSRSServer** _(Mandatory)_ : The SSRS Server Name.  
- **`[FileInfo]Report** : Name of the report to backup.  Use Get-SSRSReport to obtain the object.
- **`[String]`BackupLocation** : Path to copy the report backups
- **`[PSCredential]`Credential** : Credential of user who has permissions to upload reports ( Pubilsh Role ).

### Import-SSRSReport

Uploads an SSRS Report ( RDL File ) to SQL SSRS Server.

#### Parameters

- **`[String]`SSRSServer** _(Mandatory)_ : The SSRS Server Name.  
- **`[FileInfo]ReportFile** _(Mandatory)_ : File object representing the Report file.
- **`[String]`SSRSReportPath** : SSRS Folder path where the report should be uploaded.  Defaults to the root path /.
- **`[PSCredential]`Credential** : Credential of user who has permissions to upload reports ( Pubilsh Role ).
- **`[Switch]`Overwrite** : When specified, an existing report will be overwritten.
- **`[Switch]`IgnoreWarnings** : Supresses any warnings. The warnings are still written to the Verbose stream.  I included this as a way to allow automated deployments from not freaking out when they see a warning that can be ignored.

### Get-SSRSFolderSettings 

Gets the assigned roles for each folder specified.

#### Parameters

- **`[String]`$SSRSServer** _(Mandatory)_ : The SSRS Server Name.
- **`[String]`$RootFolder** : Root folder to start getting reports.  Defaults to /.
- **`[PSCredential]`Credential** : Credential of user who has permissions to upload reports ( Pubilsh Role ).
- **`[Switch]`$Recurse** : if true recursively retrieve permissions for all folders and subfolders to the root.

### Get-SSRSReport

Gets a list of SSRS Reports ( RDL File ) on the SQL SSRS Server. 

#### Parameters

- **`[String]`SSRSServer** _(Mandatory)_ : The SSRS Server Name.  
- **`[PSCredential]`Credential** : Credential of user who has permissions to list reports ( Browse Role ).

### New-SSRSFolderSettings

Creates an SSRS Folder Settings (New user role assignment).

#### Parameters

- **`[String]`$SSRSServer** _(Mandatory)_ : The SSRS Server Name.
- **`[String]`$USer** : Group Name or User Name to add to folder Settings.
- **`[String[]]`$Role** : Array containing the roles to be assigned to user.
- **`[String]`Folder** : Folder path where the assignments should be applied.  Defaults to the root path /.
- **`[PSCredential]`Credential** : Credential of user who has permissions to upload reports ( Content Manager Role ).

###Set-SSRSFolderSettings

Used to set the folder permissions on an SSRS Server.

#### Parameters

- **`[String]`$SSRSServer** _(Mandatory)_ : The SSRS Server Name.
- **`[String]`$USer** : Group Name or User Name to add to folder Settings.
- **`[String[]]`$Role** : Array containing the roles to be assigned to user.
- **`[String]`Folder** : Folder path where the assignments should be applied.
- **`[PSCredential]`Credential** : Credential of user who has permissions to upload reports ( Content Manager Role ).
