# SQLExtras

Powershell SQL Cmdlets and SQL Scripts wrapped in a SQLExtras module

## Branches

### Master

Version: 3.0

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

- **Import-SSRSReport**(#Import-SSRSReport) :   Uploads an SSRS Report ( RDL File ) to SQL SSRS Server.  
- **Get-SSRSReport** :  Gets a list of SSRS Reports ( RDL File ) on the SQL SSRS Server.  

### Import-SSRSReport

Uploads an SSRS Report ( RDL File ) to SQL SSRS Server.

#### Parameters

- **`[String]`SSRSServer** _(Mandatory)_ : The SSRS Server Name.  
- **`[FileInfo]ReportFile** _(Mandatory)_ : File object representing the Report file.
- **`[String]`SSRSReportPath** : SSRS Folder path where the report should be uploaded.  Defaults to the root path /.
- **`[PSCredential]`Credential** : Credential of user who has permissions to upload reports ( Pubilsh Role ).
- **`[Switch]`Overwrite** : When specified, an existing report will be overwritten.
- **`[Switch]`IgnoreWarnings** : Supresses any warnings. The warnings are still written to the Verbose stream.  I included this as a way to allow automated deployments from not freaking out when they see a warning that can be ignored.

