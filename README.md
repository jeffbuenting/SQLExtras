# SQL
Powershell SQL Cmdlets and SQL Scripts

##Cmdlets

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
- **Upload-SSRSReport** :   Uploads an SSRS Report ( RDL File ) to SQL SSRS Server.  
- **Get-SSRSReport** :  Gets a list of SSRS Reports ( RDL File ) on the SQL SSRS Server.  
- **Get-SQLClientProtocol** :  lists SQL Protocol Client status.  
- **Get-SQLNetworkProtocol** : Lists SQL Server Protocol Status.
- **Set-SQLNetworkProtocol** :   Changes SQL Network Protocol Settings.  
- **Get-SQLDBMail** :  Retrieves the SQL DB Mail Settings.  
- **Get-SQLDBMailAccount** :  Retrieves a SQL DB Mail Account.  

##Installation

Download the InternetExplorer.PSM1 and PSD1 files.  Copy them to your C:\Program Files\WindowsPowershell\Modules directory or a directory that is in the PSModulePath.  Then you can either explicitly import it or let powershells autoload take care if it if you use one of the cmdlets.
