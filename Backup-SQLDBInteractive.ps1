$SQLServer = "jeffb-sql03.stratuslivedemo.com"

$BackupRoot = "\\vaslnas.stratuslivedemo.com\sl_SQL_Backups"

#Connect to SQL
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null
$serverInstance = New-Object ('Microsoft.SqlServer.Management.Smo.Server') "$SQLServer"

#$serverInstance.databases | Select-Object Name | Out-GridView -PassThru | foreach { Backup-SqlDatabase -serverInstance $SqlServer -Database $_.name -backupfile "c:\temp\$($_.Name)_Full_$(Get-Date -UFormat %Y%m%d_%H%M%S).bak" }

$serverInstance.databases | Select-Object Name | Out-GridView -PassThru | foreach { 

Backup-SqlDatabase -serverInstance $SqlServer -Database $_.name -backupfile "$BackupRoot\$(($SQLServer -split '\.')[0])\$($_.Name)_Full_$(Get-Date -UFormat %Y%m%d_%H%M%S).bak"
 }

 #\($_.Name)\FULL