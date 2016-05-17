 $SQLServer = 
 $Login = 
 
 
 import-module 'C:\Program Files (x86)\Microsoft SQL Server\110\Tools\PowerShell\Modules\SQLPS\sqlps' -disablenamechecking 
 import-module 'C:\scripts\sql\SQL.psm1' -force

[System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") #| out-null
$SMOserver = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $SQLServer

$SMOServer.Databases | where name -like "Hello*" | Select-Object -ExpandProperty Name | Set-SQLDBLoginRoles -ServerInstance $SQLServer -Login $Login -DBRole db_datareader,db_datawriter -Verbose