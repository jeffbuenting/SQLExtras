$BackupRoot = '\\sl-jeffb\h$\wgpqa1_backup'
$SQLServer = 'WGPQA1-SQL'
$TempDrive = "c:\Temp"

$Location = Get-Location

Get-ChildItem -Path "$Backuproot\$SQLServer" -Directory | Select-Object Name | Out-GridView -OutputMode Multiple -Title 'Select a DB to restore on $SQLServer' | Foreach {

    Write-Output "Restoring $($_.Name)"

    # ----- retrieve latest backup by date
    $DBFile = Get-ChildItem -Path "$Backuproot\$SQLServer\$($_.Name)\full" | Sort-Object CreationTime -Descending | Select-Object -First 1

    # ----- Because we have a double hop issue with restoring from a network share to a remote server, we will copy the file to the remote server and restore from there
    copy-item -Path $DBFile.FullName -Destination "\\$SQLServer\$($TempDrive.Replace(':','$'))" -Force

    # ----- different servers have different  file locations ( yeah, I know ).  Restoring to the default location of the specific server
    $DefaultLocation = Invoke-Sqlcmd -ServerInstance $SQLServer -Query "select SERVERPROPERTY('instancedefaultdatapath') AS [DefaultFile], SERVERPROPERTY('instancedefaultlogpath') AS [DefaultLog]"
    
    # ----- Extract the filenames from the backup file
    $files = Invoke-Sqlcmd -ServerInstance $SQLServer -Query "RESTORE FILELISTONLY FROM DISK = N'$TempDrive\$($DBFILE.Name )'"
    $dataFile = $files | Where-Object -Property Type -EQ "D"
    $logFile = $files | Where-Object -Property Type -EQ "L"
    
    $RelocateData = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile("$($DataFile.Logicalname)", "$($DefaultLocation.DefaultFile)\$($DataFile.Logicalname).mdf")
    $RelocateLog = New-Object Microsoft.SqlServer.Management.Smo.RelocateFile("$($LogFile.Logicalname)", "$($DefaultLocation.DefaultFile)\$($LogFile.Logicalname).ldf")

    # ----- Restore
    Restore-SqlDatabase -ServerInstance $SQLServer -Database $_.Name -BackupFile "$TempDrive\$($DBFILE.Name )" -RelocateFile @($RelocateData,$RelocateLog)
}

Set-Location $Location