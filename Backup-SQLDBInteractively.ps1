# -------------------------------------------------------------------------------------
# Backup Selected SQL DBs
#
# Must be ran on SQL Server
# Designed to be used with the OLA Hallegren scripts.
#
# CHANGE the $BULocation to point to the server/share where the backups are to be stored
#
# CHANGE the $NotAutomaticallyDeleted switch to $True if you want to retain a copy that will not be automatically cleaned up when the OLA scripts are run.
#--------------------------------------------------------------------------------------

#$BULocation = "\\RWVA-Storage\e$\SQLBackups"
$BULocation = "\\vaslnas.stratuslivedemo.com\SL_SQL_Backups"

$NotAutomaticallyDeleted = $False

#--------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------

$SQLServer = $env:COMPUTERNAME

# ----- SQL SMO will switch to the SQL Provider.  This causes issues when doing other stuff.  So setting the location to what it was prior to connecting the SMO provider
$Location = Get-Location
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.SqlServer.SMO') | out-null
$serverInstance = New-Object ('Microsoft.SqlServer.Management.Smo.Server') "$SQLServer"
Set-Location $Location

$serverInstance.databases | Select-Object Name | Out-GridView -PassThru | foreach { 
    
    # ----- Checking if the SQL is FQDN. Splitting out the NetBIOS name as that is what we use in the folder and naming convention
    $ServerName = ($sqlserver.Split('.'))[0].ToUpper()
    $BackupName = "$($ServerName)_$($_.Name)_FULL_$(Get-Date -UFormat %Y%m%d_%H%M%S).bak"

    # ----- Check local path existence
    if ( -Not ( Test-Path -Path c:\temp ) ) { New-item -Path c:\temp -ItemType Directory }

    # ----- Check remote backup storeage path existence
    if ( -Not ( Test-Path -Path "$BULocation\$ServerName\$($_.Name)\FULL" ) ) { New-Item -Path "$BULocation\$ServerName\$($_.Name)\FULL" -ItemType Directory }

    # ----- Becuase I can't get Backup-SQLDatabase to backup the DB to a remote location, I back them up locally and the move them to the remote location.
    Backup-SqlDatabase -serverInstance $SqlServer -Database $_.name -backupfile "c:\temp\$BackupName" 

    # ----- Copy Backup to a location that is not automatically cleaned.  Older backups won't be deleted.
    if ( $NotAutomaticallyDeleted ) {
        if ( -Not ( Test-Path -Path "$BULocation\$ServerName\$($_.Name)\NotAutomaticallyDeleted" ) ) { New-Item -Path "$BULocation\$ServerName\$($_.Name)\NotAutomaticallyDeleted" -ItemType Directory }
        Copy-Item -Path c:\temp\$BackupName -Destination "$BULocation\$ServerName\$($_.Name)\NotAutomaticallyDeleted\$BakcuName"
    }

    move-item -Path c:\temp\$BackupName -Destination "$BULocation\$ServerName\$($_.Name)\FULL\$BackupName"
}