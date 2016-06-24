Function Set-SQLJob {

<#
    .Synopsis
        Edit a SQL Job

#>

    [CmdletBinding()]
    Param (
        [Alias('ComputerName')]
        [String]$SQLInstance = $env:COMPUTERNAME,

        [System.Data.DataRow]$SQLJob,

        [String]$ScheduleName
    )

    $SQLJob

    if ( $ScheduleName ) {
        Write-verbose "Setting SQL Job ( $J.Name ) Schedule to $ScheduleName"
    #    Invoke-Sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "sp_attach_Schedule @Job_id = $($SQLJob.Job_ID), @Schedule_Name = $ScheduleName"
    }

}

$J = Get-SQLJob -SQLInstance Jeffb-sql01.stratuslivedemo.com -Name MSCRM*
Set-SQLJob -SQLInstance jeffb-sql01.stratuslivedemo.com -SQLJob $J -Verbose