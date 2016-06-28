Function Set-SQLJob {

<#
    .Synopsis
        Edit a SQL Job

    .Description
        Allows edit / changes to a SQL Job

    .Parameter SQLInstance
        SQL server\Instance to retrieve jobs.

    .Parameter SQLJob
        Object that represents a sql job.  Use Get-SQLJob.

    .Parameter ScheduleName
        Name of the schedule to assign to the job.  Schedule must already exist.  Use New-SQLSchedule to create.

    .Example
        Assign schedule to job

        $SQLJob = Get-SQLJob -SQLInstance 'ServerA' -Name 'FullBackup'
        Set-SQLJob -SQLInstance 'ServerA' -SQLJob $SQLJob -ScheduleName '2am'

    .Note
        Author : Jeff Buenting
        Date : 2016 JUN 27

#>

    [CmdletBinding()]
    Param (
        [Alias('ComputerName')]
        [String]$SQLInstance = $env:COMPUTERNAME,

        [Parameter (Mandatory = $True)]
        [System.Data.DataRow]$SQLJob,

        [String]$ScheduleName
    )

    if ( $ScheduleName ) {
        Write-verbose "Setting SQL Job ( $($J.Name) ) Schedule to $ScheduleName"

        if ( Get-SQLSchedule -SQLInstance $SQLInstance -Name $ScheduleName ) {
                Invoke-Sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "sp_attach_Schedule @Job_id = '$($SQLJob.Job_ID)', @Schedule_Name = N'$ScheduleName'"
            }
            else {
                Write-Error "Schedule, $ScheduleName does not exist"
        }
    }
}

$J = Get-SQLJob -SQLInstance Jeffb-sql01.stratuslivedemo.com -Name MSCRM*
Set-SQLJob -SQLInstance jeffb-sql01.stratuslivedemo.com -SQLJob $J -ScheduleName 2am -Verbose