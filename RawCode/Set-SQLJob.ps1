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

    .Parameter AttachSchedule
        specifies the ScheduleName should be attached to the SQLJob

    .Parameter DetachSchedule
        Specifies the scheduleName should be removed from the SQLJob

    .parameter Credential
        Either a domain or SQL account user name / password with permissions to log onto the SQL server.

    .Example
        Assign schedule to job

        $SQLJob = Get-SQLJob -SQLInstance 'ServerA' -Name 'FullBackup'
        Set-SQLJob -SQLInstance 'ServerA' -SQLJob $SQLJob -ScheduleName '2am'

    .Link
        https://msdn.microsoft.com/en-us/library/ms187734.aspx


    .Note
        Author : Jeff Buenting
        Date : 2016 JUN 27

#>

    [CmdletBinding()]
    Param (
        [Alias('ComputerName')]
        [String]$SQLInstance = $env:COMPUTERNAME,

        [Parameter (Mandatory = $True)]
      #  [System.Data.DataRow]$SQLJob,
        [PSCustomObject]$SQLJob,

        [Parameter (ParameterSetName = 'AttachSchedule',Mandatory = $True)]
        [Parameter (ParameterSetName = 'DetachSchedule',Mandatory = $True)]
        [String]$ScheduleName,

        [Parameter (ParameterSetName = 'AttachSchedule',Mandatory = $True)]
        [Switch]$AttachSchedule,

        [Parameter (ParameterSetName = 'DetachSchedule',Mandatory = $True)]
        [Switch]$DetachSchedule,

        [PSCredential]$Credential
    )

    switch ( $PSCmdlet.ParameterSetName ) {
        'AttachSchedule' {
            Write-verbose "Setting SQL Job ( $($SQLJob.Name) ) Schedule to $ScheduleName"
        
            If ( $Credential ) {
                    if ( $Credential.UserName -match '\\' ) {
                            # ----- Username has domain name so using windows auth
                            invoke-command -ComputerName $SQLInstance -Credential $Credential -ScriptBlock {
                                if ( invoke-sqlcmd -ServerInstance $Using:SQLInstance -Database msdb -Query "SELECT * FROM dbo.sysschedules" | where Name -eq $Using:ScheduleName ) {
                                        Invoke-Sqlcmd -ServerInstance $Using:SQLInstance -Database msdb -Query "sp_attach_Schedule @Job_id = '$($Using:SQLJob.Job_ID)', @Schedule_Name = N'$Using:ScheduleName'" 
                                    }
                                    else {
                                        Write-Error "Schedule, $Using:ScheduleName does not exist"
                                }
                            }
                        }
                        else {
                            # ----- Username does not have domain name so SQL Auth
                            Invoke-Sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "sp_attach_Schedule @Job_id = '$($SQLJob.Job_ID)', @Schedule_Name = N'$ScheduleName'" -Username $Credential.UserName -Password $Credential.GetNetworkCredential().Password
                    }
                }
                else {
                    Invoke-Sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "sp_attach_Schedule @Job_id = '$($SQLJob.Job_ID)', @Schedule_Name = N'$ScheduleName'" 
            }
        }

        'DetachSchedule' {
            Write-verbose "Removing $ScheduleName Schedule from SQL Job ( $($SQLJob.Name) )"

            If ( $Credential ) {
                    if ( $Credential.UserName -match '\\' ) {
                            # ----- Username has domain name so using windows auth
                            invoke-command -ComputerName $SQLInstance -Credential $Credential -ScriptBlock {
                                if ( invoke-sqlcmd -ServerInstance $Using:SQLInstance -Database msdb -Query "SELECT * FROM dbo.sysschedules" | where Name -eq $Using:ScheduleName ) {
                                        Invoke-Sqlcmd -ServerInstance $Using:SQLInstance -Database msdb -Query "sp_detach_Schedule @Job_id = '$($Using:SQLJob.Job_ID)', @Schedule_Name = N'$Using:ScheduleName', @delete_unused_schedule = 1" 
                                    }
                                    else {
                                        Write-Error "Schedule, $Using:ScheduleName does not exist"
                                }
                            }
                        }
                        else {
                            # ----- Username does not have domain name so SQL Auth
                            Invoke-Sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "sp_detach_Schedule @Job_id = '$($SQLJob.Job_ID)', @Schedule_Name = N'$ScheduleName', @delete_unused_schedule = 1" -Username $Credential.UserName -Password $Credential.GetNetworkCredential().Password
                    }
                }
                else {
                    Invoke-Sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "sp_detach_Schedule @Job_id = '$($SQLJob.Job_ID)', @Schedule_Name = N'$ScheduleName', @delete_unused_schedule = 1" 
            }
        }
    }
}

$Cred = get-Credential stratuslivedemo\administrator

$J = Get-SQLJob -SQLInstance Jeffb-sql01.stratuslivedemo.com -Name MSCRM*

#Set-SQLJob -SQLInstance jeffb-sql01.stratuslivedemo.com -SQLJob $J -ScheduleName 2am -AttachSchedule -Credential $Cred -Verbose
Set-SQLJob -SQLInstance jeffb-sql01.stratuslivedemo.com -SQLJob $J -ScheduleName 2am -DetachSchedule -Credential $Cred -Verbose