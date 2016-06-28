Function Get-SQLJob {

<#
    .Synopsis
        Gets a list of jobs on a sql server.

    .Description
        Returns SQL jobs.

    .Parameter SQLInstance
        SQL server\Instance to retrieve jobs.

    .Parameter Name
        Name of the job to return.  Default is to return all. Wildcards are accepted.

    .Parameter Credential
        Either windows username/password or sql username/password when used with the SQLAuthentication switch

    .Parameter SQLAuthentication
        When used indicates the Credential parameter is a SQL username/password

    .Example
        Return all jobs from ServerA.

        Get-SQLJob -SQLInstance 'ServerA'

    .Example
        Return the job named 'Backup' using windows authentication

        Get-SQLJob -SQLInstance 'ServerA' -Credential (get-Credential) -Name 'Backup'

    .Example
        List the SQL Jobs using SQL Authentication on the local server.

        Get-SQLJob -Credential (Get-Credential) -SQLAuthentication

    .Note
        Author : Jeff Buenting
        Date : 2016 JUN 27   
#>

    [cmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        
        [Alias('ComputerName')]
        [String]$SQLInstance = $env:COMPUTERNAME,
                
        [String]$Name,
                
        [Parameter(ParameterSetName = 'WinAuth',Mandatory = $True)]
        [Parameter(ParameterSetName = 'SQLAuth',Mandatory = $True)]
        [PSCredential]$Credential,
        
        [Parameter(ParameterSetName = 'SQLAuth',Mandatory = $True)]
        [Switch]$SQLAuthentication

  #      [Parameter(ParameterSetName = 'WinAuth',Mandatory = $True)]
  #     [PSCredential]$RunAs
    )
    
    Process {
        Write-Verbose "Getting SQL jobs from $SQLInstance"
       
        Switch ( $PSCmdlet.ParameterSetName ) {
            'SQLAuth' {
                Write-Verbose "Using SQL Authentication"
                $SQLJobs = Invoke-SQLCmd -ServerInstance $SQLInstance -Database msdb -Query "SELECT Job.*, Sched.name as Schedule_Name,Sched.schedule_id FROM dbo.sysjobs as Job INNER Join dbo.sysjobschedules as JobSched on Job.job_id = JobSched.Job_id INNER JOIN dbo.sysschedules as Sched on JobSched.schedule_id = Sched.schedule_id" -Username $Credential.UserName -Password $Credential.GetNetworkCredential().Password
            }

            'WinAuth' {
                Write-Verbose "Windows Authentication supplying credentials"
                $SQLJobs =invoke-Command -ComputerName $SQLInstance -Credential $Credential -ScriptBlock {
                    Write-Output (Invoke-SQLCmd -ServerInstance $Using:SQLInstance -Database msdb -Query "SELECT Job.*, Sched.name as Schedule_Name,Sched.schedule_id FROM dbo.sysjobs as Job INNER Join dbo.sysjobschedules as JobSched on Job.job_id = JobSched.Job_id INNER JOIN dbo.sysschedules as Sched on JobSched.schedule_id = Sched.schedule_id")
                }
            }

            Default {
                $SQLJobs = Invoke-SQLCmd -ServerInstance $SQLInstance -Database msdb -Query "SELECT Job.*, Sched.name as Schedule_Name,Sched.schedule_id FROM dbo.sysjobs as Job INNER Join dbo.sysjobschedules as JobSched on Job.job_id = JobSched.Job_id INNER JOIN dbo.sysschedules as Sched on JobSched.schedule_id = Sched.schedule_id"
            }
        }

        
        if ( $Name ) { $SQLJobs = $SQLJobs | where Name -like $Name }
        
        Write-Output $SQLJobs
    }
}

Get-SQLJob -SQLInstance jeffb-sql01.stratuslivedemo.com -Credential (Get-Credential) -sqlauthentication