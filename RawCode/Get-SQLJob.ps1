Function Get-SQLJob {

<#
    .Synopsis
        Gets a list of jobs on a sql server.

    
#>

    [cmdletBinding()]
    param (
        [Alias('ComputerName')]
        [String]$SQLInstance = $env:COMPUTERNAME,

        [String]$Name
    )
    
    Process {

       
        $SQLJobs = invoke-sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "SELECT * FROM dbo.sysjobs"


        if ( $Name ) { $SQLJobs = $SQLJobs | where Name -like $Name }

        Write-Output $SQLJobs

    }
}

Get-SQLJob -SQLInstance Jeffb-sql01.stratuslivedemo.com -Name MSCRM*