Function Get-SQLSchedule {

<#
    .Synopsis
        Returns a list of SQL Job Schedules

    .Description
        Returns the Job schedules listed in the dbo.sysschedules database.

    .Parameter ComputerName
        Name of the SQL Server

    .Example
        Get the list of schedules from the local SQL server

        Get-SQLSchedule

        schedule_id            : 8
        schedule_uid           : d0c45013-f0fb-4140-8eb7-ac963e30ec5c
        originating_server_id  : 0
        name                   : syspolicy_purge_history_schedule
        owner_sid              : {1}
        enabled                : 1
        freq_type              : 4
        freq_interval          : 1
        freq_subday_type       : 1
        freq_subday_interval   : 0
        freq_relative_interval : 0
        freq_recurrence_factor : 0
        active_start_date      : 20080101
        active_end_date        : 99991231
        active_start_time      : 20000
        active_end_time        : 235959
        date_created           : 4/19/2016 12:06:51 PM
        date_modified          : 4/19/2016 12:06:51 PM
        version_number         : 1

        schedule_id            : 9
        schedule_uid           : f2a87e8f-91fe-4402-aa2a-c613fb4b2eeb
        originating_server_id  : 0
        name                   : Schedule
        owner_sid              : {1, 5, 0, 0...}
        enabled                : 1
        freq_type              : 4
        freq_interval          : 1
        freq_subday_type       : 1
        freq_subday_interval   : 0
        freq_relative_interval : 0
        freq_recurrence_factor : 0
        active_start_date      : 20160520
        active_end_date        : 99991231
        active_start_time      : 3000
        active_end_time        : 235959
        date_created           : 5/20/2016 2:12:08 PM
        date_modified          : 5/20/2016 2:12:08 PM
        version_number         : 1

    .Link
        dbo.Sysschedules database

        https://msdn.microsoft.com/en-us/library/ms178644.aspx

    .Note
        Author : Jeff Buenting
        Date : 2016 JUN 24
#>
    
    [CmdletBinding()]
    Param (
        [Alias('ComputerName')]
        [String]$SQLInstance = $env:COMPUTERNAME,

        [String]$Name
    )

    $Schedules = invoke-sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "SELECT * FROM dbo.sysschedules"
    
    if ( $Name ) {
 
        $Schedules = $Schedules | where Name -eq $Name
     }
    
    Write-Output $Schedules

}

import-module 'C:\Program Files (x86)\Microsoft SQL Server\110\Tools\PowerShell\Modules\SQLPS\sqlps' -disablenamechecking
"111"
Get-SQLSchedule -sqlinstance jeffb-sql01.stratuslivedemo.com -Name 2am -Verbose

"hello"