Function New-SQLSchedule {

<#
    .Synopsis
        Creates new SQL Job Schedule

    .Description
        

    .Parameter SQLInstance
        SQL Serverver and instance

    .Parameter Name
        Name of the new Schedule

    .Parameter Frequency
        How often the schedule should run

    .Parameter StartTime
        Time the job will begin running.

    .Link
        https://msdn.microsoft.com/en-us/library/cc645912.aspx

    .Link
        Schedule parameter explaination

        https://msdn.microsoft.com/en-us/library/ms187320.aspx
#>

[CmdletBinding()]
    Param (
        [Alias('ComputerName')]
        [String]$SQLInstance = $env:COMPUTERNAME,

        [Parameter(Mandatory = $True)]
        [String]$Name,

        [ValidateSet('Once','Daily','Weekly','Monthly','Monthly relative to Freq_interval','Run when SQL Agent Starts','Run when computer is idle')]
        [String]$Frequency = 'Once',

        [Parameter ( HelpMessage = "The time on any day to begin execution of a job. The time is a 24-hour clock, and must be entered using the form HHMMSS.")]
        [Validatescript ( { $_ -match '\d{6}' } )]
        [String]$StartTime = 000000
    )

    Begin {
        $FreqArray = 'Once','blank','Daily','Weekly','Monthly','Monthly relative to Freq_interval','Run when SQL Agent Starts','Run when computer is idle'

        $SP_Add_Schedule = "USE msdb ;

            EXEC dbo.sp_add_schedule
                @schedule_name = N'$Name',
                @enabled = 1,
                @freq_type = $([Math]::pow(2,$FreqArray.IndexOf( $Frequency ))),
                @freq_interval = 1,
                @freq_subday_type = 1,
                @freq_subday_interval = 0,
                @freq_relative_interval = 0,
                @freq_recurrence_factor = 0,
                @active_start_date = 20150120,
                @active_end_date = 99991231,
                @active_start_time = $StartTime,
                @active_end_time = 235959"
    }

    Process {
        
        Foreach ( $S in $SQLInstance ) {
            Write-Verbose "Adding schedule $Name to SQL on $S"

            # ----- Check if the schedule already exist to prevent duplicates
            if ( Get-SQLSchedule -SQLInstance $S -Name $Name ) { Write-Error "A schedule named $Name already exists on $S"; Continue }
        
            Invoke-Sqlcmd -ServerInstance $S -Database msdb -Query $SP_Add_Schedule
        } 
    }
}

import-module 'C:\Program Files (x86)\Microsoft SQL Server\110\Tools\PowerShell\Modules\SQLPS\sqlps' -disablenamechecking

New-SQLSchedule -SQLInstance jeffb-sql01.stratuslivedemo.com -Frequency 'Daily' -Name 2am -StartTime 020000 -verbose