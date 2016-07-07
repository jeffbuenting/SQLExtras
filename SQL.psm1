#----------------------------------------------------------------------------------
# SQL Security Cmdlets
#----------------------------------------------------------------------------------

Function Get-SQLDBLoginRoles {

<#
    .Description
        Returns a list of SQL logins and their database Roles.

    .Parameter ServerInstance
        Name of the SQL server you want login information about.

        Defaults to LocalHost.

    .Parameter Databasename
        Name of the database to retrieve info.  If black info will be returned from all databases on the server.

    .Parameter Login
        Filters the returned info on a particular Login

    .Example
        Get-SQLDBLoginRoles -ServerInstance jeffb-sql03

        Gets every user mapping for every database on the server.

    .Example
        Get-SQLDBLoginRoles -ServerInstance jeffb-sql03 

        Gets the User mappings for every database.

    .Example
        Get-SQLDBLoginRoles -ServerInstance jeffb-sql03 -DatabaseName 'jeffbtest_MSCRM'

        Gets the user mappings for the database Jeffbtest_MSCRM

    .Example 
        Get-SQLDBLoginRoles -ServerInstance jeffb-sql03 -Login 'Contoso\jeff.buenting'

        Gets the user mappings for contoso\jeff.buenting on every database on SQL server Jeffb-sql03

#>


    [CmdletBinding()]
    Param (
        [String]$ServerInstance="localhost",

        [Parameter(ValueFromPipeline=$true)]
        [String]$databaseName,
        
        [String]$Login
    )

    Begin {
        # ----- Load the SQL module if not already loaded
        if ( -Not (Get-module -Name SQLPS) ) {
            Write-Verbose 'Importing SQL Module as it is not already installed'
            $SQLModuleInstalled = $False
            $Location = $PWD
            import-module '\\sl-jeffb\f$\Sources\Powershell Modules\SQLPS\sqlps' -disablenamechecking
        }

        # ----- Establish Connection to SQL Server
        write-Verbose "Establishing connection to server"
        $serverConnection = new-object Microsoft.SqlServer.Management.Common.ServerConnection
        $serverConnection.ServerInstance=$serverInstance

    }

    Process {
        # ----- Connect to Database
        Write-Verbose "Getting User info for Database: $DatabaseName"
        $server = new-object Microsoft.SqlServer.Management.SMO.Server($serverConnection)
        if ( [String]::isNullorEmpty($databaseName) ) {
                Write-Verbose "Returning Login Permissions from every database"
                $DataBases = $Server.Databases
            }
            else {
                $databases = $server.Databases[$databaseName]
        }
        
        forEach ( $DB in $databases ) {
            foreach($user in $DB.Users) {
                Write-Verbose "Permissions for User: $User"
               
                $SQLLogin = New-object -TypeName PSCustomObject -Property @{
                    'Login' = $User.Login
                    'Roles' = $User.EnumRoles()
                    'DataBase' = $DB.Name
                }
                if ( [String]::IsNullOrEmpty($Login) ) {
                        Write-Output $SQLLogin
                    }
                    else {
                        if ( $SQLLogin.Login -eq $Login ) {
                            Write-OutPut $SQLLogin
                        }
                }

            }
       }
    }

    End {
        $server.ConnectionContext.Disconnect()
        if ( $SQLModuleInstalled ) {
            # ----- Cleanup
            Write-Verbose 'Removing SQL Module'
            Set-Location -Path $Location
            Remove-Module SQLPS
        }
    }
    
}

#----------------------------------------------------------------------------------

Function Set-SQLDBLoginRoles {

<#
    .Description
        Adds SQL login to the Database security Roles.

    .Parameter ServerInstance
        Name of the SQL server.  Defaults to LocalHost.

    .Parameter DatabaseName
        Name of the Database to add the login permission.

    .Parameter Login
        Account to add to the database.

    .Parameter DBRole
        DB SQL security role to add the login to.

    .Link
        https://social.technet.microsoft.com/Forums/windowsserver/en-US/185a42ba-9f49-4c55-aecb-ed6fe72c5008/new-user-with-smo?forum=winserverpowershell

    .Example
        Set-SQLDBLoginRoles -ServerInstance jeffb-sql03 -databaseName test -Login Contoso\jeffbtest -DBRole db_datareader,db_datawriter
#>

    [CmdletBinding()]
    Param (
        [String]$ServerInstance="localhost",

        [Parameter(ValueFromPipeline=$true)]
        [String]$databaseName,

        [String]$Login,

        [ValidateSet('db_accessadmin','db_backupoperator','db_datareader','db_datawriter','db_ddladmin','db_denydatareader','db_denydatawriter','db_owner','db_securityadmin')]
        [String[]]$DBRole
    )

    Begin {
        # ----- Load the SQL module if not already loaded
        if ( -Not (Get-module -Name SQLPS) ) {
            Write-Verbose 'Importing SQL Module as it is not already installed'
            $SQLModuleInstalled = $False
            $Location = $PWD
            import-module '\\sl-jeffb\f$\Sources\Powershell Modules\SQLPS\sqlps' -disablenamechecking
        }

        # ----- Establish Connection to SQL Server
        $serverConnection = new-object Microsoft.SqlServer.Management.Common.ServerConnection
        $serverConnection.ServerInstance=$serverInstance
        $server = new-object Microsoft.SqlServer.Management.SMO.Server($serverConnection)

    }

    Process {
        # ----- Check if Role already set.  
        $ExistingLogins = Get-SQLDBLoginRoles -ServerInstance $ServerInstance -databaseName $databaseName -Login $Login
        
        $DB = $Server.Databases[$DataBaseName]

        Write-Verbose "Assigning roles to login"
        if ( $ExistingLogins.Login -ne $Login ) {
                Write-Verbose "Creating DB Login: $DB  $Login"
                
                
                $user = new-object ('Microsoft.SqlServer.Management.Smo.User') $DB, $Login
                $user.Login = $Login
                if ($server.Information.Version.Major -ne '8') { $user.DefaultSchema = 'dbo' }
                $user.Create()
            }
            else {
                Write-Verbose "Already exists.  Retrieving login"
                $user = $DB.users | where Login -eq $Login
        }
        Write-Verbose "Assigning DB roles"
        Foreach ( $Role in $DBRole ) {
            $User.AddtoRole($Role)
        }
        
    }

    End {
       # $server.ConnectionContext.Disconnect()
        if ( $SQLModuleInstalled ) {
            # ----- Cleanup
            Write-Verbose 'Removing SQL Module'
            Set-Location -Path $Location
            Remove-Module SQLPS
        }
    }

}

#----------------------------------------------------------------------------------
# Database Cmdlets
#----------------------------------------------------------------------------------

Function Remove-SQLDatabase {

    [CmdBinding()]
    param (
        [String]$ServerInstance,

        [String[]]$Database
    )

    Begin {
        # ----- Load the SQL module if not already loaded
        if ( -Not (Get-module -Name SQLPS) ) {
            Write-Verbose 'Importing SQL Module as it is not already installed'
            $SQLModuleInstalled = $False
            $Location = $PWD
            import-module 'C:\Program Files (x86)\Microsoft SQL Server\110\Tools\PowerShell\Modules\SQLPS\sqlps' -disablenamechecking 
        }
        
        Write-Verbose "Making connection to SQL server: $ServerInstance"
        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null
        $SMOserver = New-Object ('Microsoft.SqlServer.Management.Smo.Server') -argumentlist $ServerInstance
    }

    Process {
        foreach ( $DB in $Database ) {
            $smoserver.killallprocess($DB)
            $smoserver.databases[$DB].drop() 
        }
    }

    End {
        Remove-Variable -Name $SMOServer

        if ( $SQLModuleInstalled ) {
            # ----- Cleanup
            Write-Verbose 'Removing SQL Module'
            Set-Location -Path $Location
            Remove-Module SQLPS
        }
    }

}

#----------------------------------------------------------------------------------
# SQL Job Cmdlets
#----------------------------------------------------------------------------------

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
        [Switch]$SQLAuthentication,

        [switch]$Force
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
                    
                    # ----- Check execution Policy and override if -Force is include.
                    $Policy = Get-ExecutionPolicy 
                    if ( $Policy -ne 'Unrestricted' ) {
                        if ( $Using:Force ) {
                                Write-Verbose "Overridding execution policy"
                                Set-ExecutionPolicy Unrestricted
                            }
                            Else {
                                Write-Error "Running scrips on remote computer ( $Using:S ) is disabled.  See about_Execution_Policies for mor information.  Or use the -Force switch to override"
                        }
                    }
                                
                                          
                   # import-module 'C:\Program Files (x86)\Microsoft SQL Server\110\Tools\PowerShell\Modules\SQLPS\SQLPS.PSD1'
                    Write-Output (Invoke-SQLCmd -ServerInstance $Using:SQLInstance -Database msdb -Query "SELECT Job.*, Sched.name as Schedule_Name,Sched.schedule_id FROM dbo.sysjobs as Job INNER Join dbo.sysjobschedules as JobSched on Job.job_id = JobSched.Job_id INNER JOIN dbo.sysschedules as Sched on JobSched.schedule_id = Sched.schedule_id")
                        
                }
            }

            Default {
                $SQLJobs = Invoke-SQLCmd -ServerInstance $SQLInstance -Database msdb -Query "SELECT Job.*, Sched.name as Schedule_Name,Sched.schedule_id FROM dbo.sysjobs as Job INNER Join dbo.sysjobschedules as JobSched on Job.job_id = JobSched.Job_id INNER JOIN dbo.sysschedules as Sched on JobSched.schedule_id = Sched.schedule_id"
            }
        }

        
        if ( $Name ) { $SQLJobs = $SQLJobs | where Name -like $Name }

        #write-verbose "$($SQLJobs | out-string)"
        
        Write-Output $SQLJobs
    }
}

#----------------------------------------------------------------------------------

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

        [Parameter (Mandatory = $True,ValueFromPipeline = $True)]
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

#----------------------------------------------------------------------------------
# SQL Job Schedule Cmdlets
#----------------------------------------------------------------------------------

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

    .Parameter FreqInterval
        Used in conjuction with Frequency

        Frequency          Effect on FreqInterval
        
        Once               Unused

        Daily              Every FreqInterval Days

        Weekly             freq_interval is one or more of the following (combined with an OR logical operator):
                           1 = Sunday
                           2 = Monday
                           4 = Tuesday
                           8 = Wednesday
                           16 = Thursday
                           32 = Friday
                           64 = Saturday

        Monthly            on the FreqInterval day of the month

        Monthly Relative   FreqInterval is one of the following
                           1 = Sunday
                           2 = Monday
                           3 = Tuesday
                           4 = Wednesday
                           5 = Thursday
                           6 = Friday
                           7 = Saturday
                           8 = Day
                           9 = Weekday
                           10 = Weekend Day

        When SQL Agent Starts Unused


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

        [Int]$FreqInterval = 1,

        [int]$FreqRecurranceFactor,

        [Parameter ( HelpMessage = "The time on any day to begin execution of a job. The time is a 24-hour clock, and must be entered using the form HHMMSS.")]
        [Validatescript ( { $_ -match '\d{6}' } )]
        [String]$StartTime = 000000,

        [Parameter(ParameterSetName = 'WinAuth',Mandatory = $True)]
        [Parameter(ParameterSetName = 'SQLAuth',Mandatory = $True)]
        [PSCredential]$Credential,
        
        [Parameter(ParameterSetName = 'SQLAuth',Mandatory = $True)]
        [Switch]$SQLAuthentication,

        [Switch]$Force

    )

    Begin {
        $FreqArray = 'Once','blank','Daily','Weekly','Monthly','Monthly relative to Freq_interval','Run when SQL Agent Starts','Run when computer is idle'

        # ----- This sets the defaults for FreqRecuranceFactor.  Doing it this way Because it is different depending on what FreqInterval is.  And I could not figure out how to get it to work in the parameter section
        if ( -Not $FreqRecurranceFactor ) {
            Write-Verbose "Freq = $Frequency"
             if ( ($Frequency -eq 8) -or ($Frequency -eq 16) -or ($Frequency -eq 32) ) { 
                    $FreqRecurranceFactor = 1
                }
                Else {
                    $FreqRecurranceFactor = 0
            }
        }

        # ----- Creates the SQL Query to build the SQL Job Schedule
        $SP_Add_Schedule = "USE msdb ;

            EXEC dbo.sp_add_schedule
                @schedule_name = N'$Name',
                @enabled = 1,
                @freq_type = $([Math]::pow(2,$FreqArray.IndexOf( $Frequency ))),
                @freq_interval = $FreqInterval,
                @freq_subday_type = 1,
                @freq_subday_interval = 0,
                @freq_relative_interval = 0,
                @freq_recurrence_factor = $FreqRecurranceFactor,
                @active_start_date = 20150120,
                @active_end_date = 99991231,
                @active_start_time = $StartTime,
                @active_end_time = 235959"

        write-Verbose $SP_Add_Schedule
    }

    Process {
        
        Foreach ( $S in $SQLInstance ) {
            Write-Verbose "Adding schedule $Name to SQL on $S"

            Switch ( $PSCmdlet.ParameterSetName ) {
                'SQLAuth' {
                    Write-Verbose "Using SQL Authentication"

                    # ----- Check if the schedule already exist to prevent duplicates
                    if ( Get-SQLSchedule -SQLInstance $S -Name $Name ) { Write-Error "A schedule named $Name already exists on $S"; Continue }

                    Invoke-Sqlcmd -ServerInstance $S -Database msdb -Query $SP_Add_Schedule -Username $Credential.UserName -Password $Credential.GetNetworkCredential().Password
                }

                'WinAuth' {
                    Write-Verbose "Windows Authentication supplying credentials"
                    invoke-Command -ComputerName $S -Credential $Credential -ScriptBlock {
                    
                        # ----- Check execution Policy and override if -Force is include.
                        $Policy = Get-ExecutionPolicy 
                        if ( $Policy -ne 'Unrestricted' ) {
                            if ( $Using:Force ) {
                                    Write-Verbose "Overridding execution policy"
                                    Set-ExecutionPolicy Unrestricted
                                }
                                Else {
                                    Write-Error "Running scrips on remote computer ( $Using:S ) is disabled.  See about_Execution_Policies for mor information.  Or use the -Force switch to override"
                            }
                        }
                        
                        # ----- Check if the schedule already exist to prevent duplicates
                        if (  invoke-sqlcmd -ServerInstance $Using:S -Database msdb -Query "SELECT * FROM dbo.sysschedules" | where Name -eq $Name ) { Write-Error "A schedule named $Using:Name already exists on $Using:S"; Continue }
                             
                        Invoke-Sqlcmd -ServerInstance $Using:S -Database msdb -Query $Using:SP_Add_Schedule 
                    }
                }

                Default {
                    # ----- Check if the schedule already exist to prevent duplicates
                    if ( Get-SQLSchedule -SQLInstance $S -Name $Name ) { Write-Error "A schedule named $Name already exists on $S"; Continue }
        
                    Invoke-Sqlcmd -ServerInstance $S -Database msdb -Query $SP_Add_Schedule
                }
            }

            
        } 
    }
}

#----------------------------------------------------------------------------------

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

        [String]$Name,

        [PSCredential]$Credential,

        [Switch]$Force
    )

    Write-Verbose "Getting SQL job schedules on $SqlInstance"

    If ( $Credential ) {
            if ( $Credential.UserName -match '\\' ) {
                    # ----- Username has domain name so using windows auth
                    $Schedules = invoke-command -ComputerName $SQLInstance -Credential $Credential -ScriptBlock { 
                        
                        # ----- Check execution Policy and override if -Force is include.
                        $Policy = Get-ExecutionPolicy 
                        if ( $Policy -ne 'Unrestricted' ) {
                            if ( $Using:Force ) {
                                    Write-Verbose "Overridding execution policy"
                                    Set-ExecutionPolicy Unrestricted
                                }
                                Else {
                                    Write-Error "Running scrips on remote computer ( $Using:S ) is disabled.  See about_Execution_Policies for mor information.  Or use the -Force switch to override"
                            }
                        }

                        write-output ( invoke-sqlcmd -Database msdb -Query "SELECT * FROM dbo.sysschedules" )
                    }
                }
                else {
                    # ----- Username does not have domain name so SQL Auth
                    $Schedules = invoke-sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "SELECT * FROM dbo.sysschedules" -Username $Credential.UserName -Password $Credential.GetNetworkCredential().Password
            }
        }
        else {
            # ----- No credentials using logged on credentials
            $Schedules = invoke-sqlcmd -ServerInstance $SQLInstance -Database msdb -Query "SELECT * FROM dbo.sysschedules"
    }
    
    if ( $Name ) {
         $Schedules = $Schedules | where Name -eq $Name
     }

    
    
    Write-Output $Schedules
}

#----------------------------------------------------------------------------------
#----------------------------------------------------------------------------------
#----------------------------------------------------------------------------------
#----------------------------------------------------------------------------------