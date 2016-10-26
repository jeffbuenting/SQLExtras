#---------------------------------------------------------------------------------
# Install
#---------------------------------------------------------------------------------

Function install-SQLServer {

<#
    .Synopsis
        Install SQL Server

    .Description
        Install and Configure SQL Server

    .Parameter ComputerName
        Name of the computer to install SQL

    .Parameter SQLISO
        Full path to the SQL ISO.

    .Parameter SQLAgent 
        Credential object that the SQL Agent service runs as.

    .Parameter SQLServer
        Credential object that the SQL Service Runs as.

    .Parameter ReportService
        Credential object that the Reprot Service runs as.

    .Parameter InstallSQLDataDir
        Path to install SQL

    .Parameter SAPWD
        SA Password

    .Parameter SysAdmin
        Users or Groups that should be given Sys Admin Rights to SQL

    .Parameter InstanceName
        SQL Named instance

    .Parameter InstanceID
        Instance ID.  Usually the same as the Instance Name.

    .Parameter SQLTempDir
        Path to where the DB files will be stored

    .Parameter SQLTempDBLogDir
        Path to where the DB Log files will be stored

    .Parameter SQLUserDir
        Path to where the DB files will be stored

    .Parameter SQLUserDBLogDir
        Path to where the DB Log files will be stored

    .Parameter Credential
        User name and password of an account with permissions required to install SQL  
        
    .Example
        Installs SQL on ServerA
        
        install-SQLServer -ComputerName ServerA `
            -SQLISO c:\iso\en_sql_server_2014_developer_edition_with_service_pack_1_x64_dvd_6668542.iso `
            -Features SQLEngine,FullText,RS,SSMS,ADV_SSMS `
            -SQLAgent $SQLSVCAccount `
            -SAPWD $SAWPD `
            -SQLService $SQLSVCAccount `
            -SysAdmin 'Contoso\ServerA-SQLAdmins' `
            -ReportService $SQLSVCAccount `
            -Credential $CRMAdmin   

    .Link
        Explaination of SQL Commandline switches

        https://msdn.microsoft.com/en-us/library/ms144259.aspx#Feature

    .Link
        Why CredSSP is required to install SQL remotely

        https://social.technet.microsoft.com/Forums/en-US/ea696b2f-39a0-44d0-9121-8a653c34e4a8/installing-sql-server-2012-remotely-via-powershell-using-invokecommand?forum=ITCG

    .Notes
        Author : Jeff Buetning
        Date : 2016 OCT 18

#>


    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True )]
        [String]$ComputerName,

        [Parameter( Mandatory = $True )]
        [ValidateScript( { (Get-item $_ | Select-Object -ExpandProperty Extension ) -eq '.iso' } ) ]
        [String]$SQLISO,

        [ValidateSet( 'SQLEngine','FullText','RS','SSMS','ADV_SSMS' )]
        [String[]]$Features,

        [String]$InstallSharedDir = "$Env:ProgramFiles\Microsoft SQL Server",

        [Parameter( Mandatory = $True )]
        [PSCredential]$SQLAgent,

        [Parameter( Mandatory = $True )]
        [PSCredential]$SQLService,

        [Parameter( Mandatory = $True )]
        [PSCredential]$ReportService,

        [String]$InstallSQLDataDir = "$Env:ProgramFiles\MicrosoftSQL Server",

        [PSCredential]$SAPWD,

        [Parameter( Mandatory = $True )]
        [String[]]$SysAdmin,

        [String]$InstanceName = 'MSSQLSERVER',

        [String]$InstanceID = $InstanceName,

        [String]$SQLTempDBDir = "$InstallSQLDataDir\$InstanceID\MSSQL\Data",

        [String]$SQLTempDBLogDir = "$InstallSQLDataDir\$InstanceID\MSSQL\Data",

        [String]$SQLUserDBDir = "$InstallSQLDataDir\$InstanceID\MSSQL\Data",

        [String]$SQLUserDBLogDir = "$InstallSQLDataDir\$InstanceID\MSSQL\Data",

        [PSCredential]$Credential
    )

    Process {

        if ( -Not (Test-Path -Path "\\$ComputerName\c$\Temp") ) { New-Item -Path "\\$ComputerName\c$\Temp" -ItemType Directory | write-Verbose }

        # ----- Check for SQL Prerequisites
        # ----- .NET 3.5
        if ( ( Get-WindowsFeature -ComputerName $ComputerName -Name NET-Framework-Features ).InstallState -ne 'Installed' ) {
            Install-WindowsFeature -ComputerName $ComputerName -Name NET-Framework-Features | write-Verbose
        }

        # ----- Get File info for SQL ISO.
        $SQLISOFile = Get-Item -Path $SQLISO

        # ----- Copy SQL Source to Server
        if ( -Not (Test-Path -Path "\\$ComputerName\c$\Temp\$($SQLISOFile.Name)") ) { 
                Try {
                        Write-Verbose "SQL ISO does not exist on $ComputerName.  Copying files"
                        Copy-Item -Path $SQLISO -Destination "\\$ComputerName\c$\Temp\" -Recurse -Force -ErrorAction Stop
                    }
                    Catch {
                        $EXceptionMessage = $_.Exception.Message
                        $ExceptionType = $_.exception.GetType().fullname
                        Throw "Install-SQLServer : Failed to copy SQL ISO to $ComputerName.`n`n     $ExceptionMessage`n`n     Exception : $ExceptionType" 
                }
            }
                else {
                Write-Verbose "SQL ISO already exists on remote computer"
        }

        # ----- CredSSP required to make the SQL changes.
        Write-Verbose "Configure $ComputerName for CredSSP"
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Enable-WSMANCredSSP -Role Server -Force | Out-Null
        }

        Write-Verbose "Installing SQL on $ComputerName"
        $SummaryLog = Invoke-Command -ComputerName $ComputerName -Authentication Credssp -Credential $Credential -Scriptblock {
            
            #----- Set verbose pref to what calling shell is set to
            $VerbosePreference=$Using:VerbosePreference
        
            Write-verbose "Mount the SQL ISO"
            $DriveLetter = (Mount-DiskImage -ImagePath "c:\temp\$($Using:SQLISOFile.Name)" -PassThru | Get-Volume ).DriveLetter
            Write-Verbose "     On drive $DriveLetter"

            # ----- Because I haven't figured out how to use the USING scope modifier with a PSCredential variable Password
            $SQLAGENTAcct = $Using:SQLAgent
            $SQLServiceAcct = $Using:SQLService
            $ReportServiceAcct = $Using:ReportService
            $SAWPDAcct = $Using:SAWPD

            # ----- Pulling the argument list out from the Start-Process cmdlet to allow different arguments added depending on parameters.
            $ArgumentList = "/ACTION=Install /IAcceptSQLServerLicenseTerms /ENU=True /QUIET=True /UpdateEnabled=True /ERRORREPORTING=False /USEMICROSOFTUPDATE=True /UpdateSource=MU /FEATURES=SQLEngine FullText RS SSMS ADV_SSMS /HELP=False /INDICATEPROGRESS=False /X86=False  /INSTANCENAME=MSSQLSERVER /SQMREPORTING=False /INSTANCEID=MSSQLSERVER /RSINSTALLMODE=DefaultNativeMode  /AGTSVCSTARTUPTYPE=Automatic /SQLSVCSTARTUPTYPE=Automatic /BROWSERSVCSTARTUPTYPE=Disabled /RSSVCSTARTUPTYPE=Automatic /FTSVCACCOUNT=NT Service\MSSQLFDLauncher /SQLCOLLATION=SQL_Latin1_General_CP1_CI_AS /SQLSYSADMINACCOUNTS=stratuslivedemo\jeff.buenting stratuslivedemo\administrator /TCPENABLED=1 /NPENABLED=1 "


            # ----- Add User name.  If no name is provided, SQL will use its defaults
            if ( $SQLServiceAcct.UserName ) { $ArgumentList += " /SQLSVCACCOUNT=$($SQLServiceAcct.UserName)" }
            if ( $SQLAgentAcct.UserName  ) { $ArgumentList += " /AGTSVCACCOUNT=$($SQLAgentAcct.UserName)" }
            if ( $SQLAgentAcct.UserName ) { $ArgumentList += " /RSSVCACCOUNT=$($ReportServiceAcct.UserName)" }

            # ----- Adds the password if one is passed.
            if ( $SQLServiceAcct.GetNetworkCredential().Password ) { $ArgumentList += " /SQLSVCPassword=$($SQLServiceAcct.GetNetworkCredential().Password)" }
            if ( $SQLAgentAcct.GetNetworkCredential().Password ) { $ArgumentList += " /AGTSVCPassword=$($SQLAgentAcct.GetNetworkCredential().Password)" }
            if ( $ReportServiceAcct.GetNetworkCredential().Password ) { $ArgumentList += " /RSSVCPASSWORD=$($ReportServiceAcct.GetNetworkCredential().Password)" }
            if ( $SAWPDAcct.GetNetworkCredential().Password ) { $ArgumentList += " /SECURITYMODE=SQL /SAPWD=$($SAWPDAcct.GetNetworkCredential().Password)" }

            Write-verbose "Beginning the Install"
            Write-Verbose "Install Arguments = $ArgumentList"
        
            start-Process -FilePath "$($DriveLetter):\Setup.exe" -ArgumentList $ArgumentList -wait -Credential $Using:Credential
          
            Dismount-DiskImage -ImagePath "c:\temp\$($Using:SQLISOFile.Name)" 

            # ----- Take a look at the SQL install Summary Log file.  
            # ----- Setting to silently continue.  I don't want to fail this cmdlet if it can't find the file.
            Write-Output ( Get-Content "C:\Program Files\Microsoft SQL Server\120\Setup Bootstrap\Log\Summary.txt" )
            
        }

        # ----- Turn off CredSSP
        Write-Verbose "Remove CredSSP Configure $ComputerName"
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
             Disable-WSMANCredSSP -Role Server | Out-Null
        }

        # ----- Take a look at the SQL install Summary Log file.  
        
        # ----- Regex to get the exitcode
        ($SummaryLog | Select-String -Pattern 'Exit error code:' ) -match '(\-?\d+)' | Out-Null
        $ExitCode = $Matches[1]
        $ExitCode

        # ----- Regex to get the Exit Message
        ($SummaryLog | Select-String -Pattern 'Exit message:' ) -match ':\s+(.+)' | Out-Null
        $ExitMessage = $Matches[1]
        $ExitMessage

        $Result = New-Object -TypeName psobject -Property @{
            'ExitCode' = $ExitCode
            'ExitMessage' = $ExitMessage
            'SummaryLog' = $SummaryLog
        }

        Write-Output $Result   
    }

    End {
        # ----- Clean up files
        remove-item \\$ComputerName\c$\Temp\$($SQLISOFile.Name)
    }
}

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

Function Get-SQLDatabase {

<#
    .Synopsis
        Gets Database information for DBs on a SQL Server

    .Descriptions
        Connects to SQL Server and returns all Databases

    .Parameter ServerInstance
        Server name or Servername/Instance of the SQL Server

    .Example
        Get-SQLDatabase -ServerInstance Jeffb-Sql03.stratuslivedemo.com

    .Note
        Author : Jeff Buenting
        Date : 23 SEP 2016
#>

    [CmdletBinding()]
    param (
        [Parameter ( Mandatory = $True, Position = 0 ) ]
        [String]$ServerInstance
    )

    Process {
        Write-Verbose "Making connection to SQL server: $ServerInstance"
        [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SqlServer.SMO") | out-null
        $SMOserver = New-Object ('Microsoft.SqlServer.Management.Smo.Server') -argumentlist $ServerInstance

        Write-verbose "Get Databases from $ServerInstance"
        $SMOServer.Databases | Foreach { Write-Output $_ }
    }
}

#----------------------------------------------------------------------------------

Function Remove-SQLDatabase {

    [CmdletBinding()]
    param (
        [Parameter ( Mandatory = $True, Position = 0 )]
        [String]$ServerInstance,

        [Parameter ( Mandatory = $True, Position = 1, ValueFromPipeLine = $True ) ]
        [Alias ( 'Name' ) ]
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

Function Refresh-SQLDatabase  {
    
<#
    .Synopsis
        Refreshesh an existing DB.

    .Description
        Deletes and Restores a DB on a SQL Server

    .Parameter ServerInstance
        Computername or Computername / Instance of SQL Server

    .Parameter BackupFile
        File object for the Database SQL Backup

    .Parameter Database
        Name of the Database to refresh

    .Example
        Refresh-SQLDatabase -ComputerName Jeffb-SQL03.Contoso.com -BackupFile \\Storage.Contoso.com\SQL_Backups\SQL02\r7_MSCRM\FULL\SQL02_R7_MSCRM_FULL_20160922_002214.bak

    .Note
        I created this as I got tired of doing this manually for our developers

    .Note
        ServerIntance currently assumes Computername.  Not COmputername/instance.  Need to fix this once I have a reason to.

    .Note
        Author : Jeff Buenting
        Date : 2016 Sep 23
#>

    [CmdletBinding()]
    Param (
        [Parameter ( Mandatory = $True, Position = 0 )]
        [String]$ServerInstance,

        [Parameter( Mandatory = $True, Position = 1, ValueFromPipeline = $True)]
        [System.IO.FileInfo]$BackupFile,

        [Parameter( Position = 2 ) ]
        [String]$Database

        
    )

    Begin {
        # ----- SQL module likes to switch to the SQL Server Provider.  This causes issues with file system cmdlets.  To work around this Save the current location and then if need be change back to it.
        $Location = Get-Location
    }

    Process {
        # ----- If no database name is supplied, then we will extract the DB name from our backupfile naming convention
        if ( -Not $Database ) {
            $BackupFile.name -match '[^_]*_(.*)(?=_FULL)|(?=_LOG)|(?=DIFF)' | Out-Null
            $Database = $Matches[1]
        }

        # ----- Delete the Existing DB
        Get-SQLDatabase -ServerInstance $ServerInstance | where Name -eq $Database | Remove-SQLDatabase -ServerInstance $ServerInstance

        if ( -Not (Test-Path -Path "\\$ServerInstance\c$\Temp") ) { New-Item -Path "\\$ServerInstance\c$\Temp" -ItemType Directory }

        # ----- Copy the backup file to the server.  Not doing this throws an access denied error when accessing the share.  CredSSP does not help.
        $BackupFile | Copy-Item -Destination \\$ServerInstance\c$\temp 

        Write-Verbose "Restoring $Database to $ServerInstance from $($BackupFile.FullName)"
        Restore-SqlDatabase -ServerInstance $ServerInstance -Database $Database -BackupFile c:\Temp\$($BackupFile.Name)
    }

    End {
        # ----- Clean up
        Remove-Item \\$ServerInstance\c$\Temp\$($BackupFile.Name) -Force
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
                $SQLJobs = Invoke-SQLCmd -ServerInstance $SQLInstance -Database msdb -Query "SELECT Job.*, Sched.name as Schedule_Name,Sched.schedule_id FROM dbo.sysjobs as Job LEFT Join dbo.sysjobschedules as JobSched on Job.job_id = JobSched.Job_id LEFT JOIN dbo.sysschedules as Sched on JobSched.schedule_id = Sched.schedule_id" -Username $Credential.UserName -Password $Credential.GetNetworkCredential().Password
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
                    Write-Output (Invoke-SQLCmd -ServerInstance $Using:SQLInstance -Database msdb -Query "SELECT Job.*, Sched.name as Schedule_Name,Sched.schedule_id FROM dbo.sysjobs as Job LEFT Join dbo.sysjobschedules as JobSched on Job.job_id = JobSched.Job_id LEFT JOIN dbo.sysschedules as Sched on JobSched.schedule_id = Sched.schedule_id")
                        
                }
            }

            Default {
                $SQLJobs = Invoke-SQLCmd -ServerInstance $SQLInstance -Database msdb -Query "SELECT Job.*, Sched.name as Schedule_Name,Sched.schedule_id FROM dbo.sysjobs as Job LEFT Join dbo.sysjobschedules as JobSched on Job.job_id = JobSched.Job_id LEFT JOIN dbo.sysschedules as Sched on JobSched.schedule_id = Sched.schedule_id"
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
             if ( ($Frequency -eq 'Weekly') -or ($Frequency -eq 'Monthly') -or ($Frequency -eq 'Monthly relative to Freq_interval') ) { 
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
                                    Write-Error "Running scrips on remote computer ( $Using:SQLInstance ) is disabled.  See about_Execution_Policies for mor information.  Or use the -Force switch to override"
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
# SSRS Report Cmdlets
#----------------------------------------------------------------------------------

Function Upload-SSRSReport {

<#
    .Synopsis
        Uploads an SSRS Report ( RDL File ) to SQL SSRS Server

    .Description
        Uploads a single or multiple SSRS Reports to the reporting server.  Will overwrite reports if they exist and overwrite has been selected.

    .Parameter SSRSServer
        The SSRS Server Name.

    .Parameter ReportFile
        File object representing the Report file.

    .Parameter SSRSReportPath
        SSRS Folder path where the report should be uploaded.

    .Parameter Credential
        User who has permissions to the SSRS Server

    .Parameter Overwrite
        When specified, an existing report will be overwritten.

    .Example
        Uploads the Budget Report

        Upload-SSRSReport -SSRSServer jeffb-sql01.stratuslivedemo.com -ReportFile (Get-Item c:\budget.rdl) -Credential (Get-Credential Contoso\Usera ) -Overwrite -Verbose

    .Link
        https://msdn.microsoft.com/en-us/library/reportservice2010.reportingservice2010.aspx
    
    .Link
        The majority of this script came from this website

        http://www.geoffhudik.com/tech/2011/10/13/uploading-ssrs-reports-with-powershell.html

    .Note
        Author : Jeff Buenting
        Date : 2016 AUG 15
#>

    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True )]
        [string]$SSRSServer,

        [Parameter( Mandatory = $True,ValueFromPipeline = $True )]
        [System.IO.FileInfo[]]$ReportFile,

        [String]$SSRSReportPath = "/",

        [PSCredential]$Credential,

        [Switch]$Overwrite
    )

    Begin {
        Write-Verbose "Connecting to $SSRSServer"
        $reportServerUri = "http://$SSRSServer/ReportServer/ReportService2010.asmx"
        Try {
                if ( $Credential ) {
                        $RS = New-WebServiceProxy -Uri $reportServerUri -Credential $Credential -ErrorAction Stop
                    }
                    else {
                        $RS = New-WebServiceProxy -Uri $reportServerUri -UseDefaultCredential -ErrorAction Stop
                }
            }
            Catch {
                $ErrorMessage = $_.Exception.message
                $ExceptionType = $_.Exception.GetType().FullName
                 
                Throw "Upload-SSRSReports : Error Connecting to SSRS $SSRSServer`n`n     $ErrorMessage`n`n     $ExceptionType"
        }

        $UploadWarnings = $Null
    }

    Process {
        Foreach ( $R in $ReportFile ) {
            Write-Verbose "Uploading $Report"

            [byte[]]$Definition = Get-Content $R -Encoding Byte

            $RS.CreateCatalogItem( 'Report',$R.BaseName,$SSRSReportPath,$Overwrite,$Definition,$Null, [ref]$UploadWarnings )

            if ( $UploadWarning ) {
                Foreach ( $W in $UploadWarnings ) {
                    Write-Warning "$($Warning.Message)"
                }
            }
        }
    }
    End {
        Write-Verbose "Cleaning up"
        $RS.Dispose()
    }
}

#----------------------------------------------------------------------------------

Function Get-SSRSReport {

<#
    .Synopsis
        Gets a list of SSRS Reports ( RDL File ) on the SQL SSRS Server

    .Description
        Retrieves information about the SSRS reports on the SSRS Server

    .Parameter SSRSServer
        The SSRS Server Name.
   
    .Example
        Returns all reports

        Get-SSRSReport -SSRSServer jeffb-sql01 -verbose

    .Link
        The majority of this script came from this website

        http://www.sqlmusings.com/2012/02/04/resolving-ssrs-and-powershell-new-webserviceproxy-namespace-issue/
        https://blogs.infosupport.com/managing-ssrs-reports-with-powershell/
        https://msdn.microsoft.com/en-us/library/reportservice2010.reportingservice2010.aspx
        http://www.geoffhudik.com/tech/2011/10/13/uploading-ssrs-reports-with-powershell.html
        https://blogs.infosupport.com/managing-ssrs-reports-with-powershell/
        http://larsenconfigmgr.blogspot.com/2015/01/powershell-script-bulk-import-ssrs.html

    .Note
        Author : Jeff Buenting
        Date : 2016 AUG 15
#>

    [CmdletBinding()]
    Param (
        [string]$SSRSServer,

        [PSCredential]$Credential
    )

    Begin {
        Write-Verbose "Connecting to $SSRSServer"
        $reportServerUri = "http://$SSRSServer/ReportServer/ReportService2010.asmx"
        Try {
                if ( $Credential ) {
                        $RS = New-WebServiceProxy -Uri $reportServerUri -Credential $Credential -ErrorAction Stop
                    }
                    else {
                        $RS = New-WebServiceProxy -Uri $reportServerUri -UseDefaultCredential -ErrorAction Stop
                }
            }
            Catch {
                $ErrorMessage = $_.Exception.message
                $ExceptionType = $_.Exception.GetType().FullName
                 
                Throw "Get-SSRSReports : Error Connecting to SSRS $SSRSServer`n`n     $ErrorMessage`n`n     $ExceptionType"
        }
        
    }

    Process {
        # Download all Reports from a specific folder to .rdl files in the current 
        # directory.
        
        
        Write-Output ($RS.ListChildren("/", $true) | Where TypeName -eq "Report")

    }

    End {
        Write-Verbose "Cleaning up"
        $RS.Dispose()
    }
}

#----------------------------------------------------------------------------------
# SQL Configuration Cmdlets
#----------------------------------------------------------------------------------

Function Get-SQLclientProtocol {

<#
    .Synopsis
        lists SQL Protocol status

    .Description
        Retrieves a list of connection protocols from a SQL Server

    .Parameter ComputerName
        SQL Server Name

    .Example
        Get-SQLProtocol -ComputerName 'jeffb-sql01.stratuslivedemo.com'

        DisplayName    : Named Pipes
        State          : Existing
        SQLServer      : 
        Properties     : {Name=DisplayName/Type=System.String/Writable=False/Value=Named Pipes, Name=IsEnabled/Type=System.Boolean/Writable=True/Value=True, Name=NetworkLibrary/Type=System.String/Writable=False/Value=SQLNCLI11, 
                         Name=Order/Type=System.Int32/Writable=True/Value=3}
        Name           : np
        Order          : 3
        IsnEnabled     : True
        PSComputerName : jeffb-sql01.stratuslivedemo.com
        RunspaceId     : bfa98fe4-b4e7-4e74-b2da-07f122c0a5b9

        DisplayName    : Shared Memory
        State          : Existing
        SQLServer      : 
        Properties     : {Name=DisplayName/Type=System.String/Writable=False/Value=Shared Memory, Name=IsEnabled/Type=System.Boolean/Writable=True/Value=True, Name=NetworkLibrary/Type=System.String/Writable=False/Value=SQLNCLI11, 
                         Name=Order/Type=System.Int32/Writable=True/Value=1}
        Name           : sm
        Order          : 1
        IsnEnabled     : True
        PSComputerName : jeffb-sql01.stratuslivedemo.com
        RunspaceId     : bfa98fe4-b4e7-4e74-b2da-07f122c0a5b9

        DisplayName    : TCP/IP
        State          : Existing
        SQLServer      : 
        Properties     : {Name=DisplayName/Type=System.String/Writable=False/Value=TCP/IP, Name=IsEnabled/Type=System.Boolean/Writable=True/Value=True, Name=NetworkLibrary/Type=System.String/Writable=False/Value=SQLNCLI11, 
                         Name=Order/Type=System.Int32/Writable=True/Value=2}
        Name           : tcp
        Order          : 2
        IsnEnabled     : True
        PSComputerName : jeffb-sql01.stratuslivedemo.com
        RunspaceId     : bfa98fe4-b4e7-4e74-b2da-07f122c0a5b9

    .Input
        None

    .Output
        Powershell Custom Object

    .Link
        https://msdn.microsoft.com/en-us/library/ms191294.aspx

    .Note
        Author : Jeff Buenting
        Date : 2016 SEP 09
#>

    [CmdletBinding()]
    Param (
        [String]$ComputerName = $ENV:ComputerName
    )
    
    $Protocol = Invoke-Command -ComputerName $ComputerName -ScriptBlock {    
        Import-Module SQLPS -Verbose:$False

        $WMI = New-Object ('Microsoft.SQLServer.Management.SMO.Wmi.ManagedComputer')
              
        Foreach ( $W in $WMI.ClientProtocols ) {
            Write-verbose "Protocol = $($W.Name)"
            $P = New-Object -TypeName psobject -Property @{
               SQLServer = $ComputerName
                DisplayName = $W.DisplayName
                IsnEnabled = $W.IsEnabled
                Order = $W.Order
                Properties = $W.Properties
                Name = $W.Name
                State = $W.State
            }
            Write-Output $P
        }
    }
    Write-Output $Protocol
}

#--------------------------------------------------------------------------------

Function Get-SQLNetworkProtocol {

<#
    .Synopsis
        lists SQL Protocol status

    .Description
        Retrieves a list of connection protocols from a SQL Server

    .Parameter ComputerName
        SQL Server Name

    .Parameter Protocol
        Name of the protocol to retrieve information about

    .Parameter Credential
        Username / Password that has permissions to the sql server.

    .Example
        Get-SQLNetworkProtocol -ComputerName 'jeffb-sql01.stratuslivedemo.com'

        PSComputerName      : jeffb-sql01.stratuslivedemo.com
        RunspaceId          : f3c6bb5a-7b1d-498d-802b-8fdf1535f789
        Parent              : Microsoft.SqlServer.Management.Smo.Wmi.ServerInstance
        DisplayName         : Named Pipes
        HasMultiIPAddresses : False
        IsEnabled           : True
        IPAddresses         : {}
        ProtocolProperties  : {Name=Enabled/Type=System.Boolean/Writable=True/Value=True, Name=PipeName/Type=System.String/Writable=True/Value=\\.\pipe\sql\query}
        Urn                 : ManagedComputer[@Name='JEFFB-SQL01']/ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='np']
        Name                : np
        Properties          : {Name=DisplayName/Type=System.String/Writable=False/Value=Named Pipes, Name=HasMultiIPAddresses/Type=System.Boolean/Writable=False/Value=False, Name=IsEnabled/Type=System.Boolean/Writable=True/Value=True}
        UserData            : 
        State               : Creating

        PSComputerName      : jeffb-sql01.stratuslivedemo.com
        RunspaceId          : f3c6bb5a-7b1d-498d-802b-8fdf1535f789
        Parent              : Microsoft.SqlServer.Management.Smo.Wmi.ServerInstance
        DisplayName         : Shared Memory
        HasMultiIPAddresses : False
        IsEnabled           : True
        IPAddresses         : {}
        ProtocolProperties  : {Name=Enabled/Type=System.Boolean/Writable=True/Value=True}
        Urn                 : ManagedComputer[@Name='JEFFB-SQL01']/ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='sm']
        Name                : sm
        Properties          : {Name=DisplayName/Type=System.String/Writable=False/Value=Shared Memory, Name=HasMultiIPAddresses/Type=System.Boolean/Writable=False/Value=False, Name=IsEnabled/Type=System.Boolean/Writable=True/Value=True}
        UserData            : 
        State               : Creating

        PSComputerName      : jeffb-sql01.stratuslivedemo.com
        RunspaceId          : f3c6bb5a-7b1d-498d-802b-8fdf1535f789
        Parent              : Microsoft.SqlServer.Management.Smo.Wmi.ServerInstance
        DisplayName         : TCP/IP
        HasMultiIPAddresses : True
        IsEnabled           : False
        IPAddresses         : {Microsoft.SqlServer.Management.Smo.Wmi.ServerIPAddress, Microsoft.SqlServer.Management.Smo.Wmi.ServerIPAddress, Microsoft.SqlServer.Management.Smo.Wmi.ServerIPAddress, 
                              Microsoft.SqlServer.Management.Smo.Wmi.ServerIPAddress...}
        ProtocolProperties  : {Name=Enabled/Type=System.Boolean/Writable=True/Value=False, Name=KeepAlive/Type=System.Int32/Writable=True/Value=30000, Name=ListenOnAllIPs/Type=System.Boolean/Writable=True/Value=True}
        Urn                 : ManagedComputer[@Name='JEFFB-SQL01']/ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='tcp']
        Name                : tcp
        Properties          : {Name=DisplayName/Type=System.String/Writable=False/Value=TCP/IP, Name=HasMultiIPAddresses/Type=System.Boolean/Writable=False/Value=True, Name=IsEnabled/Type=System.Boolean/Writable=True/Value=False}
        UserData            : 
        State               : Creating

    .Input
        None

    .Output
        Powershell Custom Object

    .Link
        https://msdn.microsoft.com/en-us/library/ms162567.aspx

    .Note
        Author : Jeff Buenting
        Date : 2016 SEP 09
#>

    [CmdletBinding()]
    Param (
        [String]$ComputerName = $ENV:ComputerName,

        [PSCredential]$Credential,

        [ValidateSet ( 'np','sm','tcp' )]
        [String[]]$Protocol = @('np','sm','tcp')
    )

    $ProtocolInfo = Invoke-Command -ComputerName $ComputerName -Credential $Credential -ScriptBlock { 
        
        #----- Set verbose pref to what calling shell is set to
        $VerbosePreference=$Using:VerbosePreference
        
        $Location = Get-Location
        Import-Module SQLPS -DisableNameChecking -Verbose:$False
        Set-Location $Location

        $WMI = New-Object ('Microsoft.SQLServer.Management.SMO.Wmi.ManagedComputer')
        
        Foreach ( $ProtocolName in $Using:Protocol ) {
            Write-Verbose "Getting Protocol $ProtocolName"
            $uri = "ManagedComputer[@Name='$Env:ComputerName']/ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='$ProtocolName']"  
            $P = $wmi.GetSmoObject($uri)    

            Write-Output $P
        }
    }
    Write-Output $ProtocolInfo
}

#----------------------------------------------------------------------------------

Function Set-SQLNetworkProtocol {

<#
    .Synopsis
        Changes SQL Network Protocol Settings

    .Description
        uses powershell to modify the SQL Network Protocols

    .Parameter Protocol
        Object containin information about the protocol.  Use Get-SQLNetworkProtocol to obtain object

    .Parameter Credential
        Username / Password that has permissions to the sql server.

    .Parameter Enable
        Specifies to enable or disable protocol

    .Example
        Get-SQLNetworkProtocol -ComputerName 'jeffb-sql01.stratuslivedemo.com' -Protocol tcp -Credential $Credential | Set-SQLNetworkProtocol -Enable $True -credential $Credential

        Sets the TCP/IP protocol to Enabled

    .Link
        https://msdn.microsoft.com/en-us/library/ms162567.aspx

    .Note
        Author : Jeff Buenting
        Date : 2016 SEP 13
        
    
#>

     [CmdletBinding()]
    Param (
        [Parameter ( Mandatory = $True, ValueFromPipeline = $True )]
        [PSObject]$Protocol,

        [PSCredential]$Credential,

        [Parameter ( Mandatory = $True )]
        [bool]$Enable
    )

    Process {
        Write-verbose "Setting Protocol $($Protocol.DisplayName) on $($Protocol.SQLServer)"
        Invoke-Command -ComputerName $Protocol.PSComputerName -ScriptBlock {
            $Location = Get-Location
            Import-Module SQLPS -DisableNameChecking -Verbose:$False
            Set-Location $Location

            #----- Set verbose pref to what calling shell is set to
            $VerbosePreference=$Using:VerbosePreference

            Try {
                    $ProtocolName = $Using:Protocol.Name
                    Write-Verbose "Protocol Name = $ProtocolName"

                    $WMI = New-Object ('Microsoft.SQLServer.Management.SMO.Wmi.ManagedComputer')

                    # ----- Since we may be doing this on a remote server this data will probably be deserialized so we need to re get the protocol object
                    $uri = "ManagedComputer[@Name='JEFFB-SQL01']/ ServerInstance[@Name='MSSQLSERVER']/ServerProtocol[@Name='$ProtocolName']"  
                    $P = $wmi.GetSmoObject($uri) 
                }
                Catch {
                    $EXceptionMessage = $_.Exception.Message
                    $ExceptionType = $_.exception.GetType().fullname
                    Throw "Set-SQLNetworkProtocol : Error GetSMOObject.`n`n     $ExceptionMessage`n`n     Exception : $ExceptionType" 
            }
             
            # ----- Enable/Disable  protocol
            $P.IsEnabled = $Using:Enable 

            # ----- Save new protocol config
            $P.Alter()  
        }      
    }
}

#----------------------------------------------------------------------------------
# DataBase Mail Cmdlets
#----------------------------------------------------------------------------------

Function Get-SQLDBMail {

<#
    .Synopsis
        Retrieves the SQL DB Mail Settings

    .Descriptions
        Retrieves the SQL Database Mail Settings

    .Parameter Computername
        SQL Server Name/Instance.  If the default instance is used then the computername only will suffice.

    .Parameter Credential
        By default, this cmdlet will connect to the SQL Server using the current logged in account.  Provide Credentials if you need to use a different account.

    .Example
        Get-SQLDBMail -Computername ServerA -Credential $cloudaccount

        Enabled             : True
        PSComputerName      : ServerA
        RunspaceId          : 
        Parent              : [Server]
        Profiles            : {[Mail]}
        Accounts            : {[SQLAlerts]}
        ConfigurationValues : {[AccountRetryAttempts], [AccountRetryDelay], [DatabaseMailExeMinimumLifeTime], [DefaultAttachmentEncoding]...}
        Urn                 : Server[@Name='ServerA']/Mail
        Properties          : {}
        UserData            : 
        State               : Existing

    .Link
        http://sqlmag.com/powershell/script-your-database-mail-setup

    .Note
        Author : Jeff Buenting
        Date : 2016 OCT 26
#>

    [CmdletBinding()]
    Param (
        [Parameter ( Position = 0,Mandatory = $True, ValueFromPipeline = $True ) ]
        [String[]]$ComputerName,

        [Parameter ( Position = 1 ) ]
        [PSCredential]$Credential
    )

    Process     {
        Foreach ( $C in $ComputerName ) {
            Write-Verbose "Getting Database Mail settings for $C"

            if ( $Credential ) { 
                    $Session = New-PSSession -ComputerName $C -Credential $Credential
                }
                Else {
                    $Session = New-PSSession -ComputerName $C
            }

            Invoke-Command -Session $Session -ScriptBlock {
                # ----- Establish Connection to SQL Server
                write-Verbose "Establishing connection to server"
                [system.reflection.assembly]::loadwithpartialname('Microsoft.sqlserver.smo') 

                $serverConnection = new-object Microsoft.SqlServer.Management.Common.ServerConnection
                $serverConnection.ServerInstance=$C
           
                $server = new-object Microsoft.SqlServer.Management.SMO.Server($Using:C)

                $MailSettings = $Server.Mail

                $MailSettings | Add-Member -MemberType NoteProperty -Name 'Enabled' -value ([Bool]( $Server.Configuration.DatabaseMailEnabled.ConfigValue ))

                Write-Output $MailSettings
            }
        }
    }
}

#----------------------------------------------------------------------------------

Function Get-SQLDBMailAccount {

<#
    .Synopsis
        Retrieves a SQL DB Mail Account

    .Description
        Retrieves a SQL DB Mail Account

    .ParameterComputername
        SQL Server Name/Instance.  If the default instance is used then the computername only will suffice.

    .Parameter Credential
        By default, this cmdlet will connect to the SQL Server using the current logged in account.  Provide Credentials if you need to use a different account.

    .parameter DBMail
        SQL DB Mail Object.  Use Get-SQLDBMail to obtain this object.

    .Parameter AccountName
        Name of a SQL DB Mail Account

    .Link
        https://technet.microsoft.com/en-us/library/ms188668(v=sql.105).aspx

    .Note
        Author : Jeff Buenting
        Date : 2016 OCT 26
#>

    [CmdletBinding()]
    Param (
        [Parameter ( Position = 0,Mandatory = $True ) ]
        [String[]]$ComputerName,

        [Parameter ( Position = 1 ) ]
        [PSCredential]$Credential,

        [Parameter ( ParameterSetName = 'DBMailObject', Position = 2 ) ]
        [psobject]$DBMail,

        [Parameter ( ParameterSetName = 'AccountName', Position = 2 ) ]
        [String[]]$AccountName
    )

    Process {
        Switch ( $PSCmdlet.ParameterSetName ) {
            'DBMailObject' {
                Write-verbose "ParameterSetName DBMailObject"
                # ----- Extract the Account Names from the DB Mail Object
                $AccountName = $DBMail.Accounts
            }

            'AccountName' {
                Write-verbose "ParameterSetName AccountName"
                # ----- Already have the account Names
            }
        }

        Write-verbose "Account Names = $($AccountName | out-string)"
        Write-Verbose "Count = $($AccountName | Measure-object | out-string ) "

        if ( $Credential ) { 
                $Session = New-PSSession -ComputerName $ComputerName -Credential $Credential
            }
            Else {
                $Session = New-PSSession -ComputerName $ComputerName
        }

        Invoke-Command -Session $Session -ScriptBlock {
             $VerbosePreference=$Using:VerbosePreference

             # ----- Reget the DB Mail object as the one we passed in was deserialized.
            [system.reflection.assembly]::loadwithpartialname('Microsoft.sqlserver.smo') 

            $serverConnection = new-object Microsoft.SqlServer.Management.Common.ServerConnection
            $serverConnection.ServerInstance=$using:ComputerName
           
            $server = new-object Microsoft.SqlServer.Management.SMO.Server($Using:ComputerName)

            Foreach ( $A in $Using:AccountName ) {
                if ( $A -eq '' ) { Continue }
                Write-Verbose "Getting Account Name : $A"
                               
                Invoke-Sqlcmd -ServerInstance $ComputerName -Database MSDB -Query "SELECT * FROM [dbo].[sysmail_account] where name = '$A'"
             
            }
        }
            
        Remove-PSSession $Session
    }

}

#----------------------------------------------------------------------------------
#----------------------------------------------------------------------------------
#----------------------------------------------------------------------------------
#----------------------------------------------------------------------------------