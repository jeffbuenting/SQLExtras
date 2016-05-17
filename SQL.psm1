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