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

    .Link
        Explaination of SQL Commandline switches

        https://msdn.microsoft.com/en-us/library/ms144259.aspx#Feature

    .Link
        Why CredSSP is required to install SQL remotely

        https://social.technet.microsoft.com/Forums/en-US/ea696b2f-39a0-44d0-9121-8a653c34e4a8/installing-sql-server-2012-remotely-via-powershell-using-invokecommand?forum=ITCG

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
        Invoke-Command -ComputerName $ComputerName -Authentication Credssp -Credential $Credential -Scriptblock {
            
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
            #$ArgumentList = "/ACTION=Install /IAcceptSQLServerLicenseTerms /ENU=True /QUIET=True /UpdateEnabled=True /ERRORREPORTING=False /USEMICROSOFTUPDATE=True /UpdateSource=MU /FEATURES=$Using:Features /HELP=False /INDICATEPROGRESS=False /X86=False /INSTALLSHAREDDIR=$Using:InstallSharedDir /INSTALLSHAREDWOWDIR='C:\Program Files (x86)\Microsoft SQL Server' /INSTANCENAME=$Using:InstanceName /SQMREPORTING=False /INSTANCEID=$Using:InstanceID /RSINSTALLMODE=DefaultNativeMode /INSTANCEDIR=$Using:InstallSQLDataDir /AGTSVCSTARTUPTYPE=Automatic /SQLSVCSTARTUPTYPE=Automatic /BROWSERSVCSTARTUPTYPE=Disabled /RSSVCSTARTUPTYPE=Automatic /FTSVCACCOUNT=NT Service\MSSQLFDLauncher /SQLCOLLATION=SQL_Latin1_General_CP1_CI_AS /SQLSYSADMINACCOUNTS=$Using:SysAdmin /TCPENABLED=1 /NPENABLED=1"
            $ArgumentList = "/ACTION=Install /IAcceptSQLServerLicenseTerms /ENU=True /QUIET=True /UpdateEnabled=True /ERRORREPORTING=False /USEMICROSOFTUPDATE=True /UpdateSource=MU /FEATURES=SQLEngine FullText RS SSMS ADV_SSMS /HELP=False /INDICATEPROGRESS=False /X86=False  /INSTANCENAME=MSSQLSERVER /SQMREPORTING=False /INSTANCEID=MSSQLSERVER /RSINSTALLMODE=DefaultNativeMode  /AGTSVCSTARTUPTYPE=Automatic /SQLSVCSTARTUPTYPE=Automatic /BROWSERSVCSTARTUPTYPE=Disabled /RSSVCSTARTUPTYPE=Automatic /FTSVCACCOUNT=NT Service\MSSQLFDLauncher /SQLCOLLATION=SQL_Latin1_General_CP1_CI_AS /SQLSYSADMINACCOUNTS=stratuslivedemo\jeff.buenting stratuslivedemo\administrator /TCPENABLED=1 /NPENABLED=1 "


            # ----- Known accounts Local System, Network Service, etc, when passed as PSCredential only have the user name not the 'domain'.  This section adds the domain if necessary
 #           if ( $SQLServiceAcct.UserName -eq 'Network Service' ) {
 #                   $ArgumentList += " /SQLSVCACCOUNT='NT AUTHORITY\NETWORK SERVICE'"
 #               }
 #               else {
 #                   $ArgumentList += " /SQLSVCACCOUNT=$($SQLServiceAcct.UserName)"
 #           }
 #           if ( $SQLAgentAcct.UserName -eq 'Network Service' ) {
 #                   $ArgumentList += " /AGTSVCACCOUNT='NT AUTHORITY\NETWORK SERVICE'"
 #               }
 #               else {
  #                  $ArgumentList += " /AGTSVCACCOUNT=$($SQLAgentAcct.UserName)"
 #           }
 #           if ( $SQLAgentAcct.UserName -eq 'Network Service' ) {
 #                   $ArgumentList += " /RSSVCACCOUNT='NT AUTHORITY\NETWORK SERVICE'"
 #               }
 #               else {
 #                   $ArgumentList += " /RSSVCACCOUNT=$($ReportServiceAcct.UserName)"
 #           }

            # ----- Adds the password if one is passed.
            if ( $SQLServiceAcct.GetNetworkCredential().Password ) { $ArgumentList += " /SQLSVCPassword=$($SQLServiceAcct.GetNetworkCredential().Password)" }
            if ( $SQLAgentAcct.GetNetworkCredential().Password ) { $ArgumentList += " /AGTSVCPassword = $($SQLAgentAcct.GetNetworkCredential().Password)" }
            if ( $ReportServiceAcct.GetNetworkCredential().Password ) { $ArgumentList += " /RSSVCPASSWORD=$($ReportServiceAcct.GetNetworkCredential().Password)" }
            if ( $SAWPDAcct.GetNetworkCredential().Password ) { $ArgumentList += " /SECURITYMODE=SQL /SAPWD=$($SAWPDAcct.GetNetworkCredential().Password)" }

            Write-verbose "Beginning the Install"
            Write-Verbose "Install Arguments = $ArgumentList"
        #    start-Process -FilePath "E:\Setup.exe"  -ArgumentList "/ACTION=Install /Q /UpdateEnabled=True /FEATURES=$Using:Features /InstallShareDDir=$Using:InstallSharedDir /SQMREPORTING=0 /AGTSVCACCOUNT=$SQLAGENTacct.Username /AGTSVCPASSWORD=$SQLAgentAcct.GetNetworkCredential().Password /AGTSVCSTARTUPType=Automatic /InstallSQLDATADIR=$Using:INSTALLSQLDATADIR /SAPWD=$Using:SAPWD /SECURITYMODE=SQL /SQLSVCACCOUNT=$SQLServiceAcct.Username /SQLSVCPASSWORD=$SQLServiceAcct.GetNetworkCredential().Password /SQLSVCSTARTUPTYPE=Automatic /SQLSYSADMINACCOUNTS=$Using:SYSAdmin /SQLTEMPDBDIR=$Using:SQLTempDBDir /SQLTEMPDBLOGDIR=$Using:SQLTempDBLogDir /SQLUSERDBDIR=$Using:SQLUserDBDir /SQLUSERDBLOGDIR=$Using:SQLUserDBLogDir /NPEnabled=1 /RSSVCACCOUNT=$ReportServiceAcct.Username /RSSVCPASSWORD=$ReportServiceAcct.GetNetworkCredential().Password /RSSVCSTARTUPTYPE=Automatic /IAcceptSQLServerLicenseTerms" -wait -Credential $Using:Credential
            #start-Process -FilePath "e:\Setup.exe"  -ArgumentList '/ACTION=Install /IAcceptSQLServerLicenseTerms /ENU=True /QUIET=True /UpdateEnabled=True /ERRORREPORTING=False /USEMICROSOFTUPDATE=True /UpdateSource=MU /FEATURES=SQLENGINE,FULLTEXT,RS,SSMS,ADV_SSMS /HELP=False /INDICATEPROGRESS=False /X86=False /INSTALLSHAREDDIR="C:\Program Files\Microsoft SQL Server" /INSTALLSHAREDWOWDIR="C:\Program Files (x86)\Microsoft SQL Server" /INSTANCENAME=MSSQLSERVER /SQMREPORTING=False /INSTANCEID=MSSQLSERVER /RSINSTALLMODE=DefaultNativeMode /INSTANCEDIR="C:\Program Files\Microsoft SQL Server" /AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE" /AGTSVCSTARTUPTYPE=Automatic /SQLSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE" /SQLSVCSTARTUPTYPE=Automatic /BROWSERSVCSTARTUPTYPE=Disabled /RSSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE" /RSSVCSTARTUPTYPE=Automatic /FTSVCACCOUNT=NT Service\MSSQLFDLauncher /SQLCOLLATION=SQL_Latin1_General_CP1_CI_AS /SQLSYSADMINACCOUNTS=STRATUSLIVEDEMO\Jeff.Buenting /SECURITYMODE=SQL /SAPWD=Password1 /TCPENABLED=0 /NPENABLED=1' -wait -Credential $Using:Credential
            
           
           # start-Process -FilePath "$($DriveLetter):\Setup.exe"  -ArgumentList "/ACTION=Install /IAcceptSQLServerLicenseTerms /ENU=True /QUIET=True /UpdateEnabled=True /ERRORREPORTING=False /USEMICROSOFTUPDATE=True /UpdateSource=MU /FEATURES=$Using:Features /HELP=False /INDICATEPROGRESS=False /X86=False /INSTALLSHAREDDIR=$Using:InstallSharedDir /INSTALLSHAREDWOWDIR='C:\Program Files (x86)\Microsoft SQL Server' /INSTANCENAME=$Using:InstanceName /SQMREPORTING=False /INSTANCEID=$Using:InstanceID /RSINSTALLMODE=DefaultNativeMode /INSTANCEDIR=$Using:InstallSQLDataDir /AGTSVCACCOUNT=$($SQLAgentAcct.UserName) /AGTSVCPassword = $($SQLAgentAcct.GetNetworkCredential().Password) /AGTSVCSTARTUPTYPE=Automatic /SQLSVCACCOUNT=$($SQLServiceAcct.UserName) /SQLSVCPassword=$($SQLServiceAcct.GetNetworkCredential().Password) /SQLSVCSTARTUPTYPE=Automatic /BROWSERSVCSTARTUPTYPE=Disabled /RSSVCACCOUNT=$($ReportServiceAcct.UserName) /RSSVCPASSWORD=$($ReportServiceAcct.GetNetworkCredential().Password) /RSSVCSTARTUPTYPE=Automatic /FTSVCACCOUNT=NT Service\MSSQLFDLauncher /SQLCOLLATION=SQL_Latin1_General_CP1_CI_AS /SQLSYSADMINACCOUNTS=$Using:SysAdmin /SECURITYMODE=SQL /SAPWD=$($SAPWDAcct.GetNetworkCredential().Password) /TCPENABLED=0 /NPENABLED=1" -wait -Credential $Using:Credential
            start-Process -FilePath "$($DriveLetter):\Setup.exe" -ArgumentList $ArgumentList -wait -Credential $Using:Credential
          
            Dismount-DiskImage -ImagePath "c:\temp\$($Using:SQLISOFile.Name)" 
            
        }

        # ----- Take a look at the SQL install Summary Log file.  
 #       $SummaryLog =  Get-Content "\\$ComputerName\C$\Program Files\Microsoft SQL Server\120\Setup Bootstrap\Log"

 #       Write-Verbose $SummaryLog

        # ----- Turn off CredSSP
        Write-Verbose "Remove CredSSP Configure $ComputerName"
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
             Disable-WSMANCredSSP -Role Server | Out-Null
        }
    }

    End {
        # ----- Clean up files
     #   remove-item \\$ComputerName\c$\Temp\$($SQLISOFile.Name)
    }
}

$NetSVC = Get-Credential 'Network Service'

$secpasswd = ConvertTo-SecureString '1$tellar$ervice' -AsPlainText -Force
$CRMAdmin = New-Object System.Management.Automation.PSCredential (“stratuslivedemo\administrator”, $secpasswd)

$secpasswd = ConvertTo-SecureString 'Password1' -AsPlainText -Force
$SAWPD = New-Object System.Management.Automation.PSCredential (“SA”, $secpasswd)


install-SQLServer -ComputerName JB-SQL01.stratuslivedemo.com `
    -SQLISO \\vaslnas.stratuslivedemo.com\StratusLive\Software\en_sql_server_2014_developer_edition_with_service_pack_1_x64_dvd_6668542.iso `
    -Features SQLEngine,FullText,RS,SSMS,ADV_SSMS `
    -SQLAgent $NetSVC `
    -SAPWD $SAWPD `
    -SQLService $NetSVC `
    -SysAdmin 'stratuslivedemo\jeff.buenting','stratuslivedemo\administrator' `
    -ReportService $NetSVC `
    -Credential $CRMAdmin `
    -verbose
