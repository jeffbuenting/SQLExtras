Function install-SQLServer {

<#
    .Synopsis
        Install SQL Server

    .Description
        Install and Configure SQL Server

    .Parameter ComputerName
        Name of the computer to install SQL

    .Parameter SQLISO
        Full path to the SQL ISO
#>


    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True )]
        [String]$ComputerName,

        [Parameter( Mandatory = $True )]
        [ValidateScript( { (Get-item $_ | Select-Object -ExpandProperty Extension ) -eq '.iso' } ) ]
        [String]$SQLISO
    )

    Process {

        if ( -Not (Test-Path -Path "\\$ComputerName\c$\Temp") ) { New-Item -Path "\\$ComputerName\c$\Temp" -ItemType Directory }

        # ----- Check for SQL Prerequisites
        # ----- .NET 3.5
        if ( ( Get-WindowsFeature -ComputerName $ComputerName -Name WAS-NET-Environment ).InstallState -ne 'Available' ) {
            Install-WindowsFeature -ComputerName $ComputerName -Name WAS-NET-Environment
        }

        # ----- Copy SQL Source to Server
        if ( -Not (Test-Path -Path "\\$ComputerName\c$\Temp\$SQLISO") ) { 
            Try {
                    Write-Verbose "Install-CRM2016 : CRM 2016 Install ISO does not exist on $ComputerName.  Copying files"
                    Move-Item -Path $SQLISO -Destination "\\$ComputerName\c$\Temp\$SQLISO" -Recurse -Force -ErrorAction Stop
                }
                Catch {
                    $EXceptionMessage = $_.Exception.Message
                    $ExceptionType = $_.exception.GetType().fullname
                    Throw "Install-CRM2016 : Failed to copy CRM 2016 ISO to CRM Server.`n`n     $ExceptionMessage`n`n     Exception : $ExceptionType" 
            }
        }
        else {
        Write-Verbose "SQL ISO already exists on remote computer"
    }

        Write-Verbose "Installing SQL on $ComputerName"
        Invoke-Command -Session $ComputerName -ArgumentList $SQLISO -Scriptblock {
            
            #----- Set verbose pref to what calling shell is set to
            $VerbosePreference=$Using:VerbosePreference
        
            Write-verbose "Mount the SQL ISO"
            $DriveLetter = (Mount-DiskImage -ImagePath "c:\temp\$Using:SQLISO" -PassThru | Get-Volume ).DriveLetter
            Write-Verbose "     On drive $DriveLetter"

            Write-verbose "Beginning the Install"
          #  start-Process -FilePath "E:\Server\amd64\SetupServer.exe" -ArgumentList "/Q /Config c:\temp\Server.xml /L c:\temp\CRMInstall.Log" -Credential $Using:CRMAdmin -wait 
    
            Dismount-DiskImage -ImagePath "c:\temp\$SQLISO"     
        }
    }

    End {
        # ----- Clean up files
        remove-item \\$ComputerName\c$\Temp\$SQLISO
    }
}

install-SQLServer -ComputerName JB-SQL01.stratuslivedemo.com -SQLISO \\vaslnas.stratuslivedemo.com\StratusLive\Software\en_sql_server_2014_developer_edition_with_service_pack_1_x64_dvd_6668542.iso -verbose
