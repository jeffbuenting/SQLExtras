Function Install-SQL {

<#
    .Link
       https://msdn.microsoft.com/en-us/library/ms144259.aspx
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeLine=$True)]  
        [String[]]$ComputerName,

        [String]$SrcPath

    )

    Process {
        foreach ( $C in $ComputerName ) {
            Write-Verbose "Installing SQL on $C" 



        }
    }

}

Install-SQL -ComputerName "JeffB-SQL02" -Verbose