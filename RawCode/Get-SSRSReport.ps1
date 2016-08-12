Function Get-SSRSReport {

<#
    .Synopsis
        Gets a list of SSRS Reports ( RDL File ) on the SQL SSRS Server

    .Link
        The majority of this script came from this website

        http://www.geoffhudik.com/tech/2011/10/13/uploading-ssrs-reports-with-powershell.html
        https://blogs.infosupport.com/managing-ssrs-reports-with-powershell/
#>

    [CmdletBinding()]
    Param (
        [string]$SSRSServer,

        [String]$Report
    )

    Begin {
        Write-Verbose "Connecting to $SSRSServer"
        $reportServerUri = "http://$SSRSServer/reportserver/ReportService2010.asmx?wsdl"
        $RS = New-WebServiceProxy -Uri $reportServerUri -Namespace SSRS -UseDefaultCredential
        #$RS | GM

        # ----- Create property for the FindItems method
        $Property = New-Object ReportService2010.Property
        $Property.Name = 'Recurse'
        $Property.Value = $True
    }

    Process {
        # Download all Reports from a specific folder to .rdl files in the current 
        # directory.
        
        #$items = $RS.ListChildren($sourceFolderPath, $false)
        $Reports = $RS.FindItems( "/","AND",$Propery,"")
        Write-Output $Reports
        
        #Write-Output ($items | Where-Object { $_.TypeName -eq "Report" } )
        
        #| Foreach-Object {
        #    $filename = ("{0}.rdl" -f $_.Name)

        #    Write-Output ("Downloading ""{0}""..." -f $_.Path)
        #    $bytes = $RS.GetItemDefinition($_.Path)
        #    [System.IO.File]::WriteAllBytes("$pwd\$filename", $bytes)
        #}
    }
}

Get-SSRSReport -SSRSServer jeffb-sql01.stratuslivedemo.com -verbose