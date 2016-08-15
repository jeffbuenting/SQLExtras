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
        [string]$SSRSServer
    )

    Begin {
        Write-Verbose "Connecting to $SSRSServer"
        $reportServerUri = "http://$SSRSServer/reportserver/ReportService2010.asmx?wsdl"
        $RS = New-WebServiceProxy -Uri $reportServerUri -UseDefaultCredential
        
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

Get-SSRSReport -SSRSServer jeffb-sql01.stratuslivedemo.com -verbose