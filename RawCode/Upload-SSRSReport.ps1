Function Upload-SSRSReport {

<#
    .Synopsis
        Uploads an SSRS Report ( RDL File ) to SQL SSRS Server

    .Link
        The majority of this script came from this website

        http://www.geoffhudik.com/tech/2011/10/13/uploading-ssrs-reports-with-powershell.html
#>

    [CmdletBinding()]
    Param (
        [string]$SSRSServer,

        [String]$Report
    )

    Begin {
        Write-Output "Connecting to $SSRSServer"
        $reportServerUri = "http://$SSRSServer/ReportServer/ReportService2005.asmx"
        $proxy = New-WebServiceProxy -Uri $reportServerUri -Namespace SSRS.ReportingService2005 -UseDefaultCredential
    }

    Process {
        Foreach ( $R in $Report ) {
            
        }
    }
}