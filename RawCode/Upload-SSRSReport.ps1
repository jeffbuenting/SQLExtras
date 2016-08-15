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
        The majority of this script came from this website

        http://www.geoffhudik.com/tech/2011/10/13/uploading-ssrs-reports-with-powershell.html
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

            $RS.CreateCatalogItem( 'Report',$R.Name,$SSRSReportPath,$Overwrite,$Definition,$Null, [ref]$UploadWarnings )

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

Upload-SSRSReport -SSRSServer jeffb-sql01.stratuslivedemo.com -ReportFile C:\temp\CostCenterReport.rdl -Credential (Get-Credential stratuslivedemo\administrator ) -Overwrite -Verbose