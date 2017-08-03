# ----- Get the module name
$ModulePath = 'F:\GitHub\SQLExtras'

$ModuleName = $ModulePath | Split-Path -Leaf

# ----- Remove and then import the module.  This is so any new changes are imported.
Get-Module -Name $ModuleName -All | Remove-Module -Force -Verbose

Import-Module "$ModulePath\$ModuleName.PSD1" -Force -ErrorAction Stop -Scope Global -Verbose

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "SQLExtras : Upload-SSRSReport" {
    # ----- Get Function Help
    # ----- Pester to test Comment based help
    # ----- http://www.lazywinadmin.com/2016/05/using-pester-to-test-your-comment-based.html
    Context "Help" {

        $H = Help Upload-SSRSReport -Full

        # ----- Help Tests
        It "has Synopsis Help Section" {
            $H.Synopsis | Should Not BeNullorEmpty
        }

        It "has Description Help Section" {
            $H.Description | Should Not BeNullorEmpty
        }

        It "has Parameters Help Section" {
            $H.Parameters | Should Not BeNullorEmpty
        }

        # Examples
        it "Example - Count should be greater than 0"{
            $H.examples.example.code.count | Should BeGreaterthan 0
        }
            
        # Examples - Remarks (small description that comes with the example)
        foreach ($Example in $H.examples.example)
        {
            it "Example - Remarks on $($Example.Title)"{
                $Example.remarks | Should not BeNullOrEmpty
            }
        }

        It "has Notes Help Section" {
            $H.alertSet | Should Not BeNullorEmpty
        }
    } 

    Mock -CommandName Get-Content -MockWith {
    }

    Context "Execution" {
        It "Should throw an error if the connection to the SSRS server fails" {
            Mock -CommandName New-WebServiceProxy -MockWith {
                Return "NoServer"
            }

            { Upload-SSRSReport -SSRSServer SSRS -ReportFile Report } | Should Throw
        }

        It "Should show no warnings if no warnings exist" {

            Mock -CommandName New-WebServiceProxy -Verifiable -MockWith {
                $Obj = New-Object -TypeName PSObject
                $obj | Add-Member -memberType ScriptMethod  -Name "CreateCatalogItem" -Value {
                    Param (
                        [String]$Type = 'Report',

                        [String]$Name = 'Test',

                        [String]$SSRSReportPath,

                        [String]$Overwrite,

                        [String]$Definition,

                        [String]$Nope = $Null,

                        [ref]$UploadWarnings
                    )

                } -Force

                $obj | Add-Member -memberType ScriptMethod  -Name "Dispose" -Value {
                } -Force

                Return $Obj
            }

            Upload-SSRSReport -SSRSServer SSRS -ReportFile Report 3>&1 | Should BENullOrEmpty
        }
        
        It "Displays a Warning if one exists" {

             Mock -CommandName New-WebServiceProxy -Verifiable -MockWith {
                $Obj = New-Object -TypeName PSObject
                $obj | Add-Member -memberType ScriptMethod  -Name "CreateCatalogItem" -Value {
                    Param (
                        [String]$Type = 'Report',

                        [String]$Name = 'Test',

                        [String]$SSRSReportPath,

                        [String]$Overwrite,

                        [String]$Definition,

                        [String]$Nope = $Null,

                        [ref]$UploadWarnings
                    )

                    $UploadWarnings.value = "Warning" 
                } -Force

                $obj | Add-Member -memberType ScriptMethod  -Name "Dispose" -Value {
                } -Force

                Return $Obj
            }

            Upload-SSRSReport -SSRSServer SSRS -ReportFile Report -Overwrite 3>&1 | Should Match ".*"
        }
    }
}
