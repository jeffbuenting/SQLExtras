﻿# ----- Get the module name
$ModulePath = 'F:\GitHub\SQLExtras'

$ModuleName = $ModulePath | Split-Path -Leaf

# ----- Remove and then import the module.  This is so any new changes are imported.
Get-Module -Name $ModuleName -All | Remove-Module -Force -Verbose

Import-Module "$ModulePath\$ModuleName.PSD1" -Force -ErrorAction Stop -Scope Global -Verbose

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "SQLExtras : Import-SSRSReport" {
    # ----- Get Function Help
    # ----- Pester to test Comment based help
    # ----- http://www.lazywinadmin.com/2016/05/using-pester-to-test-your-comment-based.html
    Context "Help" {

        $H = Help Import-SSRSReport -Full

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

            { Import-SSRSReport -SSRSServer SSRS -ReportFile Report } | Should Throw
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

                        [ref]$ImportWarnings
                    )

                } -Force

                $obj | Add-Member -memberType ScriptMethod  -Name "Dispose" -Value {
                } -Force

                Return $Obj
            }

            Import-SSRSReport -SSRSServer SSRS -ReportFile Report 3>&1 | Should BENullOrEmpty
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

                        [ref]$ImportWarnings
                    )

                    $ImportWarnings.value = "Warning" 
                } -Force

                $obj | Add-Member -memberType ScriptMethod  -Name "Dispose" -Value {
                } -Force

                Return $Obj
            }

            Import-SSRSReport -SSRSServer SSRS -ReportFile Report -Overwrite 3>&1 | Should Match ".*"
        }

        It "Should Ignore all Warnings" {

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

                        [ref]$ImportWarnings
                    )

                    $ImportWarnings.value = "Warning" 
                } -Force

                $obj | Add-Member -memberType ScriptMethod  -Name "Dispose" -Value {
                } -Force

                Return $Obj
            }

            Import-SSRSReport -SSRSServer SSRS -ReportFile Report -Overwrite -IgnoreWarnings 3>&1 | Should Match ".*"
        }
    }
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "SQLExtras : Backup-SSRSReport" {
    # ----- Get Function Help
    # ----- Pester to test Comment based help
    # ----- http://www.lazywinadmin.com/2016/05/using-pester-to-test-your-comment-based.html
    Context "Help" {

        $H = Help Backup-SSRSReport -Full

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

    Context "Execution" {
        
        It "Should throw an error if connecting to SQL Server Fails" {
            { Backup-SSRSReport -SSRSServer "SSRSServer" -Report $Report } | Should Throw
        } 
    }

    Context "Output" {

         Mock -CommandName New-WebServiceProxy -Verifiable -MockWith {
            $Obj = New-Object -TypeName PSObject
            
            $Obj | Add-Member -MemberType ScriptMethod -Name "GetItemDefinition" -Value { [byte]('0x' + 'FF') }

            $obj | Add-Member -memberType ScriptMethod  -Name "Dispose" -Value {
            } -Force

            Return $Obj
        }

        $Report = New-Object -TypeName PSObject -Property (@{            
            'Name' = "TestReport"
        })

        Backup-SSRSReport -SSRSServer "SSRSServer" -Report $Report -backupLocation $Testdrive   

        It "Should create a file with the backed up report" {
            "$TestDrive\$($Report.Name).rdl" | Should Exist
        }

    }
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "SQLExtras : Get-SSRSFolderSettings" {
    # ----- Get Function Help
    # ----- Pester to test Comment based help
    # ----- http://www.lazywinadmin.com/2016/05/using-pester-to-test-your-comment-based.html
    Context "Help" {

        $H = Help Get-SSRSFolderSettings -Full

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
 
    

    Context "Execution" {
        
        It "Should throw an error if connecting to SQL Server Fails" {
            { Get-SSRSFolderSettings -SSRSServer "SSRSServer" } | Should Throw
        } 

    }

    Context 'Output' {

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

                    [ref]$ImportWarnings
                )

            } -Force

            $obj | Add-Member -memberType ScriptMethod  -Name "Dispose" -Value {
            } -Force

            $Obj | Add-Member -MemberType ScriptMethod -Name GetPolicies -Value {
                $Pol = New-Object -TypeName PSObject -Property (@{
                    'GroupUserName' = 'testuser'
                    'Roles' = 'Browser','Publisher'
                })
            
                Write-Output $Pol
            } -Force

            $Obj | Add-Member -MemberType ScriptMethod -Name ListChildren -value {
                Write-Object 'Path'
            }

            Return $Obj
        }

        It "Should return a custom object" {
            Get-SSRSFolderSettings -SSRSServer Test | Should BeofType PSObject
        }

    }   
} 