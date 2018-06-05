# ----- Get the module name
$ModulePath = $PSScriptRoot

$ModuleName = $ModulePath | Split-Path -Leaf

# ----- Remove and then import the module.  This is so any new changes are imported.
Get-Module -Name $ModuleName -All | Remove-Module -Force -Verbose

Import-Module "$ModulePath\$ModuleName.PSD1" -Force -ErrorAction Stop -Scope Global -Verbose

#-------------------------------------------------------------------------------------
# ----- Check if all fucntions in the module have a unit tests

Describe "$ModuleName : Module Tests" {

    $Module = Get-module -Name $ModuleName

    $testFile = Get-ChildItem $module.ModuleBase -Filter '*.Tests.ps1' -File
    
    $testNames = Select-String -Path $testFile.FullName -Pattern 'describe\s[^\$](.+)?\s+{' | ForEach-Object {
        [System.Management.Automation.PSParser]::Tokenize($_.Matches.Groups[1].Value, [ref]$null).Content
    }

    $moduleCommandNames = (Get-Command -Module $ModuleName | where CommandType -ne Alias)

    it 'should have a test for each function' {
        Compare-Object $moduleCommandNames $testNames | where { $_.SideIndicator -eq '<=' } | select inputobject | should beNullOrEmpty
    }
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Install-SQLServer" {
    # ----- Not convinced I even need this function.
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SQLMemberRole" {
    
    Mock -CommandName New-Object -ParameterFilter { $TypeName -eq "Microsoft.SqlServer.Management.Common.ServerConnection" } -MockWith {
        $Obj = New-Object -TypeName psobject -Property (@{
            'ServerInstance' = 'localhost'
        })

        Return $Obj
    }

    Mock -CommandName New-Object -ParameterFilter { $TypeName -eq "Microsoft.SqlServer.Management.SMO.Server" } -MockWith {
        $D = @()

        $U1 = New-Object -TypeName psobject (@{
            'Name' = "User1"
            'Login' = "Domain\User1"
        }) 
        $U1 | Add-Member -MemberType NoteProperty -Name EnumRoles -Value @('db_owner','RSExecRole')

        $U2 = New-Object -TypeName psobject (@{
            'Name' = "User2"
            'Login' = "Domain\User2"
        }) 

        $U2 | Add-Member -MemberType NoteProperty -Name EnumRoles -Value @('db_owner')
        
        For ( $I = 1; $I -le 4; $I++ ) {   
            $D += New-Object -TypeName psobject (@{
                'Name' = "DB$I"
                'Users' = $U1
            })           
        }

        

        ($D | where $Name -eq "DB1" ).$Users += $U2
        
        $Obj = New-Object -TypeName psobject -Property (@{
            'Databases' = $D
        })
           
        Return $Obj
    }

    Context Output {

  #      $Users = Get-SQLMemberRole -Verbose

        It "should return an custom object" {
            $Users | should beofType PSObject 
        } -Pending

        It "SHould return all (5) objects when a membername is not included" {
            $Users | Measure-Object | Select-Object -ExpandProperty Count | Should HaveCount 5
        } -Pending

        It "Should return only 1 object when a Membername is included" {
            Get-SQLMemberRole -MemberName U2 | Should HaveCount 1
        } -Pending

        It "Should return all objects when a DB is not included" {
            $users | Should HaveCount 1
        } -Pending

        It "Should return all objects for a DB (2) when a DB is included" {
            Get-SQLMemberRole -Database DB1 | Should HaveCount 1
        } -Pending

        It "Should return only 1 object when a DB and Member name is included" {
            Get-SQLMemberRole -Database DB1 -MemberName U2 | Should HaveCount 1
        } -Pending
    }
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Set-SQLPermission" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SQLPermission" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SQLDatabase" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Remove-SQLDatabase" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Repair-SQLDatabase" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SQLJob" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Set-SQLJob" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : New-SQLSchedule" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SQLSchedule" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Import-SSRSReport" {
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

Describe "$ModuleName : Backup-SSRSReport" {
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

Describe "$ModuleName : Get-SSRSReport" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SSRSFolderSettings" {
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

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Set-SSRSFolderSettings" {
    # ----- Get Function Help
    # ----- Pester to test Comment based help
    # ----- http://www.lazywinadmin.com/2016/05/using-pester-to-test-your-comment-based.html
    Context "Help" {

        $H = Help Set-SSRSFolderSettings -Full

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

        $User = New-Object -TypeName PSObject -Property (@{
            'GroupUserName' = 'TestUser'
            'Folder' = '/'
            'Roles' = ''
        })
        
        It "Should throw an error if connecting to SQL Server Fails" {
            { Set-SSRSFolderSettings -SSRSServer "SSRSServer" -User $User -Role 'Browser'  } | Should Throw
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

            $obj | Add-Member -memberType ScriptMethod  -Name "SetPolicies" -Value {
            } -Force

            $Obj | Add-Member -MemberType ScriptMethod -Name ListChildren -value {
                Write-Object 'Path'
            }

            Return $Obj
        }
    }   
} 

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : New-SSRSFolderSettings" {
    # ----- Get Function Help
    # ----- Pester to test Comment based help
    # ----- http://www.lazywinadmin.com/2016/05/using-pester-to-test-your-comment-based.html
    Context "Help" {

        $H = Help New-SSRSFolderSettings -Full

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

            $obj | Add-Member -memberType ScriptMethod  -Name "SetPolicies" -Value {
            } -Force

            $Obj | Add-Member -MemberType ScriptMethod -Name ListChildren -value {
                Write-Object 'Path'
            }

            Return $Obj
        }
       
        It "Should throw an error if connecting to SQL Server Fails" {
            { New-SSRSFolderSettings -SSRSServer "SSRSServer" -User $User -Role 'Browser'  } | Should Throw
        } 

        It "Should throw an error if the user already exists" {
            { New-SSRSFolderSettings -SSRSServer "SSRSServer" -User 'testuser' -Role 'Browser'  } | Should Throw
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

            $obj | Add-Member -memberType ScriptMethod  -Name "SetPolicies" -Value {
            } -Force

            $Obj | Add-Member -MemberType ScriptMethod -Name ListChildren -value {
                Write-Object 'Path'
            }

            Return $Obj
        }
    }   
} 

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SSRSSitePermissions" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Add-SSRSSitePermissions" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SSRSReportDataSource" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Set-SSRSReportDataSource" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SQLClientProtocol" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SQLNetworkProtocol" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Set-SQLNetworkProtocol" {
}

#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SQLDBMail" {
}


#-------------------------------------------------------------------------------------

Write-Output "`n`n"

Describe "$ModuleName : Get-SQLDBMailAccount" {
}

