
Import-Module "$PSScriptRoot\..\..\PortableLcm.psm1" -Force

InModuleScope 'PortableLcm' {

    Describe 'Assert-MofConfig' {
        Mock -CommandName Test-ModulePresent -MockWith { $true }
        Context 'Calling Assert-MofConfig with bad path' {
            It 'Should throw' {
                { Assert-MofConfig -Path fake } | Should -Throw
            }        
        }

        Context 'Calling Assert-MofConfig with good path' {
            It 'Shoult not throw' {
                { Assert-MofConfig -Path $PSScriptRoot\Test.mof -DownloadModules } | Should -Not -Throw
            }

            It 'Should only return 1 resource from test MOF' {
                Mock -CommandName Test-MofResource -MockWith { $false } -ModuleName 'PortableLcm'
                Mock -CommandName Set-MofResource -ModuleName 'PortableLcm'

                Assert-MofConfig -Path $PSScriptRoot\Test.mof
                Should -Invoke -CommandName Test-MofResource -Times 1 -Exactly -ModuleName 'PortableLcm'
                Should -Invoke -CommandName Set-MofResource -Times 1 -Exactly -ModuleName 'PortableLcm'
            }

            It 'Should not try to Set a monitored resource' {
                $resourceId = '[UserRightsAssignment][V-26473][medium][Allow log on through Remote Desktop Services]::[WindowsServer]WindowsServerADStig'
                Mock -CommandName Test-MofResource -ModuleName 'PortableLcm' -MockWith { return @{
                        ResourceId     = $resourceId
                        InDesiredState = $false
                    }
                }

                Mock -CommandName Set-MofResource -ModuleName 'PortableLcm'
                [array]$resource = [Resource]::new('fake', $resourceId, 'fake', 'fake', 'fake', @{}, $false)
                Assert-MofConfig -Path $PSScriptRoot\Test.mof -MonitorResources $resource
                Should -Invoke -CommandName Test-MofResource -Times 1 -Exactly -ModuleName 'PortableLcm'
                Should -Invoke -CommandName Set-MofResource -Times 0 -Exactly -ModuleName 'PortableLcm'
            }

            It 'Should download missing modules if DownloadModules used' {
                Mock -CommandName 'Test-ModulePresent' -MockWith { $false } -ModuleName 'PortableLcm'
                Mock -CommandName 'Test-MofResource' -MockWith { $true } -ModuleName 'PortableLcm'
                Mock -CommandName 'Install-Module' -ModuleName 'PortableLcm'
                Assert-MofConfig -Path $PSScriptRoot\Test.mof -DownloadModules

                Should -Invoke -CommandName 'Install-Module' -Times 1 -Exactly
                Should -Invoke -CommandName 'Write-Warning' -Times 1 -Exactly
            }
        }
    }    

    Describe 'Get-MofResources' {
        Context 'Calling Get-MofResources with bad path' {
            It 'Should throw' {
                { Get-MofResources -Path fake } | Should -Throw
            }        
        }

        Context 'Calling Get-MofResources with good path' {
            It 'Shoult not throw' {
                { Get-MofResources -Path $PSScriptRoot\Test.mof } | Should -Not -Throw
            }
        }
    }

    Describe 'Test-MofConfig' {
        Context 'Calling Test-MofConfig with bad path' {
            It 'Should throw' {
                { Test-MofConfig -Path fake } | Should -Throw
            }        
        }

        Context 'Calling Test-MofConfig with good path' {
            It 'Shoult not throw' {
                { Test-MofConfig -Path $PSScriptRoot\Test.mof } | Should -Not -Throw
            }
        }
    }
}
