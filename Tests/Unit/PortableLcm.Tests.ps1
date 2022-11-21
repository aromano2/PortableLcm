
Import-Module "$PSScriptRoot\..\..\PortableLcm.psm1" -Force

Describe 'Assert-MofConfig' {
    Context 'Calling Assert-MofConfig with bad path' {
        It 'Should throw' {
            { Assert-MofConfig -Path fake } | Should -Throw
        }        
    }
}

Describe 'Get-MofResources' {
    Context 'Calling Get-MofResources with bad path' {
        It 'Should throw' {
            { Test-MofConfig -Path fake } | Should -Throw
        }        
    }
}

Describe 'Test-MofConfig' {
    Context 'Calling Test-MofConfig with bad path' {
        It 'Should throw' {
            { Test-MofConfig -Path fake } | Should -Throw
        }        
    }
}
