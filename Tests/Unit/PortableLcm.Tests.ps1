
Import-Module "$PSScriptRoot\..\..\PortableLcm.psm1" -Force

Describe 'Test-Parameter' {
    function Test-Function
    {
        [cmdletbinding()]
        param
        (
            [Parameter()]
            [string]
            $Key,

            [Parameter()]
            [string]
            $ValueName
        )

    }

    Context 'Calling Test-Parameter with no extra parameters' {

        $ContextParams = @{
            Name   = 'Test-Function'
            Values = @{
                Key       = 'TestRegistryKey'
                ValueName = ''
            }
        }

        $params = Test-Parameter @ContextParams

        It 'Should return 2 params' {
            $params.count | should be 2
        }
    }

    Context 'Calling Test-Parameter with extra parameters' {

        $ContextParams = @{
            Name   = 'Test-Function'
            Values = @{
                Key       = 'TestRegistryKey'
                ValueName = ''
                Extra     = ''
            }
        }

        $params = & 'Test-Parameter' @ContextParams

        It 'Should return 2 params' {
            $params.Count | should be 2
        }
    }
}

Describe 'Assert-Validation' {
    $Parameter = [System.Management.Automation.ParameterMetadata]::new('Name', 'string')
    $Parameter.Attributes.Add([System.Management.Automation.ValidateLengthAttribute]::new(1, 3))

    Context 'Calling Assert-Validation with value not meeting parameter requirements' {
        $ContextParams = @{
            element           = 'Test'
            ParameterMetadata = $Parameter
        }

        It 'Should throw' {
            { Assert-Validation @ContextParams } | should throw
        }
    }

    Context 'Calling Assert-Validation with value meeting parameter requirements' {

        $ContextParams = @{
            element           = 'Yes'
            ParameterMetadata = $Parameter
        }

        It 'Should not throw' {
            { Assert-Validation @ContextParams } | should not throw
        }
    }
}

Describe 'Test-MandatoryParameter' {
    function Test-Function
    {
        [cmdletbinding()]
        param
        (
            [parameter(Mandatory = $true)]
            [string]
            $Key,

            [parameter(Mandatory = $true)]
            [string]
            $ValueName
        )

    }

    Context 'Calling Test-MandatoryParameter with missing required parameter' {

        $ContextParams = @{
            Name   = 'Test-Function'
            Values = @{
                Key = 'TestRegistryKey'
            }
        }

        It 'Should throw' {
            { Test-MandatoryParameter @ContextParams } | should throw
        }
    }

    Context 'Calling Test-MandatoryParameter with value meeting parameter requirements' {

        $ContextParams = @{
            Name   = 'Test-Function'
            Values = @{
                Key       = 'TestRegistryKey'
                ValueName = 'Test'
            }
        }

        It 'Should not throw' {
            { Test-MandatoryParameter @ContextParams } | should not throw
        }
    }
}