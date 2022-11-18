data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData -StringData @'
    ContainerDetected = Folder detected for path '{0}'.
    FoundResources = Found {0} resources in MOF {1}.
    ModulePresent = Module '{0}' with version '{1}' is present.
    MandatoryParameter = Parameter '{0}' is mandatory.
    ModuleNotPresent = Module '{0}-{1}' not present. '{2}' resources from '{3}' will not be applied.
    ParametersValidated = Parameters for resource '{0}' passed validation.
    ResourceValidated = Resource '{0}' passed validation.
    CallExternalFunction = Calling {0}-TargetResource for resource '{1}'.
    ParametersNotValidated = Parameters for resource '{0}' failed validation.
    ResourceNotInDesiredState = Resource '{0}' is not in desired state.
    ResourceInDesiredState = Resource '{0}' is in desired state.
    TestException = Exception thrown: {0}.
    MonitorOnlyResource = Resource '{0}' is set to monitor only. Set will be skipped.
'@
}

class Resource
{
    [string] $Name
    [string] $MofFile
    [string] $ResourceId
    [string] $ModuleName
    [string] $ModuleVersion
    [hashtable] $Property
    [bool] $InDesiredState

    Resource()
    {
        $this.Properties = [hashtable]::new()
    }

    Resource([String]$ResourceName, [string]$ResourceId , [string]$MofFile, [String]$ModuleName, [String]$ModuleVersion, [hashtable]$Properties, [bool] $InDesiredState = $false)
    {
        $this.Name           = $ResourceName
        $this.ResourceId     = $ResourceId
        $this.MofFile        = $MofFile
        $this.ModuleName     = $ModuleName
        $this.ModuleVersion  = $ModuleVersion
        $this.Property       = $Properties
        $this.InDesiredState = $InDesiredState
    }
}

function Convert-MofResources
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [string]
        $Path
    )

    if (Test-Path -Path $Path -PathType 'Container')
    {
        Write-Verbose -Message ($LocalizedData.ContainerDetected -f $Path)
        $mofFiles = (Get-ChildItem -Path $Path -Include "*.mof" -Recurse).FullName
    }
    else
    {
        $mofFiles = $path
    }

    try
    {
        $resources = @()
        foreach ($mofFile in $mofFiles)
        {
            $mofResources = ([Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($mofFile, 4)).Where({-not [string]::IsNullOrEmpty($_.ModuleName)})
            Write-Verbose -Message $($LocalizedData.FoundResources -f $mofResources.Count, $mofFile)
            
            foreach ($resource in $mofResources)
            {
                $resources += Get-MofResourceProperties -Resource $resource -MofFile $mofFile
            }
        }

        return $resources
    }
    catch
    {
        throw $_.Exception
    }
    finally
    {
        [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ClearCache()
    }
}

function Get-MofResourceProperties
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance]
        $Resource,

        [Parameter(Mandatory = $true)]
        [string]
        $MofFile
    )

    $ignoreProperties = 'ResourceId', 'PSComputerName', 'SourceInfo', 'ModuleName', 'ModuleVersion', 'ConfigurationName'
    $allProperties = Get-Member -InputObject $Resource -MemberType 'Property'
    $filteredProperties = $allProperties.Name.Where({$ignoreProperties -notcontains $_})
    if ($Resource.ResourceID -match '(?<=\[).*?(?=\])')
    {
        $resourceName = $Matches[0]
    }

    $properties = @{}
    foreach ($key in $filteredProperties)
    {
        $properties.Add($key, $Resource.$key)
    }

    return [Resource]::new($resourceName, $Resource.ResourceID, $MofFile, $Resource.ModuleName, $Resource.ModuleVersion, $properties, $false)
}

function Test-ParameterValidation
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [Hashtable]
        $Values
    )

    $ignoreResourceParameters = [System.Management.Automation.Cmdlet]::CommonParameters + [System.Management.Automation.Cmdlet]::OptionalCommonParameters
    $hasErrors = $false
    $command = Get-Command -Name $Name
    $parameterNames = $command.Parameters
    foreach ($key in $parameterNames.Keys)
    {
        if ($ignoreResourceParameters -notcontains $key)
        {
            $metadata = $command.Parameters.$($name)
            if ($($metadata.Attributes | Where-Object {$_.TypeId.Name -eq 'ParameterAttribute'}).Mandatory -and -not $Values.$($key))
            {
                Write-Warning -Message ($LocalizedData.MandatoryParameter -f $key)
                $hasErrors = $true
            }
        }
    }
    
    return (-not $hasErrors)
}

function Test-ModulePresent
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ModuleName,

        [Parameter(Mandatory = $true)]
        [string]
        $ModuleVersion
    )

    $moduleMatches = Get-Module -Name $ModuleName -ListAvailable -Verbose:$false | Select-Object @{Name='Version'; Expression = {$_.Version.ToString()}}
    if ($moduleMatches.Version -contains $ModuleVersion)
    {
        Write-Verbose -Message ($LocalizedData.ModulePresent -f $ModuleName, $ModuleVersion)
        return $true
    }
    else
    {
        return $false
    }
}

function Get-ValidParameter
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Name,

        [Parameter(Mandatory = $true)]
        [Hashtable]
        $Values
    )

    $ignoreResourceParameters = [System.Management.Automation.Cmdlet]::CommonParameters + [System.Management.Automation.Cmdlet]::OptionalCommonParameters
    $command = Get-Command -Name $Name
    $parameterNames = $command.Parameters
    $properties = @{}
    foreach ($key in $parameterNames.Keys)
    {
        if ($ignoreResourceParameters -notcontains $key)
        {
            if ($Values.ContainsKey($key))
            {
                $properties.Add($key, $Values.$key)
            }
        }
    }

    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']
    $properties.Add('Verbose', $verboseSetting)
    $properties.Add('ErrorAction', 'Stop')
    return $properties
}

function Invoke-Mof
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'ApplyAndMonitor', 'ApplyAndAutoCorrect', 'Test')]
        [string]
        $Operation,

        [Parameter()]
        [Resource[]]
        $MonitorResources
    )

    $oldPreference = $ProgressPreference
    $ProgressPreference = 'Ignore'
    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']
    [System.Collections.ArrayList]$allResources = Convert-MofResources -Path $Path
    $groupResources = $allResources | Group-Object -Property 'ModuleName', 'ModuleVersion'
    foreach ($groupResource in $groupResources)
    {
        $group = $groupResource.Group
        $moduleName = $group.ModuleName | Select-Object -First 1
        $moduleVersion = $group.ModuleVersion | Select-Object -First 1

        if(-not (Test-ModulePresent -ModuleName $moduleName -ModuleVersion $moduleVersion))
        {
            Write-Warning -Message $($LocalizedData.ModuleNotPresent -f $moduleName, $moduleVersion, $group.Count, $Path)

            foreach ($missingResource in $group)
            {
                $allResources.Remove($missingResource)
            }
        }
    }

    try
    {
        if ($allResources.Count -gt 0)
        {
            switch ($Operation)
            {
                'Get'
                {
                    foreach ($resource in $allResources)
                    {
                        Get-MofResource -Resource $resource -Verbose:$verboseSetting
                    }
                }

                'ApplyAndMonitor'
                {                    
                    foreach ($resource in $allResources)
                    {
                        if ($null -ne $MonitorResources -and $MonitorResources.ResourceID -contains $resource.ResourceID)
                        {
                            Write-Verbose -Message ($LocalizedData.MonitorOnlyResource -f $resource.ResourceID)
                            Test-MofResource -Resource $resource -Verbose:$verboseSetting
                        }
                        else
                        {
                            $result = Test-MofResource -Resource $resource -Verbose:$verboseSetting
                            
                            if (-not $result.InDesiredState)
                            {
                                Set-MofResource -Resource $resource -Verbose:$verboseSetting
                            }
                        }
                    }

                    break
                }

                'ApplyAndAutoCorrect'
                {
                    foreach ($resource in $allResources)
                    {
                        $result = Test-MofResource -Resource $resource -Verbose:$verboseSetting
                            
                        if (-not $result.InDesiredState)
                        {
                            Set-MofResource -Resource $resource -Verbose:$verboseSetting
                        }
                    }

                    break
                }

                'Test'
                {
                    foreach ($resource in $allResources)
                    {
                        Test-MofResource -Resource $resource -Verbose:$verboseSetting
                    }
                }
            }
        }
    }
    finally
    {
        $ProgressPreference = $oldPreference
    }
}

function Get-MofResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Resource]
        $Resource
    )

    $functionName = 'Get-TargetResource'
    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']

    try
    {
        $tempFunctionName = $functionName.Replace("-", "-$($Resource.Name)")
        $dscResource = (Get-DscResource -Module $Resource.ModuleName -Name $resource.Name -Verbose:$false).Where({$_.Version -eq $Resource.ModuleVersion}) | Select-Object -First 1
        if(-not (Get-Command -Name $tempFunctionName -ErrorAction 'SilentlyContinue'))
        {
            Import-Module -FullyQualifiedName $dscResource.Path -Function $functionName -Prefix $Resource.Name -Verbose:$false
        }

        if(Test-ParameterValidation -Name $tempFunctionName -Values $Resource.Property)
        {
            Write-Verbose -Message ($LocalizedData.ParametersValidated -f $Resource.ResourceId)
            $splatProperties = Get-ValidParameter -Name $tempFunctionName -Values $Resource.Property -Verbose:$verboseSetting
            Write-Verbose -Message ($LocalizedData.CallExternalFunction -f 'Get',$Resource.Name)

            $get = & "Get-$($Resource.Name)TargetResource" @splatProperties
            $cimGetResults = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
            foreach ($row in $get.Keys.GetEnumerator())
            {
                $value = $get.$row

                $CimProperties = @{
                    Namespace = 'root/Microsoft/Windows/DesiredStateConfiguration'
                    ClassName = "MSFT_KeyValuePair"
                    Property  = @{
                        Key   = "$row"
                        Value = "$value"
                    }
                }

                $cimGetResults += New-CimInstance -ClientOnly @CimProperties
            }

            $returnValue = @{
                ResourceName  = $Resource.ResourceName
                ResourceId    = $Resource.ResourceId
                ModuleName    = $Resource.ModuleName
                ModuleVersion = $Resource.ModuleVersion
                Properties    = $Resource.Property
                Result        = $cimGetResults
            }

            return $returnValue
        }
        else
        {
            Write-Warning -Message ($LocalizedData.ParametersNotValidated -f $Resource.ResourceId)
            return
        }
    }
    catch
    {
        throw $_.Exception
    }
    finally
    {
        Remove-Module -FullyQualifiedName $dscResource.Path
    }
}

function Test-MofResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Resource]
        $Resource
    )

    $functionName = 'Test-TargetResource'
    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']

    try
    {
        $tempFunctionName = $functionName.Replace("-", "-$($Resource.Name)")
        $dscResource = (Get-DscResource -Module $Resource.ModuleName -Name $Resource.Name -Verbose:$false).Where({$_.Version -eq $Resource.ModuleVersion}) | Select-Object -First 1
        if (-not (Get-Command -Name $tempFunctionName -ErrorAction 'SilentlyContinue'))
        {
            Import-Module -FullyQualifiedName $dscResource.Path -Function $functionName -Prefix $Resource.Name -Verbose:$false
        }            
        
        if (Test-ParameterValidation -Name $tempFunctionName -Values $Resource.Property)
        {
            Write-Verbose -Message ($LocalizedData.ParametersValidated -f $Resource.ResourceId)
            $splatProperties = Get-ValidParameter -Name $tempFunctionName -Values $Resource.Property -Verbose:$verboseSetting
            Write-Verbose -Message ($LocalizedData.CallExternalFunction -f 'Test', $Resource.Name)
            try
            {
                $result = &"Test-$($Resource.Name)TargetResource" @splatProperties
            }
            catch
            {
                Write-Error -Message ($LocalizedData.TestException -f $_.Exception)
            }

            if ($result)
            {
                Write-Verbose -Message ($LocalizedData.ResourceInDesiredState -f $Resource.ResourceId)
                $Resource.InDesiredState = $true
            }
            else
            {
                Write-Warning -Message ($LocalizedData.ResourceNotInDesiredState -f $Resource.ResourceId)
            }
        }
        else
        {
            Write-Warning -Message ($LocalizedData.ParametersNotValidated -f $Resource.ResourceId)
        }
    }
    catch
    {
        throw $_.Exception
    }
    finally
    {
        Remove-Module -FullyQualifiedName $dscResource.Path
    }

    return $Resource
}

function Set-MofResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Resource]
        $Resource
    )

    $functionName = "Set-TargetResource"    
    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']

    try
    {
        $tempFunctionName = $functionName.Replace("-", "-$($Resource.Name)")
        $dscResource = (Get-DscResource -Module $Resource.ModuleName -Name $Resource.Name -Verbose:$false).Where({$_.Version -eq $Resource.ModuleVersion}) | Select-Object -First 1
        if(-not (Get-Command -Name $tempFunctionName -ErrorAction 'SilentlyContinue'))
        {
            Import-Module -FullyQualifiedName $dscResource.Path -Function $functionName -Prefix $Resource.Name -Verbose:$false
        }
        
        if(Test-ParameterValidation -Name $tempFunctionName -Values $Resource.Property)
        {
            Write-Verbose -Message ($LocalizedData.ParametersValidated -f $Resource.ResourceId)
            $splatProperties = Get-ValidParameter -Name $tempFunctionName -Values $Resource.Property -Verbose:$verboseSetting
            Write-Verbose -Message ($LocalizedData.CallExternalFunction -f 'Set',$Resource.ResourceName)

            &"Set-$($Resource.Name)TargetResource" @splatProperties
        }
        else
        {
            Write-Warning -Message ($LocalizedData.ParametersNotValidated -f $Resource.ResourceId)
            return
        }
    }
    catch
    {
        throw $_.Exception
    }
    finally
    {
        Remove-Module -FullyQualifiedName $dscResource.Path
    }
}

Export-ModuleMember -Function Invoke-Mof