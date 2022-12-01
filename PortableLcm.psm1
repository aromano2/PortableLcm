data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData -StringData @'
    ContainerDetected = Folder detected for path '{0}'.
    FoundResources = Found {0} resources in file {1}.
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
    GetModule = Installing module '{0}:{1}'.
    JsonExists = JSON file '{0}' already exists. Use Force switch to overwrite.
    MofDoesNotExist = Publishing new MOF config '{0}' with hash '{1}'.
    HashMismatch = Hash mismatch for MOF '{0}'. Current hash: '{1}'. New hash: '{2}'. Overwriting existing configuration.
    MissingJson = MOF '{0}' missing associated file '{1}'. Re-importing.
    ModeMismatch = Mode mismatch for MOF '{0}'. Current mode: '{1}'. New mode: '{2}'. Overwriting existing configuration.
    MofExists = MOF '{0}' with hash '{1}' already exists. Skipping.
'@
}

$configParentPath = Join-Path -Path $env:ProgramData -ChildPath 'PortableLcm'
$configPath = Join-Path -Path $configParentPath -ChildPath 'config.json'
New-Variable -Name 'MofConfigPath' -Option 'ReadOnly' -Scope 'Global' -Value $configPath -Force

if (-not (Test-Path -Path $configPath))
{
    if (-not (Test-Path -Path $configParentPath))
    {
        $null = New-Item -Path $configParentPath -ItemType 'Directory'
    }

    $config = @{ Configurations = @() }
    $config | ConvertTo-Json | Out-File -FilePath $configPath
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
    [string] $Exception
    [string] $LastSet
    [string] $LastTest
    [string] $Mode

    Resource()
    {
        $this.Properties = [hashtable]::new()
    }

    Resource([String]$ResourceName, [string]$ResourceId , [string]$MofFile, [String]$ModuleName, [String]$ModuleVersion, [hashtable]$Properties)
    {
        $this.Name           = $ResourceName
        $this.ResourceId     = $ResourceId
        $this.MofFile        = $MofFile
        $this.ModuleName     = $ModuleName
        $this.ModuleVersion  = $ModuleVersion
        $this.Property       = $Properties
    }
}

#region Helpers
function Get-TimeStamp
{
    return Get-Date -Format 'MM/dd/yy hh:mm:ss'
}

<#
    .SYNOPSIS
        Imports resources from MOF file and converts them to resource objects.

    .PARAMETER Path
        Path to the folder containing many MOF files or path to a singular MOF file.

    .PARAMETER
        Optionally download modules required by the MOF resources.

    .EXAMPLE
        Initialize-MofResources -Path C:\test\test.mof -DownloadModules
#>
function Initialize-MofResources
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path,

        [Parameter()]
        [switch]
        $DownloadModules
    )

    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']
    $allResources = Get-MofResources -Path $Path
    $groupResources = $allResources | Group-Object -Property 'ModuleName', 'ModuleVersion'
    foreach ($groupResource in $groupResources)
    {
        $group = $groupResource.Group
        $moduleName = $group.ModuleName | Select-Object -First 1
        $moduleVersion = $group.ModuleVersion | Select-Object -First 1

        if(-not (Test-ModulePresent -ModuleName $moduleName -ModuleVersion $moduleVersion))
        {
            if ($DownloadModules)
            {
                Write-Verbose -Message ($LocalizedData.GetModule -f $moduleName, $moduleVersion)
                $null = Install-Module -Name $moduleName -RequiredVersion $moduleVersion -AllowClobber -Force -Verbose:$verboseSetting
            }

            Write-Warning -Message $($LocalizedData.ModuleNotPresent -f $moduleName, $moduleVersion, $group.Count, $Path)

            foreach ($missingResource in $group)
            {
                $allResources = $allResources.Where({$_.ResourceId -eq $missingResource.ResourceID})
            }
        }
    }

    return $allResources
}

function Update-MofResourceLog
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Resource]
        $Resource,

        [Parameter()]
        [ValidateScript({-not [string]::IsNullOrEmpty($_)})]
        [Newtonsoft.Json.Linq.JArray]
        $JsonLog
    )

    if ($JsonLog)
    {

    }

}

<#
    .SYNOPSIS
        Converts a CIM Instance MOF resource to a Resource object with only relative properties.

    .PARAMETER Resource
        Cim instance resource to convert.

    .PARAMETER MofFile
        Path to MOF file that the resource came from.

    .EXAMPLE
        $resource = @{
            ResourceID        = '[RegistryPolicyFile][V-46473][medium][DTBI014-IE11-TLS setting]::[InternetExplorer]BrowserStig'
            ValueName         = 'SecureProtocols'
            Ensure            = 'Present'
            Key               = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueData         = '{2560}'
            SourceInfo        = 'C:\Program Files\WindowsPowerShell\Modules\PowerSTIG\4.3.0\DSCResources\Resources\windows.Registry.ps1::40::13::RegistryPolicyFile'
            ValueType         = 'Dword'
            ModuleName        = 'GPRegistryPolicyDsc'
            TargetType        = 'ComputerConfiguration'
            ModuleVersion     = '1.2.0'
            ConfigurationName = 'MyConfiguration'
            PSComputerName    = ''
        }

        Convert-MofResource -Resource $resource -MofFile C:\temp\MyConfiguration.mof
#>
function Convert-MofResource
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

    return [Resource]::new($resourceName, $Resource.ResourceID, $MofFile, $Resource.ModuleName, $Resource.ModuleVersion, $properties)
}

<#
    .SYNOPSIS
        Tests a resource's properties to ensure it is not missing any mandatory parameters.

    .PARAMETER Name
        Name of the function to test against.

    .PARAMETER Values
        Property hashtable to validate against the function.

    .EXAMPLE
        $properties = @{
            ValueName  = 'SecureProtocols'
            ValueData  = '{2560}'
            Ensure     = 'Present'
            ValueType  = 'Dword'
            TargetType = 'ComputerConfiguration'
            Key        = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
        }

        Test-MandatoryParameter -Name 'Test-RegistryPolicyFileTargetResource' -Values $properties
#>
function Test-MandatoryParameter
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

<#
    .SYNOPSIS
        Tests if a specific version of a module is present.

    .PARAMETER ModuleName
        Name of the module.

    .PARAMETER ModuleVersion
        Version of the module.

    .EXAMPLE
        Test-ModulePresent -ModuleName 'ComputerManagementDsc' -ModuleVersion '1.0.0'
#>
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

<#
    .SYNOPSIS
        Checks to see if a hashtable contains valid parameters from a function.

    .PARAMETER Name
        Name of the function to test parameters against.

    .PARAMETER Values
        Hashtable of properties to test.

    .EXAMPLE
        $properties = @{
            Key                  = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            TargetType           = 'ComputerConfiguration'
            AccountName          = ''
            PsDscRunAsCredential = ''
            ValueType            = 'Dword'
            ValueData            = '{2560}'
            Ensure               = 'Present'
            ValueName            = 'SecureProtocols'
            Path                 = ''
            DependsOn            = ''
        }

        Test-Parameter -Name 'Test-RegistryPolicyFileTargetResource' -Values $properties
#>
function Test-Parameter
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

<#
    .SYNOPSIS
        Imports a function from a specified module with a prefix.

    .PARAMETER ModuleName
        Name of the module.

    .PARAMETER ModuleVersion
        Version of the module.

    .PARAMETER Operation
        Which function to get; get, set or test.
    
    .PARAMETER ResourceName
        Name of the DSC resource to retrieve a function from.

    .EXAMPLE
        Import-TempFunction -ModuleName ComputerManagementDsc -ModuleVersion 8.4.0 -Operation Get -ResourceName TimeZone
#>
function Import-TempFunction
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ModuleName,

        [Parameter(Mandatory = $true)]
        [string]
        $ModuleVersion,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Get', 'Test', 'Set')]
        [string]
        $Operation,

        [Parameter(Mandatory = $true)]
        [string]
        $ResourceName
    )

    $functionName = "$Operation-TargetResource"
    $tempFunctionName = $functionName.Replace("-", "-$ResourceName")
    $dscResource = (Get-DscResource -Module $ModuleName -Name $ResourceName -Verbose:$false).Where({$_.Version -eq $ModuleVersion}) | Select-Object -First 1
    if (-not (Get-Command -Name $tempFunctionName -ErrorAction 'SilentlyContinue'))
    {
        Import-Module -FullyQualifiedName $dscResource.Path -Function $functionName -Prefix $ResourceName -Verbose:$false
    }
    
    return @{
        Name = $tempFunctionName
        Path = $dscResource.Path
    }
}

<#
    .SYNOPSIS
        Executes the test method for a given resource.

    .PARAMETER Resource
        Resource object to test.

    .EXAMPLE
        $resource = @{
            Name          = 'RegistryPolicyFile'
            MofFile       = 'C:\Temp\myConfig.mof'
            ResourceId    = '[RegistryPolicyFile][V-46473][medium][DTBI014-IE11-TLS setting]::[InternetExplorer]BrowserStig'
            ModuleName    = 'GPRegistryPolicyDsc'
            ModuleVersion = '1.2.0'
            Property      = @{
                ValueName  = 'SecureProtocols'
                ValueData  = '{2560}'
                Ensure     = 'Present'
                ValueType  = 'Dword'
                TargetType = 'ComputerConfiguration'
                Key        = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            }
        }

        Test-MofResource -Resource $resource
#>
function Test-MofResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Resource]
        $Resource
    )

    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']

    try
    {
        $tempFunction = Import-TempFunction -ModuleName $Resource.ModuleName -ModuleVersion $Resource.ModuleVersion -ResourceName $Resource.Name -Operation 'Test'
        if (Test-MandatoryParameter -Name $tempFunction.Name -Values $Resource.Property)
        {
            Write-Verbose -Message ($LocalizedData.ParametersValidated -f $Resource.ResourceId)
            $splatProperties = Test-Parameter -Name $tempFunction.Name -Values $Resource.Property -Verbose:$verboseSetting
            Write-Verbose -Message ($LocalizedData.CallExternalFunction -f 'Test', $Resource.Name)
            try
            {
                $Resource.LastTest = Get-TimeStamp
                $result = &"$($tempFunction.Name)" @splatProperties
                $Resource.InDesiredState = $result
            }
            catch
            {
                $Resource.Exception = $_.Exception
                Write-Error -Message ($LocalizedData.TestException -f $_.Exception)
            }

            if ($result)
            {
                Write-Verbose -Message ($LocalizedData.ResourceInDesiredState -f $Resource.ResourceId)
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
        Remove-Module -FullyQualifiedName $tempFunction.Path
    }

    return $Resource
}

<#
    .SYNOPSIS
        Executes the set method for a given resource.

    .PARAMETER Resource
        Resource object to set.

    .EXAMPLE
        $resource = @{
            Name          = 'RegistryPolicyFile'
            MofFile       = 'C:\Temp\myConfig.mof'
            ResourceId    = '[RegistryPolicyFile][V-46473][medium][DTBI014-IE11-TLS setting]::[InternetExplorer]BrowserStig'
            ModuleName    = 'GPRegistryPolicyDsc'
            ModuleVersion = '1.2.0'
            Property      = @{
                ValueName  = 'SecureProtocols'
                ValueData  = '{2560}'
                Ensure     = 'Present'
                ValueType  = 'Dword'
                TargetType = 'ComputerConfiguration'
                Key        = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            }
        }

        Set-MofResource -Resource $resource
#>
function Set-MofResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Resource]
        $Resource
    )

    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']
    
    try
    {
        $tempFunction = Import-TempFunction -ModuleName $Resource.ModuleName -ModuleVersion $Resource.ModuleVersion -ResourceName $Resource.Name -Operation 'Set'
        if(Test-MandatoryParameter -Name $tempFunction.Name -Values $Resource.Property)
        {
            Write-Verbose -Message ($LocalizedData.ParametersValidated -f $Resource.ResourceId)
            $splatProperties = Test-Parameter -Name $tempFunction.Name -Values $Resource.Property -Verbose:$verboseSetting
            Write-Verbose -Message ($LocalizedData.CallExternalFunction -f 'Set',$Resource.ResourceName)

            try
            {
                $Resource.LastSet = Get-TimeStamp
                &"$($tempFunction.Name)" @splatProperties
                $Resource.InDesiredState = $true
            }
            catch
            {
                $Resource.Exception = $_.Exception
            }

            return $Resource
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
        Remove-Module -FullyQualifiedName $tempFunction.Path
    }
}
#endregion Helpers

function Set-MofLogPath
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({[System.IO.Path]::GetExtension($_) -eq '.json'})]
        [string]
        $Path
    )

    if (-not (Test-Path -Path $Path))
    {
        $null = New-Item -Path $Path -ItemType 'File'
    }

    $null = @{ LogPath = $Path } | ConvertTo-Json | Out-File -FilePath $global:MofConfigPath
    $global:MofLogPath = $Path
}

<#
    .SYNOPSIS
        Returns all resources in a MOF file as a resource object.

    .PARAMETER Path
        Path to the folder containing many MOF files or path to a singular MOF file

    .EXAMPLE
        Get-MofResources -Path C:\temp\file.mof
#>
function Get-MofResources
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
        $jsonFiles = (Get-ChildItem -Path $Path -Include "*.json" -Recurse).FullName
    }
    else
    {
        $mofFiles, $jsonFiles = $path
    }

    try
    {
        $resources = @()
        foreach ($jsonFile in $jsonFiles)
        {
            $jsonResources = Get-Content -Path $jsonFile | ConvertFrom-Json
            Write-Verbose -Message $($LocalizedData.FoundResources -f $jsonResources.Count, $jsonFile)

            $resources += $jsonResources
        }

        foreach ($mofFile in $mofFiles)
        {
            $mofResources = ([Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($mofFile, 4)).Where({-not [string]::IsNullOrEmpty($_.ModuleName)})
            Write-Verbose -Message $($LocalizedData.FoundResources -f $mofResources.Count, $mofFile)
            
            foreach ($resource in $mofResources)
            {
                $resources += Convert-MofResource -Resource $resource -MofFile $mofFile
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

<#
    .SYNOPSIS 
        Tests resource states defined in a MOF file.

    .PARAMETER Path
        Path to the folder containing many MOF files or path to a singular MOF file

    .EXAMPLE
        Test-MofConfig -Path C:\temp\file.mof -Operation Get
#>
function Test-MofConfig
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [string]
        $Path,

        [Parameter()]
        [switch]
        $DownloadModules
    )

    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']
    $allResources = Import-MofConfig -Path $Path -DownloadModules:$DownloadModules -Verbose:$verboseSetting
    [array]$logObjects = Get-Content -Path $global:MofLogPath -Raw | ConvertFrom-Json

    foreach ($resource in $allResources)
    {
        $result = Test-MofResource -Resource $resource -Verbose:$verboseSetting
        $currentLogObject = $logObjects.Where({$_.ResourceId -eq $resource.ResourceId})

        if ($currentLogObject)
        {
            # Carry over unmodified properties from logs
            $result.LastSet = $currentLogObject.LastSet
            $result.Mode = $currentLogObject.Mode
            $result.Exception = $currentLogObject.Exception
            
            # Remove stale log entry
            $logObjects = $logObjects.Where({$_.ResourceId -ne $result.ResourceId})
        }
        
        # Add new object to log stack
        $logObjects += $result
    }

    # Write log to file
    $logObjects | ConvertTo-Json -Depth 4 | Out-File -FilePath $global:MofLogPath -Force
}

<#
    .SYNOPSIS
        Applies configuration from a MOF file. Will not apply configuration to resources specified in MonitorResources.

    .PARAMETER Path
        Path to the folder containing many MOF files or path to a singular MOF file.

    .PARAMETER MonitorResources
        Resources that have been applied before and will not be changed. Only used with 'ApplyAndMonitor' action.

    .EXAMPLE
        Assert-MofConfig -Path C:\temp\file.mof

    .EXAMPLE
        $monitor = [Resource]::new("MyFileResource", "ResourceId", "C:\temp\file.mof", "MyModuleName", "MyModuleVersion", @{Property1 = 2}, $false)
        Assert-MofConfig -Path C:\temp\file.mof -MonitorResources $monitorResources

        This example will enforce the configuration from file.mof with exception to the resource named MyFileResource. Even though it is not in desired
        state, it will not enforce its desired state.
#>
function Assert-MofConfig
{
    [CmdletBinding()]
    param
    (
        [Parameter(ParameterSetName = 'ByFile', Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [ValidateScript({@('.mof','.json') -contains [System.IO.Path]::GetExtension($_)})]
        [string]
        $Path,

        [Parameter(ParameterSetName = 'ByObject', Mandatory = $true, ValueFromPipeline = $true)]
        [psobject]
        $InputObject,

        [Parameter()]
        [Resource[]]
        $MonitorResources,

        [Parameter()]
        [switch]
        $DownloadModules
    )

    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']
    $allResources = Import-MofConfig -Path $Path -DownloadModules:$DownloadModules
    [array]$logObjects = Get-Content -Path $global:MofLogPath -Raw | ConvertFrom-Json

    foreach ($resource in $allResources)
    {
        Write-Verbose -Message ($LocalizedData.MonitorOnlyResource -f $resource.ResourceID)
        $result = Test-MofResource -Resource $resource -Verbose:$verboseSetting

        if($resource.Mode -eq 'ApplyAndAutoCorrect' -and -not $result.InDesiredState)
        {
                $result = Set-MofResource -Resource $result -Verbose:$verboseSetting
        }

        $currentLogObject = $logObjects.Where({$_.ResourceId -eq $resource.ResourceId})
        if ($currentLogObject)
        {
            # Remove stale log entry
            $logObjects = $logObjects.Where({$_.ResourceId -ne $result.ResourceId})
        }
        
        # Add new object to log stack
        $logObjects += $result
    }

    $logObjects | ConvertTo-Json -Depth 4 | Out-File -FilePath $global:MofLogPath -Force
    return $logObjects
}

<#
    .SYNOPSIS
        Converts resources from MOF file into a JSON file.

    .PARAMETER MofPath
        Path to the MOF file.

    .PARAMETER JsonPath
        Path to JSON file that will be created.

    .PARAMETER Mode
        DSC mode to apply to the configuration, either ApplyAndAutoCorrect (default) or ApplyAndMonitor.

    .PARAMETER Force
        Forces the overwrite of an existing JSON file.

    .EXAMPLE
        Import-MofConfig -MofPath C:\test\test.mof -JsonPath c:\test\test.json
#>
function Import-MofConfig
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [ValidateScript({[System.IO.Path]::GetExtension($_) -eq '.mof'})]
        [string]
        $MofPath,

        [Parameter(Mandatory = $true)]
        [ValidateScript({[System.IO.Path]::GetExtension($_) -eq '.json'})]
        [string]
        $JsonPath,

        [Parameter()]
        [ValidateSet('ApplyAndAutoCorrect', 'ApplyAndMonitor')]
        [string]
        $Mode = 'ApplyAndAutoCorrect',

        [Parameter()]
        [switch]
        $Force
    )

    $allResources = Get-MofResources -Path $MofPath
    foreach ($resource in $allResources)
    {
        $resource.Mode = $Mode
    }   
    
    if (Test-Path -Path $JsonPath)
    {
        if (-not $Force)
        {
            Write-Warning -Message ($LocalizedData.JsonExists -f $JsonPath)
        }
        else
        {
            Remove-Item -Path $JsonPath -Force
        }
    }

    $null = New-Item -Path $JsonPath -ItemType 'File'
    $allResources | ConvertTo-Json -Depth 4 -WarningAction 'SilentlyContinue' | Out-File -FilePath $JsonPath

    return $allResources
}

function Get-DscMofConfig
{
    return Get-Content -Path $MofConfigPath | ConvertFrom-Json -Depth 4 -WarningAction 'SilentlyContinue'
}

<#
    .SYNOPSIS
        Retrieves the current state of the current DSC MOF configuration.

    .PARAMETER Name
        Name of the MOF to retrieve the status for. Leaving this null will return status for all configured MOF's.

    .PARAMETER Full
        Returns details for all resources contained in the specified MOF.

    .EXAMPLE
        Get-DscMofStatus -Name myMofConfig -Detailed

        This will return the state of every resource in the myMofConfig MOF.

    .EXAMPLE
        Get-DscMofStatus

        This will return only the Name of the MOF(s) in the configuration and whether or not all the resources are in desired state for that MOF.
#>
function Get-DscMofStatus
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [switch]
        $Full
    )
    DynamicParam
    {
        $configurations = (Get-DscMofConfig).Configurations
        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.Mandatory = $false
        $attribute.HelpMessage = "Name of the MOF"
        $attributeCollection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
        $attributeCollection.Add($attribute)

        $validateSet = New-Object System.Management.Automation.ValidateSetAttribute($configurations.Name)
        $attributeCollection.add($validateSet)

        $param = New-Object System.Management.Automation.RuntimeDefinedParameter('Name', [string], $attributeCollection)

        $dictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $dictionary.Add('Name', $param)
        return $dictionary
    }

    begin
    {
        $Name = $PsBoundParameters['Name']
    }
    process
    {
        $status = @()
        $configurations = (Get-DscMofConfig).Configurations
        if ($Name)
        {
            $configuration = $configurations.Where({$_.Name -eq $Name})
            $status += (Get-Content -Path $configuration.JsonPath | ConvertFrom-Json -WarningAction 'SilentlyContinue')
            if (-not $Full)
            {
                $properties = [ordered]@{
                    Name = $Name
                    InDesiredState = ($status.InDesiredState -notcontains $false)
                }

                return (New-Object -TypeName 'PSObject' -Property $properties)
            }
        }
        else
        {
            foreach ($configuration in $configurations)
            {
                $status += Get-Content -Path $configuration.JsonPath | ConvertFrom-Json -WarningAction 'SilentlyContinue'
                if (-not $Full)
                {
                    $properties = [ordered]@{
                        Name = $Name
                        InDesiredState = ($status.InDesiredState -notcontains $false)
                    }

                    Write-Output -InputObject (New-Object -TypeName 'PSObject' -Property $properties)
                }
            }
        }

        return $status
    }
}

<#
    .SYNOPSIS
        Publishes MOF file(s) to its internal configuration.

    .PARAMETER Path
        Path to a MOF file or folder containing many MOF files.

    .PARAMETER Mode
        Mode to apply to MOF file(s): ApplyAndMointor (default) or ApplyAndAutoCorrect

    .EXAMPLE
        Publish-DscMof -Path c:\temp\myMof.mof
#>
function Publish-DscMof
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [string]
        $Path,

        [Parameter()]
        [ValidateSet('ApplyAndAutoCorrect', 'ApplyAndMonitor')]
        [string]
        $Mode = 'ApplyAndMonitor'
    )

    # Read in configuration data
    $mofConfig = Get-DscMofConfig
    $configurations = $mofConfig.Configurations
    if (Test-Path -Path $Path -PathType 'Container')
    {
        Write-Verbose -Message ($LocalizedData.ContainerDetected -f $Path)
        $mofFiles = (Get-ChildItem -Path $Path -Include "*.mof" -Recurse).FullName
    }
    else
    {
        $mofFiles = $Path
    }

    foreach ($mofFile in $mofFiles)
    {
        $hash = (Get-FileHash -Path $mofFile -Algorithm 'MD5').Hash
        $parentPath = Split-Path -Path $mofFile -Parent
        $mofName = [System.IO.Path]::GetFileNameWithoutExtension($mofFile)
        $jsonPath = Join-Path -Path $parentPath -ChildPath "$mofName.json"
        $existingConfig = $configurations.Where({$_.Name -eq $mofName -and $_.MofPath -eq $Path}) | Select-Object -First 1
        $allResources = @()

        $properties = @{
            Name     = $mofName
            Hash     = $hash
            Mode     = $Mode
            MofPath  = $Path
            JsonPath = $jsonPath
        }

        # MOF exists in config and matches all current values - skip it
        if ($existingConfig.Count -gt 0 -and $existingConfig.Hash -eq $hash -and (Test-Path -Path $jsonPath) -and $existingConfig.Mode -eq $Mode)
        {
            Write-Verbose -Message ($LocalizedData.MofExists -f $mofName, $hash)
            continue
        }
        else
        {
            $jsonExists = Test-Path -Path $jsonPath

            # Config doesn't exist or hash doesn't match (MOF updated) or JSON doesn't exist
            if ($existingConfig.Count -eq 0 -or $existingConfig.Hash -ne $hash -or -not $jsonExists)
            {
                if ($existingConfig.Count -eq 0)
                {
                    Write-Verbose -Message ($LocalizedData.MofDoesNotExist -f $mofName, $hash)
                    $mofResources = Import-MofConfig -MofPath $mofFile -JsonPath $jsonPath -Mode $Mode -Force
                    $properties.ResourceCount = $mofResources.Count
                    $configurations += $properties
                }
                else
                {
                    if ($existingConfig.Hash -ne $hash)
                    {
                        Write-Verbose -Message ($LocalizedData.HashMismatch -f $mofName, $existingConfig.Hash, $hash)
                        $existingConfig.Hash = $hash
                    }
                    elseif (-not $jsonExists)
                    {
                        Write-Verbose -Message ($LocalizedData.MissingJson -f $mofName, $jsonPath)
                    }

                    $mofResources = Import-MofConfig -MofPath $mofFile -JsonPath $jsonPath -Mode $Mode -Force
                    $allResources += $mofResources
                    $properties.ResourceCount = $mofResources.Count    
                }
            }
            elseif ($existingConfig.Mode -ne $Mode)
            {
                Write-Verbose -Message ($LocalizedData.ModeMismatch -f $mofName, $existingConfig.Mode, $Mode)
                $existingConfig.Mode = $Mode
            }
        }
    }

    $tempConfig = $mofConfig
    $tempConfig.Configurations = $configurations
    $tempConfig | ConvertTo-Json -Depth 4 -WarningAction 'SilentlyContinue' | Out-File -FilePath $MofConfigPath
}

Export-ModuleMember -Function Assert-MofConfig, Test-MofConfig, Get-MofResources, Set-MofLogPath, Import-MofConfig, Publish-DscMof, Get-DscMofConfig, Get-DscMofStatus
