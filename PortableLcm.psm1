data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData -StringData @'
    ContainerDetected = Folder detected for path '{0}'.
    FoundInstances = Found {0} resources in file {1}.
    ModulePresent = Module '{0}' with version '{1}' is present.
    InstallModule = Installing module '{0}' version '{1}' to scope '{2}'.
    MandatoryParameter = Parameter '{0}' is mandatory.
    ModuleNotPresent = Module '{0}-{1}' not present. Skipping resource '{2}'.
    ParametersValidated = Parameters for resource '{0}' passed validation.
    ResourceValidated = Resource '{0}' passed validation.
    CallExternalFunction = Calling {0}-TargetResource for resource '{1}'.
    ExternalFunctionError = Resource: {0}\n{1} Error: {2}.
    ParametersNotValidated = Parameters for resource '{0}' failed validation.
    ResourceNotInDesiredState = Resource '{0}' is not in desired state.
    ResourceInDesiredState = Resource '{0}' is in desired state.
    TestException = Exception thrown: {0}.
    MonitorOnlyResource = Resource '{0}' is set to monitor only. Set will be skipped.
    MofDoesNotExist = Publishing new MOF config '{0}' with hash '{1}'.
    HashMismatch = Hash mismatch for MOF '{0}'. Current hash: '{1}'. New hash: '{2}'. Overwriting existing configuration.
    ModeMismatch = Mode mismatch for MOF '{0}'. Current mode: '{1}'. New mode: '{2}'. Overwriting existing configuration.
    MofExists = MOF '{0}' with hash '{1}' already exists. Skipping.
    DependencyDesiredState = Resource '{0}' dependency '{1}' is in desired state.
    DependencyNotInDesiredState = Resource '{0}' dependency '{1}' is not in desired state, skipping.
    DependencySet = Resource '{0}' dependency '{1}' has been set.
    DependencyNotSet = Resource '{0}' dependency '{1}' has not been set, skipping.
    CopyMof = Copying '{0}' to {1}'.
    RebootRequiredNotAllowed = A reboot is required to finish applying configuration but reboots are not allowed. 
    RebootNotRequired = A reboot is not required.
    Reboot = Rebooting to finish applying configuration.
    CredentialNotSupported = Credential property detected in resource '{0}'. Credentials are currently not supported. Skipping.
    LcmBusy = A compliance check is already in progress in process '{0}'.
    StopWait = Waiting '{0}' seconds before shutting down.
    MissingProcessId = Unable to stop lcm process. Process ID is missing from the configuration.
'@
}

function Initialize-Lcm
{
    $configParentPath = Join-Path -Path $env:ProgramData -ChildPath 'PortableLcm'
    $configPath = Join-Path -Path $configParentPath -ChildPath 'config.json'
    New-Variable -Name 'MofConfigPath' -Option 'ReadOnly' -Scope 'Global' -Value $configPath -Force

    if (-not (Test-Path -Path $configPath))
    {
        if (-not (Test-Path -Path $configParentPath))
        {
            $null = New-Item -Path $configParentPath -ItemType 'Directory'
        }

        $config = [ordered]@{
            Settings = @{
                AllowReboot           = $true
                Status                = 'Idle'
                ProcessId             = $null
                Cancel                = $false
                CancelTimeoutInSeconds = 300
            }
            Configurations = @()
        }

        $config | ConvertTo-Json | Out-File -FilePath $configPath
    }
}

class Resource
{
    [string] $ResourceId
    [string] $Type
    [string] $ModuleName
    [string] $ModuleVersion
    [bool] $InDesiredState
    [string] $Exception
    [string] $LastSet
    [string] $LastTest
    [string] $Mode
    [string] $DependsOn
    [hashtable] $Properties

    Resource([string]$ResourceId, [string]$Type, [String]$ModuleName, [String]$ModuleVersion, [string]$Mode, [string]$DependsOn)
    {
        $this.ResourceId     = $ResourceId
        $this.Type           = $Type
        $this.ModuleName     = $ModuleName
        $this.ModuleVersion  = $ModuleVersion
        $this.Mode           = $Mode
        $this.DependsOn      = $DependsOn
    }

    Resource([string]$ResourceId, [string]$Type, [String]$ModuleName, [String]$ModuleVersion, [string]$Mode, [string]$DependsOn, [hashtable]$Properties)
    {
        $this.ResourceId     = $ResourceId
        $this.Type           = $Type
        $this.ModuleName     = $ModuleName
        $this.ModuleVersion  = $ModuleVersion
        $this.Mode           = $Mode
        $this.DependsOn      = $DependsOn
        $this.Properties     = $Properties
    }
}

#region Helpers
function Get-TimeStamp
{
    return Get-Date -Format 'MM/dd/yy hh:mm:ss'
}

<#
    .SYNOPSIS
        Converts a CIM Instance to a Resource object with only relative properties.

    .PARAMETER Instance
        Cim instance to convert.

    .PARAMETER Mode
        Mode to apply to instance, either 'ApplyAndAutoCorrect' or 'ApplyAndMonitor'.

    .PARAMETER IncludeProperties
        If supplied, properties will be included with resource output.

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

        Convert-MofInstance -Instance $instance
#>
function Convert-MofInstance
{
    [CmdletBinding()]
    [OutputType([Resource])]
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance]
        $Instance,

        [Parameter()]
        [ValidateSet('ApplyAndAutoCorrect', 'ApplyAndMonitor')]
        [string]
        $Mode = 'ApplyAndAutoCorrect',
        
        [Parameter()]
        [switch]
        $IncludeProperties
    )

    if ($Instance.ResourceID -match '(?<=\[).*?(?=\])')
    {
        $type = $Matches[0]
    }

    if ($IncludeProperties)
    {
        $properties = Get-MofInstanceProperties -Instance $Instance
        return [Resource]::new($Instance.ResourceID, $type, $Instance.ModuleName, $Instance.ModuleVersion, $Mode, $Instance.DependsOn, $properties)
    }
    else
    {
        return [Resource]::new($Instance.ResourceID, $type, $Instance.ModuleName, $Instance.ModuleVersion, $Mode, $Instance.DependsOn)
    }
}

<#
    .SYNOPSIS
        Extracts properties embedded in a CIM instance.

    .PARAMETER Instance
        CIM instance to get properties from.
#>
function Get-MofInstanceProperties
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance]
        $Instance
    )

    $filterProperties = @('ConfigurationName', 'ModuleName', 'ModuleVersion', 'SourceInfo', 'ResourceID', 'PSComputerName')
    $properties = $Instance.CimInstanceProperties.Where({$filterProperties -notcontains $_.Name})
    
    $propertyTable = @{}
    foreach ($property in $properties)
    {
        $type = $property.CimType.ToString()
        if ($type -notlike '*Array')
        {
            if ($type -eq 'SInt64')
            {
                $type = 'Long'
            }
            elseif ($type -eq 'Instance')
            {
                $typeName = ($property.Value | Get-Member).TypeName
                if ($typeName -contains 'Microsoft.Management.Infrastructure.CimInstance#MSFT_Credential')
                {
                    throw ($LocalizedData.CredentialNotSupported -f $Instance.ResourceId)
                }
            }

            $propertyTable[$($property.Name)] = ($property.Value -as ([type]$type))
        }
        else
        {
            $propertyTable[$($property.Name)] = @($property.Value)
        }      
    }

    return $propertyTable
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
    [OutputType([bool])]
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
    [OutputType([bool])]
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

        Merge-MofResourceParameter -Name 'Test-RegistryPolicyFileTargetResource' -Values $properties
#>
function Merge-MofResourceParameter
{
    [CmdletBinding()]
    [OutputType([hashtable])]
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
    [OutputType([hashtable])]
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

    $progPref = $ProgressPreference
    $global:ProgressPreference = 'SilentlyContinue'
    $functionName = "$Operation-TargetResource"
    $tempFunctionName = $functionName.Replace("-", "-$ResourceName")
    try
    {
        $dscResource = (Get-DscResource -Module $ModuleName -Name $ResourceName -Verbose:$false).Where({$_.Version -eq $ModuleVersion}) | Select-Object -First 1
        if (-not (Get-Command -Name $tempFunctionName -ErrorAction 'SilentlyContinue') -and $null -ne $dscResource)
        {
            Import-Module -FullyQualifiedName $dscResource.Path -Function $functionName -Prefix $ResourceName -Verbose:$false
        }
    }
    catch
    {
        throw $_.Exception
    }
    finally
    {
        $global:ProgressPreference = $progPref
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
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [Resource]
        $Resource
    )

    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']

    try
    {
        $tempFunction = Import-TempFunction -ModuleName $Resource.ModuleName -ModuleVersion $Resource.ModuleVersion -ResourceName $Resource.Type -Operation 'Test'
        if (Test-MandatoryParameter -Name $tempFunction.Name -Values $Resource.Properties)
        {
            Write-Verbose -Message ($LocalizedData.ParametersValidated -f $Resource.ResourceId)
            $splatProperties = Merge-MofResourceParameter -Name $tempFunction.Name -Values $Resource.Properties -Verbose:$verboseSetting
            Write-Verbose -Message ($LocalizedData.CallExternalFunction -f 'Test', $Resource.Type)
            try
            {
                $result = &"$($tempFunction.Name)" @splatProperties
            }
            catch
            {
                throw $_.Exception
            }

            if ($result)
            {
                Write-Verbose -Message ($LocalizedData.ResourceInDesiredState -f $Resource.ResourceId)
            }
            else
            {
                Write-Warning -Message ($LocalizedData.ResourceNotInDesiredState -f $Resource.ResourceId)
            }

            return $result
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
        if ($null -ne $tempFunction -and $tempFunction.ContainsKey('Path') -and $null -ne $tempFunction.Path)
        {
            #Remove-Module -FullyQualifiedName $tempFunction.Path
        }
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
        $tempFunction = Import-TempFunction -ModuleName $Resource.ModuleName -ModuleVersion $Resource.ModuleVersion -ResourceName $Resource.Type -Operation 'Set'
        if(Test-MandatoryParameter -Name $tempFunction.Name -Values $Resource.Properties)
        {
            Write-Verbose -Message ($LocalizedData.ParametersValidated -f $Resource.ResourceId)
            $splatProperties = Merge-MofResourceParameter -Name $tempFunction.Name -Values $Resource.Properties -Verbose:$verboseSetting
            Write-Verbose -Message ($LocalizedData.CallExternalFunction -f 'Set',$Resource.Type)

            try
            {
                $Resource.LastSet = Get-TimeStamp
                &"$($tempFunction.Name)" @splatProperties
                $Resource.InDesiredState = $true
            }
            catch
            {
                $Resource.Exception = $_.Exception
                throw $_.Exception
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
        if ($null -ne $tempFunction -and $tempFunction.ContainsKey('Path') -and $null -ne $tempFunction.Path)
        {
            #Remove-Module -FullyQualifiedName $tempFunction.Path
        }
    }
}

function Write-EventLogEntry
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $EntryMessage,

        [Parameter(Mandatory = $true)]
        [string[]]
        $EntryArguments,

        [Parameter()]
        [ValidateSet("Error", "Warning", "Information")]
        $EntryType = "Information"
    )

    if ($env:OS -eq 'Windows_NT' -and $PSEdition -eq 'Desktop')
    {
        $eventParams = @{
            Category = 8 # Pipeline Execution Details
            EventId = 1000
            LogName = "Windows PowerShell"
            Source = "PowerShell"
            Message = ($EntryMessage -f $EntryArguments)
            EntryType = $EntryType
        }
        Write-EventLog @eventParams
    }

    if ($EntryType -in @("Error", "Warning"))
    {
        Write-Warning -Message ($EntryMessage -f $EntryArguments)
    }
}

<#
    .SYNOPSIS
        Converts resources from MOF file into a JSON file.

    .PARAMETER MofPath
        Path to the MOF file.

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
        $Path,

        [Parameter()]
        [ValidateSet('ApplyAndAutoCorrect', 'ApplyAndMonitor')]
        [string]
        $Mode = 'ApplyAndAutoCorrect'
    )

    $allInstances = Get-MofCimInstances -Path $Path
    $output = @()
    foreach ($instance in $allInstances)
    {
        $output += Convert-MofInstance -Instance $instance -Mode $Mode
    }   
    
    return $output
}

<#
    .SYNOPSIS
        Returns a sorted hashtable of DSC partial configuration dependencies

    .PARAMETER Graph
        Hashtable of DSC partial configuration dependencies
#>

function Invoke-SortDependencyGraph
{
    param
    (
        [Parameter(Mandatory = $true)]
        [Hashtable]
        $Graph
    )

    # To hold ordered dependencies
    $sorted = @()

    # To hold remaining dependencies
    $remaining = @{}
    foreach ($key in $Graph.Keys)
    {
        $remaining[$key] = [System.Collections.Generic.List[string]]$Graph[$key]
    }

    while ($remaining.Count -gt 0)
    {
        $leaf = Get-Leaf $remaining
        if (-not $leaf)
        {
            throw "No leaf found in graph. Sorted: $sorted Remaining: $($remaining.Keys)"
        }

        # Remove leaf from remaining and add to ordered list
        $sorted += $leaf

        # Remove leaf from remaining
        $remaining.Remove($leaf)
        foreach ($key in $remaining.Keys)
        {
            [string]$leafName = $remaining[$key].Where( {$_ -ieq $leaf})
            if (-not [string]::IsNullOrEmpty($leafName))
            {
                $null = $remaining[$key].Remove($leafName)
            }
        }
    }

    return $sorted
}

function Get-Leaf
{
    param
    (
        [Parameter(Mandatory = $true)]
        [Hashtable]
        $Graph
    )

    foreach ($key in $Graph.Keys)
    {
        if ($Graph[$key].Count -eq 0)
        {
            return $key
        }
    }
}
#endregion Helpers

#region Public
<#
    .SYNOPSIS
        Returns all CIM instances in a MOF file.

    .PARAMETER Path
        Path to the folder containing many MOF files or path to a singular MOF file

    .EXAMPLE
        Get-MofCimInstances -Path C:\temp\file.mof
#>
function Get-MofCimInstances
{
    [CmdletBinding()]
    [OutputType([Microsoft.Management.Infrastructure.CimInstance])]
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
        $mofFiles = $Path
    }

    try
    {
        $instances = @()
        foreach ($mofFile in $mofFiles)
        {
            $mofInstances = ([Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($mofFile, 4)).Where({-not [string]::IsNullOrEmpty($_.ModuleName)})
            Write-Verbose -Message $($LocalizedData.FoundInstances -f $mofInstances.Count, $mofFile)
            $instances += $mofInstances
        }

        return $instances
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
        Tests resource states defined in a MOF file or local configuration.

    .PARAMETER Path
        Path to the folder containing many MOF files or path to a singular MOF file

    .EXAMPLE
        Test-DscMofConfig -Path C:\temp\file.mof
#>
function Test-DscMofConfig
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter()]
        [switch]
        $Force
    )

    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']
    $output = @()
    $allInstances = @()
    $lcmResourcesList = @()
    $lcm = Get-LcmConfig
    if ($lcm.Settings.Status -ne 'Idle' -and -not [string]::IsNullOrEmpty($lcm.Settings.ProcessId -and -not $Force))
    {
        Write-Warning -Message ($LocalizedData.LcmBusy -f $lcm.Settings.ProcessId)
        return
    }
    elseif ($lcm.Settings.Status -ne 'Idle' -and -not [string]::IsNullOrEmpty($lcm.Settings.ProcessId) -and $Force)
    {
        Write-Verbose -Message ($LocalizedData.ForceStop)
        Stop-Lcm -Force
    }
    else
    {
        $lcm.Settings.Status = 'Busy'
        $lcm.Settings.ProcessId = $PID
        $lcm | ConvertTo-Json -Depth 6 | Out-File -FilePath $MofConfigPath
    }

    foreach($configuration in $lcm.Configurations)
    {
        $lcmResourcesList += $configuration.Resources
        $allInstances += Get-MofCimInstances -Path $configuration.MofPath
    }

    $graph = @{}
    foreach ($mofInstance in $allInstances)
    {
        $graph[$mofInstance.ResourceId] = $mofInstance.DependsOn
    }

    $sorted = Invoke-SortDependencyGraph -Graph $graph
    $count = 0
    foreach ($resourceId in $sorted)
    {
        $instance = $allInstances.Where({$_.ResourceId -eq $resourceId}) | Select-Object -First 1
        $updateResource = $lcmResourcesList.Where({$_.ResourceID -eq $resourceId}) | Select-Object -First 1

        # Test that module is present. If not skip it.
        if (-not (Test-ModulePresent -ModuleName $instance.ModuleName -ModuleVersion $instance.ModuleVersion))
        {
            Write-Warning -Message ($LocalizedData.ModuleNotPresent -f $instance.ModuleName, $instance.ModuleVersion, $instance.ResourceId)
            if ($PSCmdlet.ParameterSetName -eq 'ByConfiguration')
            {
                $updateResource.Exception = ($LocalizedData.ModuleNotPresent -f $instance.ModuleName, $instance.ModuleVersion, $instance.ResourceId)
            }

            continue
        }

        $count++
        Write-Progress -Activity "$count of $($allInstances.Count), $(($count/$($allInstances.Count)).ToString('P'))" -Status "$($instance.ResourceId)" -PercentComplete ($count/$($allInstances.Count))
        
        $dependencySet = $false
        if ($null -ne $instance.DependsOn)
        {
            $skip = $false
            foreach ($dependencyId in $instance.DependsOn)
            {
                $lastSet = ($allInstances.Where({$_.ResourceId -eq $dependencyId}) | Select-Object -First 1).LastSet
                $dependencySet = -not [string]::IsNullOrEmpty($lastSet)
                if ($dependencySet)
                {
                    Write-Verbose -Message ($LocalizedData.DependencySet -f $resourceId, $dependencyId)
                }
                else
                {
                    $updateResource.Exception = ($LocalizedData.DependencyNotSet -f $resourceId, $dependencyId)
                    Write-Warning -Message ($LocalizedData.DependencyNotSet -f $resourceId, $dependencyId)
                    $skip = $true
                    break
                }
            }
        }

        if ($skip)
        {
            break
        }

        try
        {
            $resource = Convert-MofInstance -Instance $instance -IncludeProperties
        }
        catch
        {
            $updateResource.Exception = $_.Exception.Message
            Write-Warning -Message $_.Exception.Message
            continue
        }
        
        # Check for cancellation token
        $cancel = (Get-LcmConfig).Settings.Cancel
        if ($cancel -eq $true)
        {
            break
        }

        try
        {
            $result = Test-MofResource -Resource $resource -Verbose:$verboseSetting
            $updateResource.LastTest = Get-TimeStamp
            $updateResource.InDesiredState = $result

            # Check for cancellation token
            $cancel = (Get-LcmConfig).Settings.Cancel
            if ($cancel -eq $true)
            {
                break
            }
        }
        catch
        {
            $updateResource.Exception = $_.Exception.Message
            $updateResource.InDesiredState = $false
            Write-EventLogEntry -EntryMessage "$(`$LocalizedData.ExternalFunctionError)" -EntryArguments @($updateResource.ResourceId, "Test", $_.Exception.Message) -EntryType Error
        }
       
        $output += $result
    }

    # Update LCM status
    $lcm | ConvertTo-Json -Depth 6 | Out-File -FilePath $MofConfigPath
    Reset-Lcm

    Write-Progress -Completed -Activity 'Completed'
    return ($output -notcontains $false)
}

function Stop-Lcm
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [switch]
        $Force
    )

    $lcm = Get-LcmConfig
    if ($Force)
    {
        if (-not [string]::IsNullOrEmpty($lcm.Settings.ProcessId))
        {
            Stop-Process -Id $lcm.Settings.ProcessId -Force
            Reset-Lcm
        }
        else
        {
            Write-Warning -Message $LocalizedData.MissingProcessId
            Reset-Lcm
        }
    }
    else
    {
        $lcm.Settings.Cancel = $true
        $lcm | ConvertTo-Json -Depth 6 | Out-File $MofConfigPath

        if (-not [string]::IsNullOrEmpty($lcm.Settings.CancelTimeoutInSeconds))
        {
            $stopwatch = [System.Diagnostics.Stopwatch]::new()
            $stopwatch.Start()
            if ($null -ne (Get-Process -Id $lcm.Settings.ProcessId -ErrorAction 'SilentlyContinue'))
            {
                while ($stopwatch.Elapsed.TotalSeconds -lt $lcm.Settings.CancelTimeoutInSeconds)
                {
                    Start-Sleep -Seconds 1
                    if ($null -eq (Get-Process -Id $lcm.Settings.ProcessId -ErrorAction 'SilentlyContinue'))
                    {
                        break
                    }
                }
            }
            
            Stop-Process -Id $lcm.Settings.ProcessId -Force -ErrorAction 'SilentlyContinue'
            Reset-Lcm
        }
    }
}

function Reset-Lcm
{
    [CmdletBinding()]
    param()

    $lcm = Get-LcmConfig
    $lcm.Settings.Cancel = $false
    $lcm.Settings.Status = 'Idle'
    $lcm.Settings.ProcessId = $null

    $lcm | ConvertTo-Json -Depth 6 | Out-File $MofConfigPath
}

<#
    .SYNOPSIS
        Applies configuration from a MOF file or from stored JSON configuration.

    .PARAMETER Path
        Path to the folder containing many MOF files or path to a singular MOF file.

    .EXAMPLE
        Assert-DscMofConfig -Path C:\temp\file.mof
#>
function Assert-DscMofConfig
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter()]
        [switch]
        $Force
    )

    $verboseSetting = $PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -and $PSCmdlet.MyInvocation.BoundParameters['Verbose']
    Write-EventLogEntry -EntryMessage "Starting Portable LCM at {0}" -EntryArguments (Get-TimeStamp)
    New-Variable -Name 'DSCMachineStatus ' -Scope 'Global' -Value 0 -Force
    $lcm = Get-LcmConfig
    if ($lcm.Settings.Status -ne 'Idle' -and -not [string]::IsNullOrEmpty($lcm.Settings.ProcessId -and -not $Force))
    {
        Write-Warning -Message ($LocalizedData.LcmBusy -f $lcm.Settings.ProcessId)
        return
    }
    elseif ($lcm.Settings.Status -ne 'Idle' -and -not [string]::IsNullOrEmpty($lcm.Settings.ProcessId) -and $Force)
    {
        Write-Verbose -Message ($LocalizedData.ForceStop)
        Stop-Lcm -Force
    }
    else
    {
        $lcm.Settings.Status = 'Busy'
        $lcm.Settings.ProcessId = $PID
        $lcm | ConvertTo-Json -Depth 6 | Out-File -FilePath $MofConfigPath
    }

    try
    {
        $allInstances = @()
        $lcmResourcesList = @()
        foreach($configuration in $lcm.Configurations)
        {
            $lcmResourcesList += $configuration.Resources
            $allInstances += Get-MofCimInstances -Path $configuration.MofPath
        }    

        $graph = @{}
        foreach ($mofInstance in $allInstances)
        {
            $graph[$mofInstance.ResourceId] = $mofInstance.DependsOn
        }

        $sorted = Invoke-SortDependencyGraph -Graph $graph
        $count = 0
        foreach ($resourceId in $sorted)
        {
            $instance = $allInstances.Where({$_.ResourceId -eq $resourceId}) | Select-Object -First 1
            $updateResource = $lcmResourcesList.Where({$_.ResourceID -eq $resourceId}) | Select-Object -First 1
            
            # Test that module is present. If not skip it.
            if (-not (Test-ModulePresent -ModuleName $instance.ModuleName -ModuleVersion $instance.ModuleVersion))
            {
                Write-Warning -Message ($LocalizedData.ModuleNotPresent -f $instance.ModuleName, $instance.ModuleVersion, $instance.ResourceId)
                $updateResource.Exception = ($LocalizedData.ModuleNotPresent -f $instance.ModuleName, $instance.ModuleVersion, $instance.ResourceId)
                continue
            }

            $count++
            Write-Progress -Activity "$count of $($allInstances.Count), $(($count/$($allInstances.Count)).ToString('P'))" -Status "$($instance.ResourceId)" -PercentComplete ($count/$($allInstances.Count))
            
            # Check for dependencies.
            $skip = $false 
            if ($null -ne $instance.DependsOn)
            {
                foreach ($dependencyId in $instance.DependsOn)
                {
                    $dependencyInstance = $allInstances.Where({$_.ResourceId -eq $dependencyId}) | Select-Object -First 1
                    $dependencyInDesiredState = $dependencyInstance.InDesiredState
                    if ($dependencyInDesiredState)
                    {
                        Write-Verbose -Message ($LocalizedData.DependencyInDesiredState -f $resourceId, $dependencyId)
                    }
                    else
                    {
                        $updateResource.Exception = ($LocalizedData.DependencyNotInDesiredState -f $resourceId, $dependencyId)
                        Write-Warning -Message ($LocalizedData.DependencyNotInDesiredState -f $resourceId, $dependencyId)
                        $skip = $true
                        break
                    }
                }
            }
            
            if ($skip)
            {
                continue
            }

            try
            {
                $resource = Convert-MofInstance -Instance $instance -IncludeProperties
            }
            catch
            {
                $updateResource.Exception = $_.Exception.Message
                Write-Warning -Message $_.Exception.Message
                continue
            }

            # Check for cancellation token
            $cancel = (Get-LcmConfig).Settings.Cancel
            if ($cancel -eq $true)
            {
                break
            }

            # Test resource
            try
            {
                $result = Test-MofResource -Resource $resource -Verbose:$verboseSetting
                $updateResource.LastTest = Get-TimeStamp
                $updateResource.InDesiredState = $result

                # Check for cancellation token
                $cancel = (Get-LcmConfig).Settings.Cancel
                if ($cancel -eq $true)
                {
                    break
                }
            }
            catch
            {
                $updateResource.Exception = $_.Exception.Message
                $updateResource.InDesiredState = $false

                Write-EventLogEntry -EntryMessage "$($LocalizedData.ExternalFunctionError)" -EntryArguments @($updateResource.ResourceId,"Test", $_.Exception.Message) -EntryType Error
                continue
            }

            # Set resource
            if($resource.Mode -eq 'ApplyAndAutoCorrect' -and -not $result)
            {
                try
                {
                    $result = Set-MofResource -Resource $resource -Verbose:$verboseSetting
                    $updateResource.LastSet = Get-TimeStamp
                    $updateResource.Exception = ""
                }
                catch
                {
                    $updateResource.Exception = $_.Exception.Message
                    $updateResource.InDesiredState = $false
                }
            }
        }

        # Update LCM status
        $lcm | ConvertTo-Json -Depth 6 | Out-File -FilePath $MofConfigPath

        Write-Progress -Completed -Activity 'Completed'
        if ($global:DSCMachineStatus -eq 1 -and $lcm.Settings.AllowReboot -eq 'true')
        {
            Write-Verbose -Message $LocalizedData.Reboot
            Restart-Computer -Force -Delay 15
        }
        elseif($global:DSCMachineStatus -eq 1)
        {
            Write-Warning -Message $LocalizedData.RebootRequiredNotAllowed
        }
        else
        {
            Write-Verbose -Message $LocalizedData.RebootNotRequired
        }
    }
    finally
    {
        Reset-Lcm
    }
    Write-EventLogEntry -EntryMessage "Finishing Portable LCM at {0}" -EntryArguments (Get-TimeStamp)
}

function Get-LcmConfig
{
    $config = Get-Content -Path $MofConfigPath | ConvertFrom-Json -WarningAction 'SilentlyContinue'
    
    if (-not (Test-Path -Path $MofConfigPath) -or ($null -eq $config))
    {
        if (-not (Split-Path -Path $MofConfigPath -Parent))
        {
            $null = New-Item -Path (Split-Path -Path $MofConfigPath -Parent) -ItemType 'Directory'
        }

        $config = [ordered]@{
            Settings = @{
                AllowReboot           = $true
                Status                = 'Idle'
                ProcessId             = $null
                Cancel                = $false
                CancelTimeoutInSeconds = 300
            }
            Configurations = @()
        }

        $config | ConvertTo-Json | Out-File -FilePath $configPath
    }

    return Get-Content -Path $MofConfigPath | ConvertFrom-Json -WarningAction 'SilentlyContinue'
}

function Remove-DscMofConfig
{
    [CmdletBinding()]
    param()

    DynamicParam
    {
        $configurations = (Get-LcmConfig).Configurations
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
        $config = Get-LcmConfig
        $config.Configurations = $config.Configurations.Where({$_.Name -ne $Name})
        $config | ConvertTo-Json -Depth 6 | Out-File -FilePath $MofConfigPath
    }
    
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
        $configurations = (Get-LcmConfig).Configurations
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
        $overallStatus = @()
        $configurations = (Get-LcmConfig).Configurations
        if ($Name)
        {
            $configurations = $configurations.Where({$_.Name -eq $Name})
        }

        foreach ($configuration in $configurations)
        {
            if (-not $Full)
            {
                $properties = [ordered]@{
                    Name           = $configuration.Resources.MofFile | Select-Object -First 1
                    InDesiredState = ($configuration.Resources.InDesiredState -notcontains $false)
                }

                $overallStatus += New-Object -TypeName 'PSObject' -Property $properties
            }
            else
            {
                $overallStatus += $configuration
            }
        }

        return $overallStatus
    }
}

function Install-DscMofModules
{
    [CmdletBinding(DefaultParameterSetName = 'ByConfiguration')]
    param
    (
        [Parameter(Mandatory = $true, ParameterSetName = 'ByFile')]
        [ValidateScript({Test-Path -Path $_})]
        [string]
        $Path,

        [Parameter(ParameterSetName = 'ByFile')]
        [Parameter(ParameterSetName = 'ByConfiguration')]
        [ValidateSet('AllUsers', 'CurrentUser')]
        [string]
        $Scope = 'CurrentUser'
    )

    if ($PSCmdlet.ParameterSetName -eq 'ByFile')
    {
        if (-not [string]::IsNullOrEmpty($Path) -and (Test-Path -Path $Path -PathType 'Container'))
        {
            Write-Verbose -Message ($LocalizedData.ContainerDetected -f $Path)
            $configFiles = (Get-ChildItem -Path $Path -Include "*.mof" -Recurse).FullName
        }
        elseif (-not [string]::IsNullOrEmpty($Path))
        {
            $configFiles = $Path
        }
    }
    else
    {
        $configFiles = (Get-LcmConfig).Configurations.MofPath
    }

    $configResources = @()
    foreach ($configFile in $configFiles)
    {
        $configResources += Get-MofCimInstances -Path $configFile            
    }

    $moduleGroups = $configResources | Group-Object -Property 'ModuleName', 'ModuleVersion'
    foreach ($moduleGroup in $moduleGroups)
    {
        $group = $moduleGroup.Group
        $moduleName = $group.ModuleName | Select-Object -First 1
        $moduleVersion = $group.ModuleVersion | Select-Object -First 1
        if(-not (Test-ModulePresent -ModuleName $moduleName -ModuleVersion $moduleVersion))
        {
            Write-Verbose -Message $($LocalizedData.InstallModule -f $moduleName, $moduleVersion, $Scope)
            Install-Module -Name $moduleName -RequiredVersion $moduleVersion -Scope $Scope -Verbose:$false -Force
        }
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
        Publish-DscMofConfig -Path c:\temp\myMof.mof
#>
function Publish-DscMofConfig
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
    $mofConfig = Get-LcmConfig
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
        $mofFileName = [System.IO.Path]::GetFileName($mofFile)
        $mofName = [System.IO.Path]::GetFileNameWithoutExtension($mofFile)
        $mofCopyPath = Join-Path -Path (Split-Path -Path $MofConfigPath -Parent) -ChildPath $mofFileName
        $existingConfig = $configurations.Where({$_.Name -eq $mofName -and $_.MofPath -eq $mofCopyPath}) | Select-Object -First 1

        $properties = [ordered]@{
            Name          = $mofName
            Hash          = $hash
            MofPath       = $mofCopyPath
            Mode          = $Mode
            ResourceCount = $null
            Resources     = @()
        }

        $mofCopyExists = $false
        $mofCopyHash = $null
        if (Test-Path -Path $mofCopyPath)
        {
            $mofCopyExists = $true
            $mofCopyHash = (Get-FileHash -Path $mofCopyPath -Algorithm 'MD5').Hash
        }

        # MOF exists in config and matches all current values - skip it
        if ($existingConfig.Count -gt 0 -and $existingConfig.Hash -eq $hash -and $mofCopyExists -and $mofCopyHash -eq $hash -and $existingConfig.Mode -eq $Mode)
        {
            Write-Verbose -Message ($LocalizedData.MofExists -f $mofName, $hash)
            continue
        }

        Write-Verbose -Message ($LocalizedData.CopyMof -f $Path, $mofCopyPath)
        $null = Copy-Item -Path $mofFiles -Destination $mofCopyPath -Force
        
        $mofResources = Import-MofConfig -Path $mofFile -Mode $Mode
        $properties.ResourceCount = $mofResources.Count
        $properties.Resources += $mofResources
        if ($existingConfig.Count -gt 0)
        {
            $existingConfig.Hash = $hash
            $existingConfig.Mode = $Mode
        }
        else
        {
            $configurations += $properties
        }
    }

    $tempConfig = $mofConfig
    $tempConfig.Configurations = $configurations
    $tempConfig | ConvertTo-Json -Depth 6 -WarningAction 'SilentlyContinue' | Out-File -FilePath $MofConfigPath
}

Initialize-Lcm
Export-ModuleMember -Function Initialize-Lcm, Assert-DscMofConfig, Test-DscMofConfig, Get-MofCimInstances, Publish-DscMofConfig, Get-LcmConfig, Get-DscMofStatus, Install-DscMofModules, Remove-DscMofConfig, Get-MofInstanceProperties, Assert-DscCompliance, Stop-Lcm, *
