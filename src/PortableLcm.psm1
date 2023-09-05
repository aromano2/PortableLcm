#requires -modules PSSQLite
using namespace System.Management.Automation

data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData -StringData @'
    CallExternalFunction = Calling {0}-TargetResource for resource '{1}'.
    ContainerDetected = Folder detected for path '{0}'.
    CopyMof = Copying '{0}' to {1}'.
    CredentialNotSupported = Credential property detected in resource '{0}'. Credentials are currently not supported. Skipping.
    DependencyDesiredState = Resource '{0}' dependency '{1}' is in desired state.
    DependencyNotInDesiredState = Resource '{0}' dependency '{1}' is not in desired state, skipping.
    DependencyNotSet = Resource '{0}' dependency '{1}' has not been set, skipping.
    DependencySet = Resource '{0}' dependency '{1}' has been set.
    ExternalFunctionError = Resource: {0}\n{1} Error: {2}.
    ForcedStop = Forcing compliance check in process {0} to end.
    FoundInstancesFromFile = Found {0} resources in file {1}.
    FoundInstancesFromDB = Found {0} resources in LCM DB.
    HashMatchesActiveOverLimit = More than one active MOF matching the hash '{0}' has been found. Potential issue in database.
    HashMismatch = Hash mismatch for MOF '{0}'. Current hash: '{1}'. New hash: '{2}'. Overwriting existing configuration.
    InstallModule = Installing module '{0}' version '{1}' to scope '{2}'.
    JobAdded = "Created new job '{0}' in {1} mode for MOF '{2}' (Id: {3}; Resources: {4})"
    LcmBusy = A compliance check is already in progress in process '{0}'.
    MandatoryParameter = Parameter '{0}' is mandatory.
    MissingProcessId = Unable to stop lcm process. Process ID is missing from the configuration.
    ModeMismatch = Mode mismatch for MOF '{0}'. Current mode: '{1}'. New mode: '{2}'. Overwriting existing configuration.
    ModulePresent = Module '{0}' with version '{1}' is present.
    ModuleNotPresent = Module '{0}-{1}' not present. Skipping resource '{2}'.
    MofDoesNotExist = Publishing new MOF config '{0}' with hash '{1}'.
    MofExists = MOF '{0}' with hash '{1}' already exists. Skipping.
    MonitorOnlyResource = Resource '{0}' is set to monitor only. Set will be skipped.
    NameMatchesActiveOverLimit = More than one active MOF matching the name '{0}' has been found. Potential issue in database. Manually deactive MOFs using Remove-DscMofConfig.
    NameMatchWillBeDeactivated = The MOF matching the name '{0}' will be deactivated.\r\n\tTarget Mof Hash is '{1}'.
    NameMatchesAlreadyDeactivated = All MOFs matching the name '{0}' have already been deactivated.
    ParametersValidated = Parameters for resource '{0}' passed validation.
    ParametersNotValidated = Parameters for resource '{0}' failed validation.
    Reboot = Rebooting to finish applying configuration.
    RebootNotRequired = A reboot is not required.
    RebootRequiredNotAllowed = A reboot is required to finish applying configuration but reboots are not allowed.
    ResourceInDesiredState = Resource '{0}' is in desired state.
    ResourceValidated = Resource '{0}' passed validation.
    ResourceNotInDesiredState = Resource '{0}' is not in desired state.
    StopWait = Waiting '{0}' seconds before shutting down.
    TestException = Exception thrown: {0}.
'@
}

data SqlQuery
{
    ConvertFrom-StringData @'
    GetActiveMofByHash = SELECT * FROM Mofs WHERE Hash='{0}' AND Active=1
    GetMofById = SELECT * FROM MOFs WHERE ID='{0}'
    GetAllMofs = SELECT * FROM Mofs
    GetAllActiveMofs = SELECT * FROM Mofs WHERE Active=1
    AddMof = INSERT INTO Mofs (Hash, Name, Mode) VALUES('{0}', '{1}', '{2}') RETURNING *
    ModifyMofMode = UPDATE Mofs SET Mode='{0}' WHERE ID='{1}' RETURNING *
    ModifyMofName = UPDATE Mofs SET Name='{0}' WHERE ID='{1}' RETURNING *
    DeactivateMof = UPDATE Mofs SET Active='0' WHERE ID='{0}' RETURNING *
    AddCimInstance = INSERT INTO CimInstances (ResourceId, Mof, Type, ModuleName, ModuleVersion, DependsOn, RawInstance) VALUES('{0}', '{1}', '{2}', '{3}', '{4}', '{5}', '{6}') RETURNING *
    GetAllCimInstancesFromMof = SELECT * FROM CimInstances WHERE Mof='{0}'
    GetCimInstance = SELECT RawInstance FROM CimInstances WHERE Mof='{0}' AND ResourceId='{1}'
    AddJob = INSERT INTO Jobs (Mof, Mode) VALUES('{0}', '{1}') RETURNING *
    FinishJob = UPDATE Jobs SET EndDate=(datetime('now')) WHERE ID='{0}' RETURNING *
    GetLastJobByMof = SELECT * FROM Jobs WHERE Mof='{0}' ORDER BY StartDate DESC LIMIT 1
    AddResult = INSERT INTO Results (Job, CimInstance, InDesiredState, Error, RunType) VALUES(@Job, @CimInstance, @InDesiredState, @Error, @RunType) RETURNING ID
    GetResultsForJob = SELECT Results.Job, CimInstances.*, Results.Error, coalesce(Results.InDesiredState,0) AS InDesiredState FROM CimInstances LEFT JOIN Results ON CimInstances.Id=Results.CimInstance AND Results.Job='{0}' WHERE CimInstances.MOF='{1}' ORDER BY 5 DESC, 1 DESC, 3
'@
}

data RunType
{
    ConvertFrom-StringData @'
    Test = 1
    Set = 2
'@
}

data LcmMode
{
    ConvertFrom-StringData @'
    ApplyAndMonitor = ApplyAndMonitor
    ApplyAndAutoCorrect = ApplyAndAutoCorrect
'@
}

data ResourceState
{
    ConvertFrom-StringData @'
    NotInDesiredState = 0
    InDesiredState = 1
'@
}

function Initialize-Lcm
{
    $osProgramData = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
    $configParentPath = Join-Path -Path $osProgramData -ChildPath 'PortableLcm'
    $configPath = Join-Path -Path $configParentPath -ChildPath 'config.json'
    $dbPath = Join-Path -Path $configParentPath -ChildPath 'config.sqlite'
    New-Variable -Name 'MofConfigPath' -Option 'ReadOnly' -Scope 'Global' -Value $configPath -Force
    New-Variable -Name 'MofDBPath' -Option 'ReadOnly' -Scope 'Global' -Value $dbPath -Force

    if (-not (Test-Path -Path $configPath))
    {
        if (-not (Test-Path -Path $configParentPath))
        {
            $null = New-Item -Path $configParentPath -ItemType 'Directory'
        }

        $config = [ordered]@{
            Settings = @{
                AllowReboot            = $true
                Status                 = 'Idle'
                ProcessId              = $null
                Cancel                 = $false
                CancelTimeoutInSeconds = 300
                PurgeHistoryAfter_Days = 14
                ProgressID             = 100
            }
        }

        Set-LcmConfig -Configuration $config
        Assert-MofDBConnection
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
        $this.ResourceId = $ResourceId
        $this.Type = $Type
        $this.ModuleName = $ModuleName
        $this.ModuleVersion = $ModuleVersion
        $this.Mode = $Mode
        $this.DependsOn = $DependsOn
    }

    Resource([string]$ResourceId, [string]$Type, [String]$ModuleName, [String]$ModuleVersion, [string]$Mode, [string]$DependsOn, [hashtable]$Properties)
    {
        $this.ResourceId = $ResourceId
        $this.Type = $Type
        $this.ModuleName = $ModuleName
        $this.ModuleVersion = $ModuleVersion
        $this.Mode = $Mode
        $this.DependsOn = $DependsOn
        $this.Properties = $Properties
    }
}

#region Helpers
function Get-TimeStamp
{
    return Get-Date -Format 'MM/dd/yy hh:mm:ss'
}

<#
    .SYNOPSIS
        Creates a dependency graph for a MOF

    .PARAMETER CimInstanceRows
        An array of CimInstances from the DB
#>
function New-DependencyGraph
{
    param
    (
        [Parameter(Mandatory = $true)]
        [array]
        $CimInstanceRows
    )

    $graph = @{}
    foreach ($instance in $CimInstanceRows)
    {
        $graph[$instance.ResourceId] = $instance.DependsOn
    }

    return $graph
}

function Confirm-InstanceDependencies
{
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $Instance,

        [Parameter(Mandatory = $true)]
        [string]
        $CurrentJob
    )

    #Get results of all instances from this run
    $jobResults = Invoke-Query -Query $SqlQuery.GetResultsForJob -QueryValues $CurrentJob, $Instance.Mof
    foreach ($dependency in $Instance.DependsOn)
    {
        $dependencyResult = $jobResults.Where({ $_.ResourceId -eq $dependency })
        $messageArgs = @($Instance.ResourceId, $dependency)
        if ($dependencyResult.InDesiredState -eq $ResourceState.InDesiredState)
        {
            Write-Verbose -Message ($LocalizedData.DependencyInDesiredState -f $messageArgs)
            return $true
        }
        else
        {
            Write-Warning -Message ($LocalizedData.DependencyNotInDesiredState -f $messageArgs)
            return $false
        }
    }
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
        [Object]
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
        [Object]
        $Instance
    )

    $filterProperties = @('ConfigurationName', 'ModuleName', 'ModuleVersion', 'SourceInfo', 'ResourceID', 'PSComputerName')
    $properties = ($Instance | Get-Member -MemberType Property).Where({ $filterProperties -notcontains $_.Name })

    $propertyTable = @{}
    foreach ($property in $properties)
    {
        $propertyTable[$($property.Name)] = $Instance.$($property.Name)

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
            if ($($metadata.Attributes | Where-Object { $_.TypeId.Name -eq 'ParameterAttribute' }).Mandatory -and -not $Values.$($key))
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

    $moduleMatches = Get-Module -Name $ModuleName -ListAvailable -Verbose:$false | Select-Object @{Name = 'Version'; Expression = { $_.Version.ToString() } }
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
        $dscResource = (Get-DscResource -Module $ModuleName -Name $ResourceName -Verbose:$false).Where({ $_.Version -eq $ModuleVersion }) | Select-Object -First 1
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
        $result = $false

        if ($Resource.ModuleName -eq 'nx' -and $IsLinux)
        {
            $pythonScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'exec_dsc.py'
            $arguments = ConvertTo-Json -InputObject $Resource.Properties -Compress
            $scriptResult = python $pythonScriptPath $Resource.Type 'Test' $arguments
            $matches = Select-String -InputObject $scriptResult -Pattern '(?<=Result:)(\d|-\d)'
            if ($matches.Matches.Count -gt 0)
            {
                $returnValue = [int]::Parse( $matches.Matches[0].Value)
                if ($returnValue -ge 0)
                {
                    $result = $true
                }
            }
            else
            {
                throw "Unable to determine state of resource."
            }
        }
        else
        {
            $tempFunction = Import-TempFunction -ModuleName $Resource.ModuleName -ModuleVersion $Resource.ModuleVersion -ResourceName $Resource.Type -Operation 'Test'
            if (Test-MandatoryParameter -Name $tempFunction.Name -Values $Resource.Properties)
            {
                Write-Verbose -Message ($LocalizedData.ParametersValidated -f $Resource.ResourceId)
                $splatProperties = Merge-MofResourceParameter -Name $tempFunction.Name -Values $Resource.Properties -Verbose:$verboseSetting
                Write-Verbose -Message ($LocalizedData.CallExternalFunction -f 'Test', $Resource.Type)
                try
                {
                    # Import the DSC Resource globally for nested functions
                    $dscResource = Import-Module -FullyQualifiedName $tempFunction.Path -Global -PassThru -Verbose:$false
                    $result = &"$($tempFunction.Name)" @splatProperties
                }
                catch
                {
                    #Write-Error -Exception $_.Exception -Message $_.Exception.Message
                    throw $_.Exception
                }
            }
            else
            {
                Write-Warning -Message ($LocalizedData.ParametersNotValidated -f $Resource.ResourceId)
            }

            try
            {
                $dscResource | Remove-Module -Force -Verbose:$false
            }
            catch
            {
                Write-Verbose -Message "Unable to remove module for $($dscResource.Name)"
            }
            
        }

        if ($result)
        {
            Write-Verbose -Message ($LocalizedData.ResourceInDesiredState -f $Resource.ResourceId)
            return $ResourceState.InDesiredState
        }
        else
        {
            Write-Warning -Message ($LocalizedData.ResourceNotInDesiredState -f $Resource.ResourceId)
            return $ResourceState.NotInDesiredState
        }
    }
    catch
    {
        throw $_.Exception
        return $ResourceState.NotInDesiredState
    }
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
        if ($Resource.ModuleName -eq 'nx' -and $IsLinux)
        {
            $pythonScriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'exec_dsc.py'
            $arguments = ConvertTo-Json -InputObject $Resource.Properties -Compress

            $Resource.LastSet = Get-TimeStamp
            $result = python $pythonScriptPath $Resource.Type 'Set' $arguments

            $matches = Select-String -InputObject $result -Pattern '(?<=Result:)(\d|-\d)'
            if ($matches.Matches.Count -gt 0)
            {
                $returnValue = [int]::Parse( $matches.Matches[0].Value)
                if ($returnValue -ge 0)
                {
                    $result = $true
                }
                else
                {
                    $result = $false
                }
            }
            else
            {
                Write-Warning -Message ($LocalizedData.ParametersNotValidated -f $Resource.ResourceId)
                $result = $false
            }
        }
        else
        {
            $tempFunction = Import-TempFunction -ModuleName $Resource.ModuleName -ModuleVersion $Resource.ModuleVersion -ResourceName $Resource.Type -Operation 'Set'
            if (Test-MandatoryParameter -Name $tempFunction.Name -Values $Resource.Properties)
            {
                Write-Verbose -Message ($LocalizedData.ParametersValidated -f $Resource.ResourceId)
                $splatProperties = Merge-MofResourceParameter -Name $tempFunction.Name -Values $Resource.Properties -Verbose:$verboseSetting
                Write-Verbose -Message ($LocalizedData.CallExternalFunction -f 'Set', $Resource.Type)

                try
                {
                    # Import the DSC Resource globally for nested functions
                    $dscResource = Import-Module -FullyQualifiedName $tempFunction.Path -Global -PassThru -Verbose:$false
                    &"$($tempFunction.Name)" @splatProperties | Out-Null
                    $result = $true
                }
                catch
                {
                    throw $_.Exception
                }
            }
            else
            {
                Write-Warning -Message ($LocalizedData.ParametersNotValidated -f $Resource.ResourceId)
                $result = $false
            }

            try
            {
                $dscResource | Remove-Module -Force -Verbose:$false
            }
            catch
            {
                Write-Verbose -Message "Unable to remove module for $($dscResource.Name)"
            }
        }

        if ($result)
        {
            Write-Verbose -Message ($LocalizedData.ResourceInDesiredState -f $Resource.ResourceId)
            return $ResourceState.InDesiredState
        }
        else
        {
            Write-Warning -Message ($LocalizedData.ResourceNotInDesiredState -f $Resource.ResourceId)
            return $ResourceState.NotInDesiredState
        }
    }
    catch
    {
        throw $_.Exception
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
            Category  = 8 # Pipeline Execution Details
            EventId   = 1000
            LogName   = "Windows PowerShell"
            Source    = "PowerShell"
            Message   = ($EntryMessage -f $EntryArguments)
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
        Imports CIM Instances from MOF and returns a Resource object for each instance.

    .PARAMETER MofPath
        Path to the MOF file.

    .PARAMETER Mode
        DSC mode to apply to the configuration, either ApplyAndAutoCorrect (default) or ApplyAndMonitor.

    .EXAMPLE
        Import-MofConfig -MofPath C:\test\test.mof -JsonPath c:\test\test.json
#>
function Import-MofConfig
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ })]
        [ValidateScript({ [System.IO.Path]::GetExtension($_) -eq '.mof' })]
        [string]
        $Path,

        #TODO: Convert to dynamic param that uses LcmMode.Keys for validation set
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

function Assert-MofDBConnection
{
    if (-not $script:MofDBConnection)
    {
        $script:MofDBConnection = New-SqliteConnection -DataSource $MofDBPath
        try
        {
            $tables = Invoke-SqliteQuery -SQLiteConnection $script:MofDBConnection -Query "PRAGMA table_info(MOFs)"
            if ($null -eq $tables)
            {
                $schema = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath "config.sqlite.sql") -Raw
                Invoke-SqliteQuery -SQLiteConnection $script:MofDBConnection -Query $schema
            }
        }
        catch
        {
            $script:MofDBConnection = $null
            throw $_.Exception
        }
    }
}

function Invoke-Query
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Query,

        [Parameter()]
        [string[]]
        $QueryValues,

        [Parameter()]
        [hashtable]
        $SqlParams,

        [Parameter()]
        [switch]
        $IgnoreErrors
    )

    Assert-MofDBConnection

    try
    {
        if ($null -eq $SqlParams)
        {
            if ($QueryValues.Count -gt 0)
            {
                $finalValues = @()
                foreach ($value in $QueryValues)
                {
                    $escaped = $value -replace "'", "''"
                    $escaped = $escaped -replace "`r", [char]13
                    $escaped = $escaped -replace "`n", [char]10
                    $finalValues += $escaped
                }
                $inflatedQuery = $Query -f $finalValues
            }
            else
            {
                $inflatedQuery = $Query
            }
            return Invoke-SqliteQuery -SQLiteConnection $script:MofDBConnection -Query $inflatedQuery
        }
        else
        {
            return Invoke-SqliteQuery -SQLiteConnection $script:MofDBConnection -Query $Query -SqlParameters $SqlParams
        }
    }
    catch
    {
        if (-not $IgnoreErrors)
        {
            throw $_.Exception
        }
    }
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
            [string]$leafName = $remaining[$key].Where( { $_ -ieq $leaf })
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

function Disable-ActiveMof
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object[]]
        $Mofs,

        [Parameter(Mandatory = $true)]
        [string]
        $MofName
    )

    if ($Mofs.Count -eq 1)
    {
        Write-Verbose -Message ($LocalizedData.NameMatchWillBeDeactivated -f $MofName, $Mofs[0].Hash)
        Invoke-Query -Query $SqlQuery.DeactivateMof -QueryValues $Mofs[0].Id
        return $true
    }
    elseif ($Mofs.Count -eq 0)
    {
        Write-Verbose -Message ($LocalizedData.NameMatchesAlreadyDeactivated -f $MofName)
        return $true
    }
    else
    {
        Write-Warning -Message ($LocalizedData.NameMatchesActiveOverLimit -f $MofName)
        return $false
    }
}

function Rename-ActiveMof
{
    param
    (
        [Parameter(Mandatory = $true)]
        [object[]]
        $Mofs,

        [Parameter(Mandatory = $true)]
        [string]
        $MofName
    )

    if ($Mofs.Count -eq 1)
    {
        # Change MOF name in DB to match new file name since the contents (hash) are equal
        Invoke-Query -Query $SqlQuery.ModifyMofName -QueryValues @($MofName, $Mofs[0].ID)
        return $true
    }
    elseif ($Mofs.Count -eq 0)
    {
        #TODO: Write verbose message
        return $true
    }
    else
    {
        # Hash is a unique column, we should not ever end up here
        Write-Error -Message ($LocalizedData.HashMatchesActiveOverLimit -f $Mofs[0].Hash) -Category InvalidData
    }

}

function Invoke-DscMofJob
{
    param
    (
        [Parameter(Mandatory = $true)]
        [hashtable]
        $MofConfiguration,

        [Parameter(Mandatory = $true)]
        [bool]
        $VerboseSetting,

        [Parameter()]
        [switch]
        $TestOnly,

        [Parameter()]
        [int]
        $ProgressID = 100
    )

    try
    {
        $allInstances = @()
        $output = @()
        $job = Invoke-Query -Query $SqlQuery.AddJob -QueryValues $MofConfiguration.ID, $MofConfiguration.Mode | Select-Object -First 1
        Write-Debug -Message ($LocalizedData.JobAdded -f $job.ID,  $MofConfiguration.Mode, $MofConfiguration.Name, $MofConfiguration.ID, $MofConfiguration.Resources.Count)
        $allInstances += Get-DbCimInstances -MofID $MofConfiguration.ID
        $graph = New-DependencyGraph -CimInstanceRows $allInstances
        $sorted = Invoke-SortDependencyGraph -Graph $graph

        $count = 0
        foreach ($resourceId in $sorted)
        {
            $instance = $allInstances.Where({ $_.ResourceId -eq $resourceId }) | Select-Object -First 1
            $resourceResults = [ordered]@{
                Job            = [int]$job.Id
                CimInstance    = $instance.Id
                InDesiredState = $ResourceState.NotInDesiredState
                Error          = $null
                RunType        = $RunType.Test
            }

            # Test that module is present. If not skip it.
            if (-not (Test-ModulePresent -ModuleName $instance.ModuleName -ModuleVersion $instance.ModuleVersion))
            {
                Write-Warning -Message ($LocalizedData.ModuleNotPresent -f $instance.ModuleName, $instance.ModuleVersion, $instance.ResourceId)
                $resourceResults.Error = ($LocalizedData.ModuleNotPresent -f $instance.ModuleName, $instance.ModuleVersion, $instance.ResourceId)
                Invoke-Query -Query $SqlQuery.AddResult -SqlParams $resourceResults | Out-Null
                continue
            }

            $count++
            Write-Progress -Id $ProgressID -Activity "$count of $($allInstances.Count), $(($count/$($allInstances.Count)).ToString('P'))" -Status "$($instance.ResourceId)" -PercentComplete (($count / $($allInstances.Count)) * 100)

            # Check for dependencies.
            if ($null -ne $instance.DependsOn)
            {
                if (Confirm-InstanceDependencies -Instance $instance -CurrentJob $job.Id)
                {
                    $resourceResults.Error = ($LocalizedData.DependencyNotInDesiredState -f $resourceId, $dependCheck)
                    Invoke-Query -Query $SqlQuery.AddResult -SqlParams $resourceResults | Out-Null
                    break
                }
            }

            try
            {
                $resource = Convert-MofInstance -Instance $instance.Inflated -Mode $configuration.Mode -IncludeProperties
            }
            catch
            {
                $resourceResults.Error = $_.Exception.Message
                Invoke-Query -Query $SqlQuery.AddResult -SqlParams $resourceResults | Out-Null
                Write-Warning -Message $_.Exception.Message
                continue
            }

            # Check for cancellation token
            $cancel = (Get-LcmConfig -SettingsOnly).Settings.Cancel
            if ($cancel -eq $true)
            {
                break
            }

            # Test resource
            try
            {
                $result = Test-MofResource -Resource $resource -Verbose:$VerboseSetting
                $resourceResults.InDesiredState = $result

                # Check for cancellation token
                $cancel = (Get-LcmConfig -SettingsOnly).Settings.Cancel
                if ($cancel -eq $true)
                {
                    break
                }
            }
            catch
            {
                $resourceResults.Error = $_.Exception.Message
                $resourceResults.InDesiredState = $ResourceState.NotInDesiredState
                Invoke-Query -Query $SqlQuery.AddResult -SqlParams $resourceResults | Out-Null

                Write-EventLogEntry -EntryMessage "$($LocalizedData.ExternalFunctionError)" -EntryArguments @($resource.ResourceId, "Test", $_.Exception.Message) -EntryType Error
                continue
            }

            # Set resource
            if (-not $TestOnly -and $resource.Mode -eq 'ApplyAndAutoCorrect' -and $result -ne $ResourceState.InDesiredState)
            {
                $resourceResults.RunType = $RunType.Set
                try
                {
                    $result = Set-MofResource -Resource $resource -Verbose:$verboseSetting
                    $resourceResults.InDesiredState = $result
                    #TODO: Should we test again after setting to validate state?

                    $cancel = (Get-LcmConfig -SettingsOnly).Settings.Cancel
                    if ($cancel -eq $true)
                    {
                        break
                    }
                }
                catch
                {
                    $resourceResults.Error = $_.Exception.Message
                    $resourceResults.InDesiredState = $ResourceState.NotInDesiredState
                }
            }
            Invoke-Query -Query $SqlQuery.AddResult -SqlParams $resourceResults | Out-Null
            $output += $result
        }

        Invoke-Query -Query $SqlQuery.FinishJob -QueryValues $job.Id | Out-Null
    }
    catch
    {
        Write-EventLogEntry -EntryMessage 'Error with LCM Job {0}`r`n{1}' -EntryArguments @($Job.ID, $_.Exception.Message) -EntryType Error
        throw $_
    }

    return $output
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
        [ValidateScript({ Test-Path -Path $_ })]
        [string]
        $Path,

        #TODO: Convert to dynamic param that uses LcmMode.Keys for validation set
        [Parameter()]
        [ValidateSet('ApplyAndAutoCorrect', 'ApplyAndMonitor')]
        [string]
        $Mode = 'ApplyAndAutoCorrect'
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
            $mofInstances = ([Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ImportInstances($mofFile, 4)).Where({ -not [string]::IsNullOrEmpty($_.ModuleName) })
            Write-Verbose -Message $($LocalizedData.FoundInstancesFromFile -f $mofInstances.Count, $mofFile)

            $mofHash = (Get-FileHash -Path $mofFile -Algorithm SHA256).Hash
            $mofName = Split-Path -Path $mofFile -Leaf

            $mofRow = Invoke-Query -IgnoreErrors -Query $SqlQuery.GetActiveMofByHash -QueryValues $mofHash

            if ($null -eq $mofRow)
            {
                $mofRow = Invoke-Query -Query $SqlQuery.AddMof -QueryValues $mofHash, $mofName, $Mode
            }

            foreach ($instance in $mofInstances)
            {
                if ($null -eq (Invoke-Query -IgnoreErrors -Query $SqlQuery.GetCimInstance -QueryValues $mofRow.ID, $instance.ResourceId))
                {
                    if ($instance.ResourceID -match '(?<=\[).*?(?=\])')
                    {
                        $type = $Matches[0]
                    }

                    $instanceSerialized = ([PSSerializer]::Serialize($instance, 100)) #-replace ("'", "''")

                    $queryArgs = @(
                        $instance.ResourceID, $mofRow.ID, $type
                        $instance.ModuleName, $instance.ModuleVersion
                        $instance.DependsOn, $instanceSerialized
                    )
                    Invoke-Query -Query $SqlQuery.AddCimInstance -QueryValues $queryArgs | Out-Null
                }
            }

            $instances += $mofInstances
        }
    }
    catch
    {
        throw $_.Exception
    }
    finally
    {
        [Microsoft.PowerShell.DesiredStateConfiguration.Internal.DscClassCache]::ClearCache()
    }

    return $instances
}

function Get-DbCimInstances
{
    param
    (
        [Parameter(Mandatory = $true)]
        [int]
        $MofID
    )

    Assert-MofDBConnection
    try
    {
        $rawInstances = Invoke-Query -Query $SqlQuery.GetAllCimInstancesFromMof -QueryValues $MofID
        Write-Verbose -Message $($LocalizedData.FoundInstancesFromDB -f $rawInstances.Count)
        foreach ($rawInstance in $rawInstances)
        {
            if ([string]::IsNullOrEmpty($rawInstance.DependsOn))
            {
                $rawInstance.DependsOn = $null
            }
            $rawInstance | Add-Member -MemberType NoteProperty -Name Inflated -Value $([PSSerializer]::Deserialize([System.Text.Encoding]::ASCII.GetString($rawInstance.RawInstance)))
        }
    }
    catch
    {
        throw $_.Exception
    }
    return $rawInstances
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
    Write-EventLogEntry -EntryMessage "Starting Portable LCM at {0}" -EntryArguments (Get-TimeStamp)
    $output = @()
    $lcm = Get-LcmConfig -ActiveOnly
    if ($lcm.Settings.Status -ne 'Idle' -and -not [string]::IsNullOrEmpty($lcm.Settings.ProcessId -and -not $Force))
    {
        Write-Warning -Message ($LocalizedData.LcmBusy -f $lcm.Settings.ProcessId)
        return
    }
    elseif ($lcm.Settings.Status -ne 'Idle' -and -not [string]::IsNullOrEmpty($lcm.Settings.ProcessId) -and $Force)
    {
        Write-Verbose -Message ($LocalizedData.ForceStop -f $lcm.Settings.ProcessId)
        Stop-Lcm -Force
    }
    else
    {
        $lcm.Settings.Status = 'Busy'
        $lcm.Settings.ProcessId = $PID
        Set-LcmConfig -Configuration $lcm
    }

    foreach ($configuration in $lcm.Configurations)
    {
        $output = Invoke-DscMofJob -MofConfiguration $configuration -VerboseSetting $verboseSetting -TestOnly
    }

    Reset-Lcm
    Write-Progress -Id $lcm.Settings.ProgressID -Completed -Activity 'Completed'
    Write-EventLogEntry -EntryMessage "Finishing Portable LCM at {0}" -EntryArguments (Get-TimeStamp)
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

    $lcm = Get-LcmConfig -SettingsOnly
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
        Set-LcmConfig -Configuration $lcm

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

    $lcm = Get-LcmConfig -SettingsOnly
    $lcm.Settings.Cancel = $false
    $lcm.Settings.Status = 'Idle'
    $lcm.Settings.ProcessId = $null

    Set-LcmConfig $lcm
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
    $lcm = Get-LcmConfig -ActiveOnly
    if ($lcm.Settings.Status -ne 'Idle' -and -not [string]::IsNullOrEmpty($lcm.Settings.ProcessId) -and -not $Force)
    {
        Write-Warning -Message ($LocalizedData.LcmBusy -f $lcm.Settings.ProcessId)
        return
    }
    elseif ($lcm.Settings.Status -ne 'Idle' -and -not [string]::IsNullOrEmpty($lcm.Settings.ProcessId) -and $Force)
    {
        Write-Verbose -Message ($LocalizedData.ForceStop -f $lcm.Settings.ProcessId)
        Stop-Lcm -Force
    }
    else
    {
        $lcm.Settings.Status = 'Busy'
        $lcm.Settings.ProcessId = $PID
        Set-LcmConfig -Configuration $lcm
    }

    foreach ($configuration in $lcm.Configurations)
    {
        $result = Invoke-DscMofJob -MofConfiguration $configuration -VerboseSetting $verboseSetting
    }

    Write-Progress -Id $lcm.Settings.ProgressID -Completed -Activity 'Completed'

    if ($global:DSCMachineStatus -eq 1 -and $lcm.Settings.AllowReboot -eq 'true')
    {
        Write-Verbose -Message $LocalizedData.Reboot
        Restart-Computer -Force -Delay 15
    }
    elseif ($global:DSCMachineStatus -eq 1)
    {
        Write-Warning -Message $LocalizedData.RebootRequiredNotAllowed
    }
    else
    {
        Write-Verbose -Message $LocalizedData.RebootNotRequired
    }

    Reset-Lcm
    Write-EventLogEntry -EntryMessage "Finishing Portable LCM at {0}" -EntryArguments (Get-TimeStamp)
}

function Get-LcmConfig
{
    param
    (
        [Parameter()]
        [switch]
        $SettingsOnly,

        [Parameter()]
        [switch]
        $ActiveOnly,

        [Parameter()]
        [switch]
        $FullStatus
    )
    #TODO: Enforce the purge of data older than PurgeHistory
    $config = Get-Content -Path $MofConfigPath | ConvertFrom-Json -WarningAction 'SilentlyContinue'

    if (-not (Test-Path -Path $MofConfigPath) -or ($null -eq $config))
    {
        if (-not (Split-Path -Path $MofConfigPath -Parent))
        {
            $null = New-Item -Path (Split-Path -Path $MofConfigPath -Parent) -ItemType 'Directory'
        }

        $config = [ordered]@{
            Settings = @{
                AllowReboot            = $true
                Status                 = 'Idle'
                ProcessId              = $null
                Cancel                 = $false
                CancelTimeoutInSeconds = 300
                PurgeHistoryAfter_Days = 14
                ProgressID             = 100
            }
        }

        Set-LcmConfig -Configuration $config
        # Get the config back as a PSObject
        $config = Get-Content -Path $MofConfigPath | ConvertFrom-Json -WarningAction 'SilentlyContinue'
    }

    if (-not $SettingsOnly)
    {
        $config | Add-Member -MemberType NoteProperty -Name Configurations -Value @()

        if ($ActiveOnly)
        {
            $mofs = Invoke-Query -Query $SqlQuery.GetAllActiveMofs
        }
        else
        {
            $mofs = Invoke-Query -Query $SqlQuery.GetAllMofs
        }

        foreach ($mof in $mofs)
        {
            if ($ActiveOnly -and -not $mof.Active)
            {
                continue
            }

            $mofConfig = @{
                Id        = $mof.ID
                Name      = $mof.Name
                Hash      = $mof.Hash
                Mode      = $mof.Mode
                Active    = $mof.Active
                Resources = @()
            }

            if ($FullStatus)
            {
                $mofResources = Invoke-Query -Query $SqlQuery.GetAllCimInstancesFromMof -QueryValues $mof.ID
                $job = Invoke-Query -Query $SqlQuery.GetLastJobByMof -QueryValues $mof.ID
                if ($null -eq $job -or $job.Count -eq 0)
                {
                    foreach ($resource in $mofResources)
                    {
                        $resultResource = [Resource]::new(
                            $resource.ResourceId,
                            $resource.Type,
                            $resource.ModuleName,
                            $resource.ModuleVersion,
                            $mof.Mode,
                            "$($resource.DependsOn)"
                        )
                        $resultResource.InDesiredState = $false
                        $mofConfig.Resources += $resultResource
                        $mofConfig.LastJob = "None"
                    }
                }
                else
                {
                    $jobResults = Invoke-Query -Query $SqlQuery.GetResultsForJob -QueryValues $job.ID, $Mof.ID
                    foreach ($result in $jobResults)
                    {
                        $resultResource = [Resource]::new(
                            $result.ResourceId,
                            $result.Type,
                            $result.ModuleName,
                            $result.ModuleVersion,
                            $mof.Mode,
                            "$($result.DependsOn)"
                        )
                        $resultResource.InDesiredState = ($result.InDesiredState -eq $ResourceState.InDesiredState)
                        #TODO: Populate last set/test
                        #$resultResource.LastSet =
                        #$resultResource.LastTest =
                        $resultResource.Exception = $result.Error
                        $mofConfig.Resources += $resultResource
                        $mofConfig.LastJob = $job.ID
                    }
                }
            }

            $config.Configurations += $mofConfig
        }
    }

    return $config
}

function Set-LcmConfig
{
    param
    (
        [Parameter(Mandatory = $true)]
        $Configuration
    )

    $settings = @{
        Settings = $Configuration.Settings
    }
    $settings | ConvertTo-Json -Depth 6 | Out-File -FilePath $MofConfigPath
}

# SPIKE: Do we need this function still? Has Disable-ActiveMof taken it's place?
function Remove-DscMofConfig
{
    [CmdletBinding()]
    param()
    #TODO: Get by Hash
    DynamicParam
    {
        $configurations = (Get-LcmConfig).Configurations
        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.Mandatory = $false
        $attribute.HelpMessage = "Name of the MOF"
        $attributeCollection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
        $attributeCollection.Add($attribute)

        $validateSet = New-Object System.Management.Automation.ValidateSetAttribute($configurations.Name)
        $attributeCollection.Add($validateSet)

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
        if ([string]::IsNullOrEmpty($Name))
        {
            return
        }

        $mof = (Invoke-Query -Query -$SqlQuery.GetMofByName -QueryValues $Name).Where({ $_.Active })
        if ($mof.Count -ne 1)
        {
            throw "Found {0} active MOFs, expected 1."
        }

        return (Invoke-Query -Query $SqlQuery.DeactivateMof -QueryValues $mof.ID)
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
    #FIXME: Get state from DB
    #TODO: Get by Hash
    DynamicParam
    {
        $configurations = (Get-LcmConfig).Configurations
        $attribute = New-Object System.Management.Automation.ParameterAttribute
        $attribute.Mandatory = $false
        $attribute.HelpMessage = "Name of the MOF"
        $attributeCollection = new-object System.Collections.ObjectModel.Collection[System.Attribute]
        $attributeCollection.Add($attribute)

        $validateSet = New-Object System.Management.Automation.ValidateSetAttribute($configurations.Name)
        $attributeCollection.Add($validateSet)

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
        $configurations = (Get-LcmConfig -ActiveOnly -FullStatus).Configurations

        if ($Name)
        {
            $configurations = $configurations.Where({ $_.Name -eq $Name })
        }

        foreach ($configuration in $configurations)
        {
            if (-not $Full)
            {
                foreach ($resource in $configuration.Resources)
                {
                    $properties = [ordered]@{
                        Name           = $resource.ResourceId
                        InDesiredState = $resource.InDesiredState
                        LastError      = $resource.Exception
                    }

                    $overallStatus += New-Object -TypeName 'PSObject' -Property $properties
                }
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
        [ValidateScript({ Test-Path -Path $_ })]
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
        $configFiles = (Get-LcmConfig -ActiveOnly).Configurations.MofPath
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
        if (-not (Test-ModulePresent -ModuleName $moduleName -ModuleVersion $moduleVersion))
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
        [ValidateScript({ Test-Path -Path $_ })]
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
    #TODO: Replace all insert queries with a bulk/transactional query to prevent partial publishing

    foreach ($mofFile in $mofFiles)
    {
        $hash = (Get-FileHash -Path $mofFile -Algorithm 'SHA256').Hash
        $mofFileName = [System.IO.Path]::GetFileName($mofFile)
        $mofName = [System.IO.Path]::GetFileNameWithoutExtension($mofFile)
        $mofCopyPath = Join-Path -Path (Split-Path -Path $MofConfigPath -Parent) -ChildPath $mofFileName

        $nameMatches = $configurations.Where({ $_.Name -eq $mofFileName })
        $hashMatches = $configurations.Where({ $_.Hash -eq $hash })

        if ($nameMatches.Count -gt 0 -and $hashMatches.Count -eq 0)
        {
            $activeMatches = @($nameMatches.Where({ $_.Active }))
            if (-not (Disable-ActiveMof -Mofs $activeMatches -MofName $mofName))
            {
                Write-Verbose -Message ($LocalizedData.MofExists -f $mofName, $hash)
                continue
            }
        }
        elseif ($nameMatches.Count -eq 0 -and $hashMatches.Count -gt 0)
        {
            $activeMatches = @($hashMatches.Where({ $_.Active }))
            Rename-ActiveMof -Mofs $activeMatches -MofName $mofName
            continue
        }
        elseif ($nameMatches.Count -gt 0 -and $hashMatches.Count -gt 0)
        {
            $activeNameMatches = $nameMatches.Where({ $_.Active })
            $activeHashMatches = $hashMatches.Where({ $_.Active })

            $sameMatch = $activeNameMatches.Count -eq 1 -and $activeHashMatches.Count -eq 1
            $sameMatch = $sameMatch -and $activeNameMatches[0].ID -eq $activeHashMatches[0].ID

            if ($sameMatch)
            {
                $match = $activeNameMatches[0]
                if ($match.Mode -ne $Mode)
                {

                    Invoke-Query -Query $SqlQuery.ModifyMofMode -QueryValues @($Mode, $match.ID)
                }
                else
                {
                    Write-Verbose -Message ($LocalizedData.MofExists -f $($mofName, $hash))
                }
                continue
            }
            else
            {
                Disable-ActiveMof -Mofs $activeNameMatches -MofName $mofName
                Rename-ActiveMof -Mofs $activeHashMatches -MofName $mofName
            }
        }

        Write-Verbose -Message ($LocalizedData.CopyMof -f $Path, $mofCopyPath)
        $null = Copy-Item -Path $mofFiles -Destination $mofCopyPath -Force

        $mofResources = Import-MofConfig -Path $mofFile -Mode $Mode
    }
}

Initialize-Lcm
Export-ModuleMember -Function Initialize-Lcm, Assert-DscMofConfig, Test-DscMofConfig, Get-MofCimInstances, Publish-DscMofConfig, Get-LcmConfig, Get-DscMofStatus, Install-DscMofModules, Remove-DscMofConfig, Get-MofInstanceProperties, Assert-DscCompliance, Stop-Lcm, *
