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
