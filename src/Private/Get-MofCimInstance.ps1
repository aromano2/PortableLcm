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
