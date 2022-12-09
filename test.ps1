#get-mofresources -Path C:\repos\PortableLcm\powerstig.mof -Verbose
#Invoke-Mof -Path C:\test2\powerstig.mof -Operation Get -Verbose
#$result = Invoke-Mof -Path .\powerstig.mof -Operation Test -Verbose
#$result
#Assert-MofConfig -Path C:\repos\PortableLcm\Tests\Unit\Test.mof
#Assert-MofConfig -Path C:\repos\PortableLcm\powerstig.mof
#Test-DscMofConfig -Verbose
#Publish-DscMof -Path C:\Repos\PortableLcm\powerstig.mof -Verbose
#import-Module .\PortableLcm.psm1
#Get-DscMofStatus -Name powerstig -Detailed
#Install-DscMofModules -Scope CurrentUser -Verbose
#Assert-DscMofConfig -Verbose
#Get-DscMofStatus
#Get-MofResources -Path .\DomainController.mof
publish-DscMofConfig -Path C:\Repos\PortableLcm\DomainController.mof -Verbose
#Get-MofInstanceProperties -Instance $a
