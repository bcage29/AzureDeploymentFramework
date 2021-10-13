#
# ConfigurationData.psd1
#

@{
    AllNodes = @(
        @{
            NodeName                    = 'LocalHost'
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser        = $true

            DisksPresent                = @{DriveLetter = 'F'; DiskID = '2' }

            ServiceSetStopped           = 'ShellHWDetection'

            # IncludesAllSubfeatures
            WindowsFeaturePresent       = 'Web-Server', 'RSAT'

            # given this is for a lab and load test, just always pull down the latest App config
            DSCConfigurationMode        = 'ApplyAndAutoCorrect'

            DisableIEESC                = $True

            PowerShellModulesPresent2    = 'Az.Resources', 'Az.ManagedServiceIdentity', 'Az.Storage', 'Az.Compute'

            # PowerShellModulesPresentCustom2 = @(
            #     @{Name = 'Az'; RequiredVersion = '5.3.0' }
            #     @{Name = 'PSReadline'; RequiredVersion = '2.2.0' }
            #     @{Name = 'Az.Tools.Predictor'}
            # )

            # Single set of features
            WindowsFeatureSetPresent    = 'Web-Mgmt-Console'

            ServiceSetStarted           = 'WMSVC'

            DirectoryPresent            = @(
                'F:\Source\InstallLogs', 'F:\Repos', 'c:\program files\powershell\7', 
                'F:\API\EchoBot', 'F:\Build'
            )

            EnvironmentPathPresent2      = @(
                'F:\Source\Tools\SysInternals',
                'F:\Source\Tools\',
                'F:\Source\Tools\.vs-kubernetes\tools\helm\windows-amd64',
                'F:\Source\Tools\.vs-kubernetes\tools\kubectl',
                'F:\Source\Tools\.vs-kubernetes\tools\minikube\windows-amd64',
                'F:\Source\Tools\.vs-kubernetes\tools\draft\windows-amd64'
            )

            EnvironmentVarPresentVMSS    = @(
                @{
                    Name  = 'AzureSettings:MediaControlPlanePort'
                    BackendPortMatch = '8445'
                    Value = '{0}'
                },
                @{
                    Name  = 'AzureSettings:BotNotificationPort'
                    BackendPortMatch = '9441'
                    Value = '{0}'
                }
            )

            RegistryKeyPresent          = @(
                @{ 
                    # enable developer mode to sideload appx packages, including winget
                    Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock';
                    ValueName = 'AllowDevelopmentWithoutDevLicense'; ValueData = 1 ; ValueType = 'Dword'
                },

                @{ 
                    Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; 
                    ValueName = 'DontUsePowerShellOnWinX'; ValueData = 0 ; ValueType = 'Dword'
                },

                @{ 
                    Key = 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; 
                    ValueName = 'TaskbarGlomLevel'; ValueData = 1 ; ValueType = 'Dword'
                },

                @{ 
                    Key = 'HKEY_LOCAL_MACHINE\Software\OpenSSH';
                    ValueName = 'DefaultShell';	ValueData = 'C:\Program Files\PowerShell\7\pwsh.exe' ; ValueType = 'String'
                },

                @{ 
                    Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main';
                    ValueName = 'PreventFirstRunPage ';	ValueData = 1 ; ValueType = 'Dword'
                },

                @{ 
                    Key = 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WebManagement\Server';
                    ValueName = 'EnableRemoteManagement'; ValueData = 1 ; ValueType = 'Dword'
                }
            )

            LocalPolicyPresent2          = @(
                @{KeyValueName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarGlomLevel'; PolicyType = 'User'; Data = '1'; Type = 'DWord' }
                # @{KeyValueName = 'SOFTWARE\Microsoft\Internet Explorer\Main\NoProtectedModeBanner'; PolicyType = 'User'; Data = '1'; Type = 'DWord' },
                # @{KeyValueName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\EscDomains\contoso.com\*'; PolicyType = 'User'; Data = '2'; Type = 'DWord' },
                # @{KeyValueName = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\DontUsePowerShellOnWinX'; PolicyType = 'User'; Data = '0'; Type = 'DWord' },
                # @{KeyValueName = 'Software\Policies\Microsoft\Internet Explorer\Main\DisableFirstRunCustomize'; PolicyType = 'Machine'; Data = '1'; Type = 'DWord' }
            )

            # Blob copy with Managed Identity - Oauth2
            AZCOPYDSCDirPresentSource   = @(

                # @{
                #     sourcepathbloburi = 'https://{0}.blob.core.windows.net/source/psmodules/'
                #     destinationpath   = 'f:\source\psmodules\'
                # },

                # @{
                #     SourcePathBlobURI = 'https://{0}.blob.core.windows.net/source/Tools/'
                #     DestinationPath   = 'F:\Source\Tools\'
                # },

                @{
                    SourcePathBlobURI = 'https://{0}.blob.core.windows.net/source/GIT/'
                    DestinationPath   = 'F:\Source\GIT\'
                },

                # @{
                #     SourcePathBlobURI = 'https://{0}.blob.core.windows.net/source/PSCore/'
                #     DestinationPath   = 'F:\Source\PSCore\'
                # },

                # @{
                #    SourcePathBlobURI = 'https://{0}.blob.core.windows.net/source/DotNetCore/'
                #    DestinationPath   = 'F:\Source\DotNetCore\'
                # },

                @{
                    SourcePathBlobURI = 'https://{0}.blob.core.windows.net/source/dotnet/'
                    DestinationPath   = 'F:\Source\dotnet\'
                },

                @{
                    SourcePathBlobURI = 'https://{0}.blob.core.windows.net/source/VisualStudio/'
                    DestinationPath   = 'F:\Source\VisualStudio\'
                }
            )

            DirectoryPresentSource2      = @(

                @{
                    SourcePath      = 'F:\Source\PSModules\PackageManagement\'
                    DestinationPath = 'c:\program files\WindowsPowershell\Modules\PackageManagement\'
                },

                @{
                    SourcePath      = 'F:\Source\PSModules\PowerShellGet\'
                    DestinationPath = 'c:\program files\WindowsPowershell\Modules\PowerShellGet\'
                },

                @{
                    SourcePath      = 'F:\Source\PSModules\oh-my-posh\'
                    DestinationPath = 'c:\program files\WindowsPowershell\Modules\oh-my-posh\'
                },

                @{
                    SourcePath      = 'F:\Source\PSModules\PSReadline\'
                    DestinationPath = 'c:\program files\WindowsPowershell\Modules\PSReadline\'
                }

                # @{
                #     SourcePath      = 'F:\Source\Tools\profile.ps1'
                #     DestinationPath = 'c:\program files\powershell\7\profile.ps1'
                #     MatchSource     = $true
                # }

                # @{
                #     SourcePath      = 'F:\Source\Tools\profile.ps1'
                #     DestinationPath = 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'
                #     MatchSource     = $true
                # }
            )

            SoftwarePackagePresent      = @(

                # @{
                    # Name      = 'Microsoft Visual Studio Code'
                    # Path      = 'F:\Source\Tools\vscode\VSCodeSetup-x64-1.59.0.exe'
                #     ProductId = ''
                #     Arguments = '/silent /norestart'
                # },

                @{
                    Name      = 'Git'
                    Path      = 'F:\Source\GIT\Git-2.33.0.2-64-bit.exe'
                    ProductId = ''
                    Arguments = '/VERYSILENT'
                },

                # @{
                #     Name      = 'PowerShell 7-x64'
                #     Path      = 'F:\Source\PSCore\PowerShell-7.1.2-win-x64.msi'
                #     ProductId = '{357A3946-1572-4A21-9B60-4C7BD1BB9761}' # '{357A3946-1572-4A21-9B60-4C7BD1BB9761}'
                #     Arguments = 'ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 REGISTER_MANIFEST=1'  # ENABLE_PSREMOTING=1
                # }

                # @{
                #     Name      = 'Microsoft .NET Core SDK 3.1.407 (x64)'
                #     Path      = 'F:\Source\DotNetCore\dotnet-sdk-3.1.407-win-x64.exe'
                #     ProductId = ''
                #     Arguments = '/Install /quiet /norestart /log "F:\Source\InstallLogs\dotnet_install31407.txt"'
                # },

                # @{
                #     Name      = 'Microsoft .NET SDK 5.0.201 (x64)'
                #     Path      = 'F:\Source\DotNetCore\dotnet-sdk-5.0.201-win-x64.exe'
                #     ProductId = ''
                #     Arguments = '/Install /quiet /norestart /log "F:\Source\InstallLogs\dotnet_install50201.txt"'
                # },

                # @{
                #     Name      = 'Microsoft ASP.NET Core 5.0.4 Shared Framework (x64)'
                #     Path      = 'F:\Source\DotNetCore\aspnetcore-runtime-5.0.4-win-x64.exe'
                #     ProductId = ''
                #     Arguments = '/install /q /norestart'
                # },

                #6CD9E9ED-906D-4196-8DC3-F987D2F6615F - Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.29.30133
                #E699E009-1C3C-4E50-9B57-2B39F0954C7F - Microsoft Visual C++ 2019 X64 Additional Runtime - 14.29.30133

                @{
                    Name      = 'Microsoft Visual C++ 2019 X64 Minimum Runtime - 14.29.30133'
                    Path      = 'F:\Source\dotnet\VC_redist.x64.exe'
                    ProductId = '{6CD9E9ED-906D-4196-8DC3-F987D2F6615F}'
                    Arguments = '/install /q /norestart'
                }

                # Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
                @{  
                    Name      = 'Visual Studio Enterprise 2019'
                    Path      = 'F:\Source\VisualStudio\vs_enterprise__337181613.1633999746.exe'
                    ProductId = ''
                    Arguments = '--installPath F:\VisualStudio\2019\Enterprise --addProductLang en-US  --includeRecommended --config "F:\Source\VisualStudio\.vsconfig" --quiet --wait --norestart'
                }

                # @{
                #     Name      = 'IIS URL Rewrite Module 2'
                #     Path      = 'F:\Source\ISAPI\rewrite_amd64_en-US.msi'
                #     ProductId = '{9BCA2118-F753-4A1E-BCF3-5A820729965C}'
                #     Arguments = ''
                # }

                # @{
                #     Name      = 'Application Insights Status Monitor'
                #     Path      = 'F:\ApplicationInsights\ApplicationInsightsAgent.msi'
                #     ProductId = '{CBF2C62C-9537-4D8E-9754-92E54A0822D4}'
                #     Arguments = ''
                # }
            )

            # Blob copy with Managed Identity - Oauth2
            AppReleaseDSCAppPresent     = @(
                @{
                    ComponentName     = 'EchoBot'
                    SourcePathBlobURI = 'https://{0}.blob.core.windows.net/builds/'
                    DestinationPath   = 'F:\API\'
                    ValidateFileName  = 'CurrentBuild.txt'
                    BuildFileName     = 'F:\Build\EchoBot\componentBuild.json'
                    SleepTime         = '10'
                 }
            )

            NewServicePresent   = @(
                @{
                    Name        = 'EchoBotService'
                    Path        = 'F:\API\EchoBot\EchoBot.WindowsService.exe'
                    State       = 'Running'
                    StartupType = 'Automatic'
                    Description = 'Echo Bot Service'
                    #Cred        = 'OCRService'
                }
            )

            FWRules           = @(
                @{
                    Name      = "EchoBot"
                    LocalPort =  ('8445','9442')
                }
            )

            CertificatePortBinding = @(
                @{
                    Name     = "MediaControlPlane"
                    Port     = '8445'
                    AppId    = '{7c64d8a0-4cbb-42b6-85a8-de0e00f6a9c6}'
                    CertHash = '8b84dcdb49f5e408fe1a65c87c89acc29523793e'
                },
                @{
                    Name     = "BotCalling"
                    Port     = '9442'
                    AppId    = '{7c64d8a0-4cbb-42b6-85a8-de0e00f6a9c6}'
                    CertHash = '8b84dcdb49f5e408fe1a65c87c89acc29523793e'
                },
                @{
                    Name     = "BotNotification"
                    Port     = '9441'
                    AppId    = '{7c64d8a0-4cbb-42b6-85a8-de0e00f6a9c6}'
                    CertHash = '8b84dcdb49f5e408fe1a65c87c89acc29523793e'
                }
            )

            # Firewall $FWRule.Name
            # {
            #     Name      = $FWRule.Name
            #     Action    = 'Allow'
            #     Direction = 'Inbound'
            #     LocalPort = $FWRule.LocalPort
            #     Protocol  = 'TCP'
            # }

            # Add URL to hostfile for website testing
            HostHeaders2                 = @(
                @{HostName = '{0}-{1}-{2}-{3}-api01.haapp.net' ; ipAddress = '127.0.0.1' }
                @{HostName = '{0}-{1}-{2}-{3}-api02.haapp.net' ; ipAddress = '127.0.0.1' }
                @{HostName = '{0}-{1}-{2}-{3}-api03.haapp.net' ; ipAddress = '127.0.0.1' }
            )

            WebAppPoolPresent2           = @(
                @{Name = '{0}api' ; Version = ''; enable32BitAppOnWin64 = $false }
            )

            WebSiteAbsent2               = @(
                @{Name = 'Default Web Site'; PhysicalPath = 'C:\inetpub\wwwroot' }
            )

            WebSitePresent2              = @(
                @{Name = '{0}api' ; ApplicationPool = '{0}api' ;
                    PhysicalPath = 'F:\WEB\LogHeadersAPI'; BindingPresent = @(
                        @{HostHeader = '{0}-{1}-{2}-{3}-api01.haapp.net' ; IPAddress = '*' ; Name = '{0}api' ; Port = 80 ; Protocol = 'http' },
                        @{HostHeader = '{0}-{1}-{2}-{3}-api01.haapp.net' ; IPAddress = '*' ; Name = '{0}api' ; Port = 443 ; Protocol = 'https' },
                        @{HostHeader = '{0}-{1}-{2}-{3}-api02.haapp.net' ; IPAddress = '*' ; Name = '{0}api' ; Port = 80 ; Protocol = 'http' },
                        @{HostHeader = '{0}-{1}-{2}-{3}-api02.haapp.net' ; IPAddress = '*' ; Name = '{0}api' ; Port = 443 ; Protocol = 'https' },
                        @{HostHeader = '{0}-{1}-{2}-{3}-api03.haapp.net' ; IPAddress = '*' ; Name = '{0}api' ; Port = 80 ; Protocol = 'http' },
                        @{HostHeader = '{0}-{1}-{2}-{3}-api03.haapp.net' ; IPAddress = '*' ; Name = '{0}api' ; Port = 443 ; Protocol = 'https' },
                        @{HostHeader = '{0}-{1}-{2}-{3}-afd01-plb01.haapp.net' ; IPAddress = '*' ; Name = '{0}api' ; Port = 80 ; Protocol = 'http' },
                        @{HostHeader = '{0}-{1}-{2}-{3}-afd01-plb01.haapp.net' ; IPAddress = '*' ; Name = '{0}api' ; Port = 443 ; Protocol = 'https' },
                        @{HostHeader = '*' ; IPAddress = '*' ; Name = '*' ; Port = 80 ; Protocol = 'http' },
                        @{HostHeader = '*' ; IPAddress = '*' ; Name = '*' ; Port = 443 ; Protocol = 'https' }
                    )
                }
            )
        }
    )
}
