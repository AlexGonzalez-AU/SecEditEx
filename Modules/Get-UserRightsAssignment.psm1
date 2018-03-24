function Get-UserRightsAssignment {
    [CmdletBinding()]
    
    param (
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [string]
        $ComputerName=""
    )

    begin {
    }
    process {
        Set-StrictMode -Version 2
        $ErrorActionPreference = 'Continue'

        $scriptBlock = {
            function ConvertTo-IdentityObject {
                [CmdletBinding()]
                
                param (
                    [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
                    [ValidateNotNullOrEmpty()]
                    $InputObject
                )
                
                begin {
                }
                    
                process {
                    $a_name = ""
                    if ($InputObject.GetType() -eq [Security.Principal.SecurityIdentifier]) {
                        $sid = $InputObject
                    }
                    elseif ($InputObject.GetType() -eq [string]) {
                        if ($InputObject.StartsWith("S-")) {
                            # S-1-5-21-2357950043-1680534590-2315089127-500
                            $sid = New-Object System.Security.Principal.SecurityIdentifier($InputObject)
                        }
                        else {
                            # Administrator
                            $accountName = New-Object System.Security.Principal.NTAccount($InputObject)     
                    
                            $eap = $ErrorActionPreference 
                            $ErrorActionPreference = "Stop"
                            try {
                                $sid = $accountName.Translate([System.Security.Principal.SecurityIdentifier])
                            }
                            catch {
                                $sid = ""
                                $a_name = $InputObject
                            }
                            $ErrorActionPreference = $eap                                       
                        }
                    }
                    elseif($InputObject.GetType() -eq [byte[]]) {
                        # @(1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 91, 118, 139, 140, 62, 236, 42, 100, 231, 116, 253, 137, 244, 1, 0, 0)
                        $sid = New-Object System.Security.Principal.SecurityIdentifier($InputObject, 0)
                    }
                    else {
                        Write-Error -Message ("The InputObject of type '{0}' cannot be converted." -f $InputObject.GetType())
                    }
            
                    $eap = $ErrorActionPreference 
                    $ErrorActionPreference = "Stop"
                    try {
                        $nTAccountName = $sid.Translate([System.Security.Principal.NTAccount]).Value
                    }
                    catch {
                        if ($a_name.length -eq 0) {
                            $nTAccountName = $sid.Value
                        }
                        else {
                            $nTAccountName = $a_name
                        }
                    }
                    $ErrorActionPreference = $eap

            
                    New-Object -TypeName psobject -Property @{
                        Sid = $sid
                        NTAccountName = $nTAccountName
                    }            
                }
                    
                end {
                }
            }    
            
            $userRightsAssignments = @(
                @{"Name" = "SeNetworkLogonRight";               "Description" = "Access this computer from the network";         "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeTrustedCredManAccessPrivilege";   "Description" = "Access Credential Manager as a trusted caller"; "OperatingSystem" = @("10","6"        )};
                @{"Name" = "SeTcbPrivilege";                    "Description" = "Act as part of the operating system";           "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeMachineAccountPrivilege";         "Description" = "Add workstations to domain";                    "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeIncreaseQuotaPrivilege";          "Description" = "Adjust memory quotas for a process";            "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeInteractiveLogonRight";           "Description" = "Allow log on locally";                          "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeRemoteInteractiveLogonRight";     "Description" = "Allow log on through Terminal Services";        "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeBackupPrivilege";                 "Description" = "Back up files and directories";                 "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeChangeNotifyPrivilege";           "Description" = "Bypass traverse checking";                      "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeSystemtimePrivilege";             "Description" = "Change the system time";                        "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeTimeZonePrivilege";               "Description" = "Change the time zone";                          "OperatingSystem" = @("10","6"        )};
                @{"Name" = "SeCreatePagefilePrivilege";         "Description" = "Create a pagefile";                             "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeCreateTokenPrivilege";            "Description" = "Create a token object";                         "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeCreateGlobalPrivilege";           "Description" = "Create global objects";                         "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeCreatePermanentPrivilege";        "Description" = "Create permanent shared objects";               "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeCreateSymbolicLinkPrivilege";     "Description" = "Create symbolic links";                         "OperatingSystem" = @("10","6"        )};
                @{"Name" = "SeDebugPrivilege";                  "Description" = "Debug programs";                                "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeDenyNetworkLogonRight";           "Description" = "Deny access to this computer from the network"; "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeDenyBatchLogonRight";             "Description" = "Deny log on as a batch job";                    "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeDenyServiceLogonRight";           "Description" = "Deny log on as a service";                      "OperatingSystem" = @("10","6","5","5")}; 
                @{"Name" = "SeDenyInteractiveLogonRight";       "Description" = "Deny log on locally";                           "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeDenyRemoteInteractiveLogonRight"; "Description" = "Deny log on through Terminal Services";         "OperatingSystem" = @("10","6","5","5")};
                @{"Name" = "SeEnableDelegationPrivilege";       "Description" = "Enable computer and user accounts to be trusted for delegation"; 
                                                                                                                                    "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeRemoteShutdownPrivilege";         "Description" = "Force shutdown from a remote system";           "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeAuditPrivilege";                  "Description" = "Generate security audits";                      "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeImpersonatePrivilege";            "Description" = "Impersonate a client after authentication";     "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeIncreaseWorkingSetPrivilege";     "Description" = "Increase a process working set";                "OperatingSystem" = @("10","6"        ) };
                @{"Name" = "SeIncreaseBasePriorityPrivilege";   "Description" = "Increase scheduling priority";                  "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeLoadDriverPrivilege";             "Description" = "Load and unload device drivers";                "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeLockMemoryPrivilege";             "Description" = "Lock pages in memory";                          "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeBatchLogonRight";                 "Description" = "Log on as a batch job";                         "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeServiceLogonRight";               "Description" = "Log on as a service";                           "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeSecurityPrivilege";               "Description" = "Manage auditing and security log";              "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeRelabelPrivilege";                "Description" = "Modify an object label";                        "OperatingSystem" = @("10","6"        ) };
                @{"Name" = "SeSystemEnvironmentPrivilege";      "Description" = "Modify firmware environment values";            "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeManageVolumePrivilege";           "Description" = "Perform volume maintenance tasks";              "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeProfileSingleProcessPrivilege";   "Description" = "Profile single process";                        "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeSystemProfilePrivilege";          "Description" = "Profile system performance";                    "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeUndockPrivilege";                 "Description" = "Remove computer from docking station";          "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeAssignPrimaryTokenPrivilege";     "Description" = "Replace a process level token";                 "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeRestorePrivilege";                "Description" = "Restore files and directories";                 "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeShutdownPrivilege";               "Description" = "Shut down the system";                          "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeSyncAgentPrivilege";              "Description" = "Synchronize directory service data";            "OperatingSystem" = @("10","6","5","5") };
                @{"Name" = "SeTakeOwnershipPrivilege";          "Description" = "Take ownership of files or other objects";      "OperatingSystem" = @("10","6","5","5") }
            )

            $operatingSystemVersion = Get-WmiObject -Query "SELECT Version FROM Win32_OperatingSystem" | Select-Object -ExpandProperty Version
            $operatingSystemVersion = $operatingSystemVersion.Split(".")[0] -join(".")

            $tmpFile = [io.path]::GetTempFileName()
            "<force file encoding>" | Out-File -Encoding ascii -FilePath $tmpFile
            [string]$msg = & ("{0}\System32\SecEdit.exe" -f $env:windir) /export /mergedpolicy /areas USER_RIGHTS /cfg ("{0}" -f $tmpFile)
            if ($LASTEXITCODE -eq 0) {
                $userRightsAssignment_GroupPolicy = Get-Content -Path $tmpFile
            }
            else {
                Write-Error -Message ("The program 'SecEdit.exe' used to collect user rights assignments did not complete successfully: {0}" -f $msg)
                break
            }
            $tmpFile | Remove-Item

            $tmpFile = [io.path]::GetTempFileName()
            "<force file encoding>" | Out-File -Encoding ascii -FilePath $tmpFile
            [string]$msg = & ("{0}\System32\SecEdit.exe" -f $env:windir) /export /areas USER_RIGHTS /cfg ("{0}" -f $tmpFile)
            if ($LASTEXITCODE -eq 0) {
                $userRightsAssignment_LocalPolicy = Get-Content -Path $tmpFile
            }
            else {
                Write-Error -Message ("The program 'SecEdit.exe' used to collect user rights assignments did not complete successfully: {0}" -f $msg)
                break
            }            
            $tmpFile | Remove-Item

            $userRightsAssignment_GroupPolicy = $userRightsAssignment_GroupPolicy | Select-String -Pattern "^Se+" | Select-Object -ExpandProperty Line
            $userRightsAssignment_LocalPolicy = $userRightsAssignment_LocalPolicy | Select-String -Pattern "^Se+" | Select-Object -ExpandProperty Line

            foreach ($userRigtsAssignment in ($userRightsAssignments | Where-Object {$_.OperatingSystem -Contains $operatingSystemVersion})) {
                if (($userRightsAssignment_LocalPolicy | ForEach-Object {$_.Split("=")[0].trim()}) -notcontains $userRigtsAssignment.Name) {
                    $userRightsAssignment_LocalPolicy += ("{0} = " -f $userRigtsAssignment.Name)
                }
            }

            foreach ($userRigtsAssignment in $userRightsAssignment_LocalPolicy) {
                if ($userRigtsAssignment.Split("=")[1].trim().length -lt 1) {
                    New-Object -TypeName psobject -Property @{
                        ComputerName = $env:COMPUTERNAME
                        UserRightsAssignment = $userRigtsAssignment.Split("=")[0].trim()
                        FriendlyName = $userRightsAssignments | Where-Object {$_.Name -eq $userRigtsAssignment.Split("=")[0].trim()} | ForEach-Object {$_.Description}
                        IdentitySid = ""
                        IdentityName = "" 
                        GroupPolicyControlled = (($userRightsAssignment_GroupPolicy | ForEach-Object {$_.Split("=")[0].trim()}) -contains $userRigtsAssignment.Split("=")[0].trim())
                    }
                }
                else {
                    foreach ($sid in $userRigtsAssignment.Split("=")[1].trim().split(",")) {
                        New-Object -TypeName psobject -Property @{
                            ComputerName = $env:COMPUTERNAME
                            UserRightsAssignment = $userRigtsAssignment.Split("=")[0].trim()
                            FriendlyName = $userRightsAssignments | Where-Object {$_.Name -eq $userRigtsAssignment.Split("=")[0].trim()} | ForEach-Object {$_.Description}
                            IdentitySid = $sid 
                            IdentityName = $sid.trim('*') | ConvertTo-IdentityObject | Select-Object -ExpandProperty NTAccountName
                            GroupPolicyControlled = (($userRightsAssignment_GroupPolicy | ForEach-Object {$_.Split("=")[0].trim()}) -contains $userRigtsAssignment.Split("=")[0].trim())
                        }                    
                    }
                }
            }
        }

        if ($ComputerName.Length -lt 1) {
            . $scriptBlock | Out-GridView
        }
        else {
            Invoke-Command -ComputerName $ComputerName -SessionOption (New-PSSessionOption -NoMachineProfile) -ScriptBlock $scriptBlock
        }
    }
    end {
    }
}