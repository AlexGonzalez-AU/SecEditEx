#Requires -runasadmin

function Get-UserRightsAssignment {
    [CmdletBinding()]
    
    param (
        [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
        [string]
        $ComputerName = ""
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
                    elseif ($InputObject.GetType() -eq [byte[]]) {
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
            
                    [byte[]]$bytes = New-Object 'byte[]' $sid.BinaryLength 
                    $sid.GetBinaryForm($bytes, 0)
            
                    New-Object -TypeName psobject -Property @{
                        Sid = $sid
                        NTAccountName = $nTAccountName 
                        ByteArray = $bytes
                        HexArray = $bytes | ForEach-Object { ("{0:x2}" -f $_) }
                        LDAPString = ($bytes | ForEach-Object { ("\{0:x2}" -f $_) }) -join("")
                    }            
                }
                    
                end {
                }
            }

            $userRightsAssignments = @{
                "SeNetworkLogonRight"               = "Access this computer from the network"  
                "SeTrustedCredManAccessPrivilege"   = "Access Credential Manager as a trusted caller"
                "SeTcbPrivilege"                    = "Act as part of the operating system"           
                "SeMachineAccountPrivilege"         = "Add workstations to domain"                    
                "SeIncreaseQuotaPrivilege"          = "Adjust memory quotas for a process"            
                "SeInteractiveLogonRight"           = "Allow log on locally"                          
                "SeRemoteInteractiveLogonRight"     = "Allow log on through Terminal Services"        
                "SeBackupPrivilege"                 = "Back up files and directories"                 
                "SeChangeNotifyPrivilege"           = "Bypass traverse checking"                      
                "SeSystemtimePrivilege"             = "Change the system time"                        
                "SeTimeZonePrivilege"               = "Change the time zone"                          
                "SeCreatePagefilePrivilege"         = "Create a pagefile"                             
                "SeCreateTokenPrivilege"            = "Create a token object"                         
                "SeCreateGlobalPrivilege"           = "Create global objects"                         
                "SeCreatePermanentPrivilege"        = "Create permanent shared objects"               
                "SeCreateSymbolicLinkPrivilege"     = "Create symbolic links"                         
                "SeDebugPrivilege"                  = "Debug programs"                                
                "SeDenyNetworkLogonRight"           = "Deny access to this computer from the network" 
                "SeDenyBatchLogonRight"             = "Deny log on as a batch job"                    
                "SeDenyServiceLogonRight"           = "Deny log on as a service"                       
                "SeDenyInteractiveLogonRight"       = "Deny log on locally"                           
                "SeDenyRemoteInteractiveLogonRight" = "Deny log on through Terminal Services"         
                "SeEnableDelegationPrivilege"       = "Enable computer and user accounts to be trusted for delegation" 
                "SeRemoteShutdownPrivilege"         = "Force shutdown from a remote system"      
                "SeAuditPrivilege"                  = "Generate security audits"                 
                "SeImpersonatePrivilege"            = "Impersonate a client after authentication"
                "SeIncreaseWorkingSetPrivilege"     = "Increase a process working set"           
                "SeIncreaseBasePriorityPrivilege"   = "Increase scheduling priority"             
                "SeLoadDriverPrivilege"             = "Load and unload device drivers"           
                "SeLockMemoryPrivilege"             = "Lock pages in memory"                     
                "SeBatchLogonRight"                 = "Log on as a batch job"                    
                "SeServiceLogonRight"               = "Log on as a service"                      
                "SeSecurityPrivilege"               = "Manage auditing and security log"         
                "SeRelabelPrivilege"                = "Modify an object label"                   
                "SeSystemEnvironmentPrivilege"      = "Modify firmware environment values"       
                "SeManageVolumePrivilege"           = "Perform volume maintenance tasks"         
                "SeProfileSingleProcessPrivilege"   = "Profile single process"                   
                "SeSystemProfilePrivilege"          = "Profile system performance"               
                "SeUndockPrivilege"                 = "Remove computer from docking station"     
                "SeAssignPrimaryTokenPrivilege"     = "Replace a process level token"            
                "SeRestorePrivilege"                = "Restore files and directories"            
                "SeShutdownPrivilege"               = "Shut down the system"                     
                "SeSyncAgentPrivilege"              = "Synchronize directory service data"       
                "SeTakeOwnershipPrivilege"          = "Take ownership of files or other objects"
            }

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

            foreach ($userRigtsAssignment in $userRightsAssignments.Keys) {
                if (($userRightsAssignment_LocalPolicy | ForEach-Object {$_.Split("=")[0].trim()}) -notcontains $userRigtsAssignment) {
                    $userRightsAssignment_LocalPolicy += ("{0} = " -f $userRigtsAssignment)
                }
            }

            foreach ($userRigtsAssignment in $userRightsAssignment_LocalPolicy) {
                if ($userRigtsAssignment.Split("=")[1].trim().length -lt 1) {
                    New-Object -TypeName psobject -Property @{
                        ComputerName = $env:COMPUTERNAME
                        UserRightsAssignment = $userRigtsAssignment.Split("=")[0].trim()
                        FriendlyName = $userRightsAssignments[$userRigtsAssignment.Split("=")[0].trim()]
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
                            FriendlyName = $userRightsAssignments[$userRigtsAssignment.Split("=")[0].trim()]
                            IdentitySid = $sid 
                            IdentityName = $sid.trim('*') | ConvertTo-IdentityObject | Select-Object -ExpandProperty NTAccountName
                            GroupPolicyControlled = (($userRightsAssignment_GroupPolicy | ForEach-Object {$_.Split("=")[0].trim()}) -contains $userRigtsAssignment.Split("=")[0].trim())
                        }                    
                    }
                }
            }
        }

        if ($ComputerName.Length -lt 1) {
            . $scriptBlock
        }
        else {
            Invoke-Command -ComputerName $ComputerName -SessionOption (New-PSSessionOption -NoMachineProfile) -ScriptBlock $scriptBlock
        }
    }

    end {
    }
}