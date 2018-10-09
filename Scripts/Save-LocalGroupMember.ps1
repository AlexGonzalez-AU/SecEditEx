#Requires -runasadmin

param (
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
    [string]$ComputerName = "",
    [Parameter(Mandatory=$false,ValueFromPipeline=$false,Position=1)]
    [string]$DirectoryPath = ""
)

function Get-LocalGroupMember {
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

            $localGroups = @(Get-WmiObject -Query "Select Name, Caption from Win32_Group Where LocalAccount = True")

            foreach ($localGroup in $localGroups) {
                $group = [ADSI]("WinNT://localhost/{0}" -f $localGroup.Name)
                $members = @($group.psbase.Invoke("Members"))
                $members | 
                    ForEach-Object {
                        $name = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null) 
        
                        try {
                            $obj = $name | ConvertTo-IdentityObject
                        }
                        catch {
                            $obj = New-Object -TypeName psobject -Property @{
                                NTAccountName = $name
                                Sid = ""
                            }
                        }
        
                        New-Object -TypeName psobject -Property @{
                            ComputerName = $env:COMPUTERNAME
                            LocalGroupName = $localGroup.Name
                            LocalGroupCaption = $localGroup.Caption
                            IdentitySid = $obj.Sid 
                            IdentityName = $obj.NTAccountName
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

if ($ComputerName.Length -gt 0) {
    $filename = "LocalGroupMembership_{0}_{1:yyyyMMddHHmmss}.csv" -f $ComputerName, (Get-Date)
}
else {
    $filename = "LocalGroupMembership_{0}_{1:yyyyMMddHHmmss}.csv" -f $env:COMPUTERNAME, (Get-Date)
}

if ($DirectoryPath.Length -gt 0) {
    Get-LocalGroupMember -ComputerName $ComputerName |
        Export-Csv -NoTypeInformation -Path (Join-Path -Path $DirectoryPath -ChildPath $filename)
}
else {
    Get-LocalGroupMember -ComputerName $ComputerName
}

<#
    PowerShell.exe -ExecutionPolicy bypass -File .\Save-LocalGroupMembership.ps1 -DirectoryPath .\
#>