#Requires -runasadmin

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

$fileName = ".\{0}_{1}_localgroups.tsv" -f  $env:COMPUTERNAME, (Get-Date).tostring("yyyyMMdd_HHmmss")
"MemberName MemberSid" | Out-File -Encoding ascii -FilePath $fileName -Force

$group =[ADSI]"WinNT://localhost/Administrators" 
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
            Sid = $name
        }
    }

    ("{0} {1}" -f $obj.NTAccountName, $obj.Sid) | Out-File -Encoding ascii -FilePath $fileName -Append
}

