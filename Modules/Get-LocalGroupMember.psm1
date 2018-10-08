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
        if ($InputObject -is [Security.Principal.SecurityIdentifier]) {
            $sid = $InputObject
        }
        elseif ($InputObject -is [string]) {
            if ($InputObject.StartsWith("S-")) {
                # S-1-5-21-2357950043-1680534590-2315089127-500
                $sid = New-Object System.Security.Principal.SecurityIdentifier($InputObject)
            }
            else {
                # Administrator
                $accountName = New-Object System.Security.Principal.NTAccount($InputObject)     
                $sid = $accountName.Translate([System.Security.Principal.SecurityIdentifier])
            }
        }
        elseif ($InputObject -is [byte[]]) {
            # @(1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 91, 118, 139, 140, 62, 236, 42, 100, 231, 116, 253, 137, 244, 1, 0, 0)
            $sid = New-Object System.Security.Principal.SecurityIdentifier($InputObject, 0)
        }
        else {
            Write-Error -Message ("The InputObject of type '{0}' cannot be converted." -f $InputObject.GetType())
        }

        [byte[]]$bytes = New-Object 'byte[]' $sid.BinaryLength 
        $sid.GetBinaryForm($bytes, 0)

        New-Object -TypeName psobject -Property @{
            Sid = $sid
            NTAccountName = $sid.Translate([System.Security.Principal.NTAccount]).value
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

