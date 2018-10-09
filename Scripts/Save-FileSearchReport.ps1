#Requires -runasadmin

param (
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
    [string]$ComputerName = "",
    [Parameter(Mandatory=$false,ValueFromPipeline=$false,Position=1)]
    [string]$DirectoryPath = ""
)

function New-FileSearchReport {
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
            robocopy c:\ a:\ /l *.kdb, *.kdbx /xj /e /ndl
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
    $filename = "FileSearchReport_{0}_{1:yyyyMMddHHmmss}.log" -f $ComputerName, (Get-Date)
}
else {
    $filename = "FileSearchReport_{0}_{1:yyyyMMddHHmmss}.log" -f $env:COMPUTERNAME, (Get-Date)
}

if ($DirectoryPath.Length -gt 0) {
    New-FileSearchReport -ComputerName $ComputerName |
        Out-File -FilePath (Join-Path -Path $DirectoryPath -ChildPath $filename)
}
else {
    New-FileSearchReport -ComputerName $ComputerName
}

<#
    PowerShell.exe -ExecutionPolicy bypass -File .\Save-FileSearchReport.ps1 -DirectoryPath .\
#>