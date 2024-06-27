<#
    .SYNOPSIS
    Find directories and files with interesting permissions that may aid privilege escalation.

    .PARAMETER SearchPath
    The directory to recursively get ACLs for files and folders.

    .PARAMETER JsonOutput
    Specifies if the PowerShell objects should be converted to JSON output.

    .INPUTS
    None. 
    
    .OUTPUTS
    System.Object

    .EXAMPLE
    PS> .\Find-FileAccess.ps1

    .EXAMPLE
    PS> .\Find-FileAcces.ps1 -SearchPath 'C:\Users'

    .EXAMPLE
    PS> .\Find-FileAccess.ps1 -SearchPath 'C:\inetpub' -JsonOutput
#>
[CmdletBinding()]
Param (
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [String]$SearchPath = $PWD.Path,

    [Parameter()]
    [Switch]$JsonOutput
)
begin {
    if (-not ((Get-Item $SearchPath) -is [System.IO.DirectoryInfo])) { 
        throw "Please proivde a valid directory"
    }
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUserName = $currentUser.Name
    $currentUserGroups = $currentUser.Groups
    $currentUserGroupNames = $currentUserGroups | ForEach-Object {
        $group = $_
        $group.Translate([System.Security.Principal.NTAccount]).Value
    }
    $whoamiGroups = whoami /groups /fo csv | ConvertFrom-Csv | Select-Object -Expand 'Group Name'
    $currentUserGroupNames += $whoamiGroups | Where-Object {$_ -notin $currentUserGroupNames}
    $fileAccessRightsEnum = [System.Enum]::GetValues([System.Security.AccessControl.FileSystemRights])
    $interestingAccess = $fileAccessRightsEnum | Where-Object {$_ -notlike 'Read*' }
    $interestingPermissions = @()
}
process {
    $acls = Get-ChildItem $SearchPath -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            Get-Acl $_.FullName
        }
        catch {
            # Silently ignore errors
        }
    }
    $interestingAcls = $acls | Where-Object {$_.Access.FileSystemRights -in $interestingAccess}
}
end {
    if ($interestingAcls) {
        $interestingAcls | ForEach-Object {
            $currentAcl = $_
            $identities = $currentAcl.Access.IdentityReference | ForEach-Object {$_.ToString()}
            $identities | ForEach-Object {
                if ($_ -in @($currentUserName, $currentUserGroupNames)) {
                    $interestingPermissions += $currentAcl | Select-Object @{
                        Name = 'Path'; Expression = {$_.Path -split '\:\:' | Select-Object -Index 1}
                    },
                    @{
                        Name = 'Permissions'; Expression = {$_.AccessToString}
                    } 
                }
            }
        }
        if ($interestingPermissions) {
            if ($jsonOutput) {
                $interestingPermissions | ConvertTo-Json -Depth 100
            }
            else {
                $interestingPermissions | Format-Table -AutoSize -Wrap
            }
        }
    }
    else {
        return
    }
}
