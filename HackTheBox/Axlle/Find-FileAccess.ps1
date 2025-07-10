function Find-FileAccess {

    <#
        .SYNOPSIS
        Find directories and files with interesting permissions that may aid privilege escalation.
    
        .PARAMETER SearchPath
        The directory to recursively get ACLs for files and folders.
    
        .PARAMETER ItemType
        Specify preference for directories or files. Leave blank if both.
    
        .PARAMETER HiddenItems
        Specify if searching for file system items with the hidden attribute.
    
        .PARAMETER JsonOutput
        Specifies if the PowerShell objects should be converted to JSON output.
    
        .PARAMETER Depth
        Specify depth to recursively get items.
    
        .INPUTS
        None. 
        
        .OUTPUTS
        System.Object
    
        .EXAMPLE
        PS> .\Find-FileAccess.ps1
    
        .EXAMPLE
        PS> .\Find-FileAcces.ps1 -SearchPath 'C:\Users' -ItemType File
    
        .EXAMPLE
        PS> .\Find-FileAccess.ps1 -SearchPath 'C:\inetpub' -JsonOutput:$true
    
        .EXAMPLE
        PS> .\Find-FileAccess.ps1 -SearchPath 'C:\Windows\Temp' -Hidden:$true -Depth 1
    
        .EXAMPLE
        ...
        sudo impacket-smbserver -smb2support -username smb -password smb myshare .
    
        PS> New-SmbMapping -LocalPath Z: -RemotePath \\kali-ip-address\myshare -UserName smb -Password smb
    
        PS> $job = Start-Job -FilePath Z:\Find-FileAccess.ps1 -ArgumentList 'C:\Users', 'File', $false, $true, 2
        PS> $results = $job | Receive-Job
        PS> $results
    #>
    
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$SearchPath = $PWD.Path,
    
        [Parameter(Position = 1)]
        [ValidateSet('Directory', 'File')]
        [String]$ItemType,
    
        [Parameter(Position = 2)]
        [System.IO.FileAttributes[]]$Attributes,
    
        [Parameter(Position = 3)]
        [Bool]$JsonOutput = $false,
    
        [Parameter(Position = 4)]
        [Byte]$Depth
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
        $interestingAccess = $fileAccessRightsEnum | Where-Object {$_ -notlike 'Read*' -and $_ -notlike 'Synchronize' }
    }
    process {
        $gciParameters = @{
            Path = $SearchPath
            Recurse = $true
            ErrorAction = 'SilentlyContinue'
        }
        
        if ($Attributes) { $gciParameters.Add('Attributes', $Attributes) }
        if ($ItemType) {
            if ($ItemType -eq 'Directory') { $gciParameters.Add('Directory', $true) }
            else { $gciParameters.Add('File', $true) }
        }
        if ($Depth) { $gciParameters.Add('Depth', $Depth) }
        
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
                    if ($fileSystemRights | Where-Object { $_ -in $interestingAccess }) {
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
}
