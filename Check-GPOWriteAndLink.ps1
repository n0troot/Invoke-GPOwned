$red = Write-Output "$([char]0x1b)[101m[-]$([char]0x1b)[0m"
$green = Write-Output "$([char]0x1b)[102m[+]$([char]0x1b)[0m"
$gray = Write-Output "$([char]0x1b)[100m[*]$([char]0x1b)[0m"
$domain = (Get-ADDomain).Forest
$domaindn = (Get-ADDomain).DistinguishedName
$GPOS = (Get-ChildItem \\$domain\SYSVOL\$domain\Policies | Select -ExpandProperty Name)

foreach ($GPO in $GPOS) {
    $gpoPath = "CN=$GPO,CN=Policies,CN=System,$domaindn"
    $checkgpo = (Get-Acl -Path "AD:$gpoPath").Access |
    Where-Object {
        $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty|WriteDacl|WriteOwner|GenericAll" -and
        ($_.IdentityReference -match "$env:USERNAME|Authenticated Users|Domain Users|Everyone")
    }
    if ($checkgpo) {
        Write-Output $green"$GPO is writable by $env:USERNAME"
    } else {
        Write-Output $red"$GPO is not writable by $env:USERNAME"
    }
}

Write-Output "`nChecking linked locations for writable GPOs..."
foreach ($GPO in $GPOS) {
    $gpoPath = "CN=$GPO,CN=Policies,CN=System,$domaindn"
    $checkgpo = (Get-Acl -Path "AD:$gpoPath").Access |
    Where-Object {
        $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty|WriteDacl|WriteOwner|GenericAll" -and
        ($_.IdentityReference -match "$env:USERNAME|Authenticated Users|Domain Users|Everyone")
    }
    if ($checkgpo) {
        $linkedLocations = @()
        
        # Get the GUID of the GPO
        $gpoGUID = (Get-ADObject -Identity $gpoPath -Properties Name).Name

        # Check domain root
        $domainRoot = [ADSI]"LDAP://$domaindn"
        if ($domainRoot.Properties["gPLink"].Value -match $gpoGUID) {
            $linkedLocations += "Domain Root ($domaindn)"
        }
        
        # Check OUs for this GPO
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = [ADSI]"LDAP://$domaindn"
        $searcher.Filter = "(&(objectClass=organizationalUnit)(gpLink=*$gpoGUID*))"
        $searcher.SearchScope = "Subtree"

        $results = $searcher.FindAll()
        
        foreach ($result in $results) {
            $ou = $result.GetDirectoryEntry()
            $linkedLocations += "OU: $($ou.distinguishedName)"
        }
        
        if ($linkedLocations.Count -gt 0) {
            Write-Output $green"GPO $GPO is linked to:"
            foreach ($location in $linkedLocations) {
                Write-Output "  - $location"
            }
        } else {
            Write-Output $gray"GPO $GPO is not linked to any locations (This might be incorrect, please verify manually)"
        }
    }
}
