function Check-GPOWriteAndLink {
    param (
        [Parameter(Mandatory=$false)]
        [switch]$All,
        
        [Parameter(Mandatory=$false)]
        [string]$GPO
    )

    $red = "$([char]0x1b)[101m[-]$([char]0x1b)[0m"
    $green = "$([char]0x1b)[102m[+]$([char]0x1b)[0m"
    $gray = "$([char]0x1b)[100m[*]$([char]0x1b)[0m"
    $domain = (Get-ADDomain).Forest
    $domaindn = (Get-ADDomain).DistinguishedName

    # Function to resolve GPO GUID to display name
    function Resolve-GPOName {
        param (
            [string]$GPOGUID
        )
        try {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = [ADSI]"LDAP://CN=Policies,CN=System,$domaindn"
            $searcher.Filter = "(&(objectClass=groupPolicyContainer)(cn=$GPOGUID))"
            $searcher.SearchScope = "OneLevel"
            
            $result = $searcher.FindOne()
            
            if ($result) {
                $gpoObject = $result.GetDirectoryEntry()
                return $gpoObject.Properties["displayname"][0]
            } else {
                return "Unknown GPO"
            }
        } catch {
            return "Error resolving GPO name"
        }
    }

    # Function to check if a single GPO is writable and optionally check its links
    function Check-SingleGPO {
        param (
            [string]$GPOIdentifier,
            [switch]$CheckLinks
        )

        $gpoPath = "CN=$GPOIdentifier,CN=Policies,CN=System,$domaindn"

        $checkgpo = (Get-Acl -Path "AD:$gpoPath").Access |
        Where-Object {
            $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty|WriteDacl|WriteOwner|GenericAll" -and
            ($_.IdentityReference -match "$env:USERNAME|Authenticated Users|Domain Users|Everyone")
        }

        $isWritable = $null -ne $checkgpo

        if ($CheckLinks -and $isWritable) {
            Write-Host "`nChecking linked locations for $GPOIdentifier..."
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
            
            $gpoDisplayName = Resolve-GPOName -GPOGUID $gpoGUID
            if ($linkedLocations.Count -gt 0) {
                Write-Host $green"GPO $gpoDisplayName ($gpoGUID) is linked to:"
                foreach ($location in $linkedLocations) {
                    Write-Host "  - $location"
                }
            } else {
                Write-Host $gray"GPO $gpoDisplayName ($gpoGUID) is not linked to any locations (This might be incorrect, please verify manually)"
            }
        }

        return $isWritable
    }

    if ($All) {
        $GPOS = (Get-ChildItem \\$domain\SYSVOL\$domain\Policies | Select-Object -ExpandProperty Name)
        $writableGPOs = @()
        foreach ($GPO in $GPOS) {
            $isWritable = Check-SingleGPO -GPOIdentifier $GPO
            if ($isWritable) {
                $writableGPOs += $GPO
                Write-Host $green"GPO $GPO is writable"
            } else {
                Write-Host $red"GPO $GPO is not writable"
            }
        }
        Write-Host "`nChecking linked locations for writable GPOs..."
        foreach ($writableGPO in $writableGPOs) {
            Check-SingleGPO -GPOIdentifier $writableGPO -CheckLinks | Out-Null
        }
    } elseif ($GPO) {
        $gpoIdentifier = if ($GPO -match '^{?[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}}?$') {
            $GPO
        } else {
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = [ADSI]"LDAP://CN=Policies,CN=System,$domaindn"
            $searcher.Filter = "(&(objectClass=groupPolicyContainer)(displayName=$GPO))"
            $searcher.SearchScope = "OneLevel"
            $result = $searcher.FindOne()
            if ($result) {
                $gpoObject = $result.GetDirectoryEntry()
                $gpoObject.Name
            } else {
                Write-Host $red"Unable to find GPO with name: $GPO. Please verify the GPO name."
                return
            }
        }

        $isWritable = Check-SingleGPO -GPOIdentifier $gpoIdentifier -CheckLinks
        if ($isWritable) {
            Write-Host $green"GPO $GPO is writable"
        } else {
            Write-Host $red"GPO $GPO is not writable"
        }
    } else {
        Write-Host "Please specify either -All to check all GPOs or -GPO to check a specific GPO by GUID or name."
    }
}