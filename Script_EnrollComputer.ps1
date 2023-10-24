$Date = Get-Date -Format "dddd MM-dd-yyyy HHmm"
$TranscriptPath = "C:\Windows\Temp\EnrollmentScript - $Date.log"
Try{Start-Transcript -Path $TranscriptPath -Force -ErrorAction Stop}catch{Start-Transcript -Path $TranscriptPath -Force}

#Region - function to install or update powershell modules
Function Check-PowerShellModule(){
    param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$ModuleName
    )
    foreach($checkmodule in $ModuleName){
    #getting version of installed module
    $version = (Get-Module -ListAvailable $checkmodule) | Sort-Object Version -Descending  | Select-Object Version -First 1
    #Update module if it is already installed
    if($version){
        #converting version to string
        $stringver = $version | Select-Object @{n='ModuleVersion'; e={$_.Version -as [string]}}
        $a = $stringver | Select-Object Moduleversion -ExpandProperty Moduleversion
        #getting latest module version from ps gallery 
        $psgalleryversion = Find-Module -Name $checkmodule | Sort-Object Version -Descending | Select-Object Version -First 1
        #converting version to string
        $onlinever = $psgalleryversion | select @{n='OnlineVersion'; e={$_.Version -as [string]}}
        $b = $onlinever | Select-Object OnlineVersion -ExpandProperty OnlineVersion
        #check version format 0.0.0 or 0.0 ...
        $charCount = ($a.ToCharArray() | Where-Object {$_ -eq '.'} | Measure-Object).Count
        switch($charCount){
            {$charCount -eq 1}{
            ##version format 1.1 
            if ([version]('{0}.{1}' -f $a.split('.')) -ge [version]('{0}.{1}' -f $b.split('.'))) {
                Write-Host "Module: $checkmodule"
                Write-Host "Installed $a is equal or greater than $b"
            }
            else {
                Write-Host "Module: $checkmodule"
                Write-Host "Installed Module:$a is lower version than $b"
                #ask for update  
                do { $askyesno = (Read-Host "Do you want to update Module $checkmodule (Y/N)").ToLower() } while ($askyesno -notin @('y','n'))
                if ($askyesno -eq 'y') {
                    Write-Host "Selected YES Updating module $checkmodule"
                    Update-Module -Name $checkmodule -Force
                    
                    } else {
                    Write-Host "Selected NO , no updates to Module $checkmodule were done"
                    }
            }  
            }
            {$charCount -eq 2}{
            ##version format 1.1.1  
            if ([version]('{0}.{1}.{2}' -f $a.split('.')) -ge [version]('{0}.{1}.{2}' -f $b.split('.'))) {
                Write-Host "Module: $checkmodule"
                Write-Host "Installed $a is equal or greater than $b"
            }
            else {
                Write-Host "Module: $checkmodule"
                Write-Host "Installed Module:$a is lower version than $b"
                #ask for update  
                do { $askyesno = (Read-Host "Do you want to update Module $checkmodule (Y/N)").ToLower() } while ($askyesno -notin @('y','n'))
                    if ($askyesno -eq 'y') {
                        Write-Host "Selected YES Updating module $checkmodule"
                        Update-Module -Name $checkmodule -Verbose -Force
                        
                        } else {
                        Write-Host "Selected NO , no updates to Module $checkmodule were done"
                        }
            }  
            }
            {$charCount -eq 3}{ 
            ##version format 1.1.1.1
            if ([version]('{0}.{1}.{2}.{3}' -f $a.split('.')) -ge [version]('{0}.{1}.{2}.{3}' -f $b.split('.'))) {
                Write-Host "Module: $checkmodule"
                Write-Host "Installed $a is equal or greater than $b"
            }
            else {
                Write-Host "Module: $checkmodule"
                Write-Host "Installed Module:$a is lower version than $b"
                #ask for update  
                do { $askyesno = (Read-Host "Do you want to update Module $checkmodule (Y/N)").ToLower() } while ($askyesno -notin @('y','n'))
                    if ($askyesno -eq 'y') {
                        Write-Host "Selected YES Updating module $checkmodule"
                        Update-Module -Name $checkmodule -Force
                        
                        } else {
                        Write-Host "Selected NO , no updates to Module $checkmodule were done"
                        }
                    }  
                }
            }
    }else{
        #Install module if it is not installed
        Write-Host "Module '$checkmodule' was not found. Installing it now"
        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
        Install-Module $checkmodule -AllowClobber -Confirm:$false -Repository PSGallery    
    }
    Write-Host "Importing this module now: $checkmodule"
    Import-Module -Name $checkmodule -Force
    }
}
#EndRegion - function to install or update powershell modules

#Region - function to update windows
Function UpdateWindows(){
    param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$InstallUpdates
    )
    Check-PowerShellModule -ModuleName PSWindowsUpdate
    $Updates = Get-WindowsUpdate
    if($Updates){
        Write-Host "Here are the updates that are available to install:"
        Write-Output $Updates
        while("Yes","No" -notcontains $InstallUpdates){
            $InstallUpdates = Read-Host "
Would you like to install the updates? Valid options are 'Yes' or 'No'"
        }
        if($InstallUpdates -eq "Yes"){
            Get-WindowsUpdate -AcceptAll -Install -AutoReboot
        }
    }else{
        Write-Host "There are no pending windows updates!" -foregroundcolor green
    }
}

#Region - Functions
Function Enroll-Device(){
    Write-Host "Script has been initiated. USB no longer needs to be plugged in to this device. Feel free to unplug it and move on to the next PC" -foregroundcolor Yellow

    Write-Host "

    Checking for and setting up the needed PowerShell package providers, modules, and scripts. Please wait:"

    #Enable TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    #Region - Install Modules and scripts
    Check-PowerShellModule -ModuleName AzureAD
    Check-PowerShellModule -ModuleName NuGet
    Check-PowerShellModule -ModuleName WindowsAutoPilotIntune
    #Check-PowerShellModule -ModuleName Microsoft.Graph
    Check-PowerShellModule -ModuleName Microsoft.Graph.Intune
    
    #WindowsAutoPilotIntune: https://www.powershellgallery.com/packages/WindowsAutoPilotIntune/5.0

    #Checking if Get-WindowsAutoPilotInfo.ps1 script is downloaded.")
    #AT 5/24/2023 - Had to add this script as a function instead
    # $ScriptLocation = "C:\Program Files\WindowsPowerShell\Scripts\"
    # $AutoPilotInfoScript = "$ScriptLocation\Get-WindowsAutoPilotInfo.ps1"
    # $CheckAutoPilotInfo = Test-Path -Path $AutoPilotInfoScript -PathType Leaf
    # Write-Host "
    # Checking to See if $AutoPilotInfoScript  is already installed"
    # If($CheckAutoPilotInfo -eq 'True'){
    #     Write-Host("    Get-WindowsAutoPilotInfo.ps1 looks like it installed fine. Congrats, next phase will commence.")
    # }Else{
    #     Write-Host("    Downloading the Get-WindowsAutoPilotInfo.ps1 script now.") -ForegroundColor Yellow
    #     Install-Script -Name Get-WindowsAutoPilotInfo -Force
    #     }
    #endregion - Install Modules and scripts

    #Region Get and assign variables
    Write-Host("

    Pleaes provide the needed data to upload the device info to the clients Intune portal. If you get an error about incorrect sign in info YOU  info wrong.") -ForegroundColor Yellow

    #Connect to Graph then AzureAD
    Write-Host "Please sign in to Azure AD and Graph to begin the device upload process" -ForegroundColor Yellow
    $aadId = Connect-AzureAD
    Write-Host "Connected to Azure tenant $($aadId.TenantId.Guid)"
    #Connect to MgGraph
    Write-Host "Connecting to MgGraph now (Microsoft Graph Command Line Tools)"
    Write-Host "NOTE: If you have to consent to anything with the MgGraph connection you will need a global admin. Talk to the infra team for help <3"
    $MgGraph = Connect-MgGraph -TenantID $($aadId.TenantId.Guid) -Scope DeviceManagementServiceConfig.ReadWrite.All
    #Write-Host "Attempting to connect to MSGraph now."
    $graph = Connect-MSGraph

    #Username of person that needs to be assigned
    while(($StandardDeployment -eq "") -or ($null -eq $StandardDeployment) -or ("yes","no" -notcontains $StandardDeployment)){
    $StandardDeployment = Read-host 'Is this PC going to be used as a SPARE or does it need a different Autopiloit enrollment profile/status page (Please enter "yes" or "no")?'}

    if($StandardDeployment -eq 'No'){
        while(($UPN -eq "") -or ($null -eq $UPN)){
        $UPN = Read-Host '
    What is the users Email/Username (userPrincipalName)'}
        #Make sure a full email was entered
        While ($UPN -notlike '*@*'){
        Write-Host "
        It does NOT look like you entered a valid email address. Please make sure you enter their full email addrss including the @ symbol and domain" -foregroundcolor red
        $UPN = Read-Host 'What is the users Email/Username (userPrincipalName)'
        }
        #Connect to Graph and Azure to test username
        $QueryUser = Get-AzureADUser -Filter "userPrincipalName eq '$UPN'"
        $UPNId = $QueryUser.ObjectId
        While ($null -eq $UPNId){
            Write-Host "It does look like the username you entered ($UPN) was not correct. We could not find a matching user in Azure AD. Please retry" -ForegroundColor Red
            $UPN = $null
            while(($UPN -eq "") -or ($null -eq $UPN)){
                $UPN = Read-Host 'We could not find the user in Azure. What is the users Email/Username (userPrincipalName)'}
        $QueryUser = Get-AzureADUser -Filter "userPrincipalName eq '$UPN'"
        $UPNId = $QueryUser.ObjectId
        }
        #Get DisplayName info
        $QueryDisplayName = $QueryUser.DisplayName
        Write-Host "User Confirmed. Looks like $QueryDisplayName is getting a new computer." -ForegroundColor green
        #Set needed group for query
        $GroupAssignment = "Intune_Devices_AutopilotDeployed"
    }# else{
    #         while(($Spare -eq "") -or ($null -eq $Spare) -or ("yes","no" -notcontains $Spare)){
    #         $Spare = Read-host 'Is this PC going to be used as a spare?'}
    #             if($Spare -eq 'No'){
    #                 while(($GroupAssignment -eq "") -or ($null -eq $GroupAssignment)){
    #                 $GroupAssignment = Read-host '

    # You have selected to deploy this PC to a non standard group
    # What is the group name in Azure AD that this PC should be assigned to?'}
    #             while(($AssignUser -eq "") -or ($null -eq $AssignUser) -or ("yes","no" -notcontains $AssignUser)){
    #                 $AssignUser = Read-Host 'Do you still need to assign a user?'}
    #             if($AssignUser -eq 'yes'){
    #                 while(($UPN -eq "") -or ($null -eq $UPN)){
    #                 $UPN = Read-Host '
    # What is the users Email/Username (userPrincipalName)'}
    #                 #Make sure a full email was entered
    #                 While ($UPN -notlike '*@*'){
    #                     Write-Host "
    # It does NOT look like you entered a valid email address. Please make sure you enter their full email addrss including the @ symbol and domain" -foregroundcolor red
    #                     $UPN = Read-Host 'What is the users Email/Username (userPrincipalName)'
    #                     }
    #                     #Connect to Graph and Azure to test username
    #                 $QueryUser = Get-AzureADUser -Filter "userPrincipalName eq '$UPN'"
    #                 $UPNId = $QueryUser.ObjectId
    #                 While ($null -eq $UPNId){
    #                     Write-Host "It does look like the username you entered ($UPN) was not correct. We could not find a matching user in Azure AD. Please retry" -ForegroundColor Red
    #                     while(($UPN -eq "") -or ($null -eq $UPN)){
    #                         $UPN = Read-Host 'We could not find the user in Azure. What is the users Email/Username (userPrincipalName)'}
    #                     $QueryUser = Get-AzureADUser -Filter "userPrincipalName eq '$UPN'"
    #                     $UPNId = $QueryUser.ObjectId
    #                     #Get DisplayName info
    #                     $QueryDisplayName = $QueryUser.DisplayName
    #                     Write-Host "User Confirmed. Looks like $QueryDisplayName is getting a new computer." -ForegroundColor green
    #                     }
    #             }
    #     }
    # }


    #Get desired computer name
    while(($ComputerName -eq "") -or ($null -eq $ComputerName)){
        $ComputerName = Read-Host 'What would you like to name this device? (NOTE name applies after white glove is completed)'
        Write-Host "Checking to see if that device name is already taken..."
        While ($ComputerName.length -gt 15) {
            Write-Host "
        Please enter 15 or less than characters for the computer name. Windoes does not allow more than 15 characters." -foregroundcolor red
            $ComputerName = Read-Host 'What would you like to name this device? (NOTE name applies after white glove is completed)'
        }
        #Check computer name in Autppilot devices
        $AllDevices = Get-AutopilotDevice
        ForEach($Device in $AllDevices){
            if($ComputerName -eq $Device.displayName){
                Write-Host "It looks like this device name ($ComputerName) was already taken by another autopilot device. Please try again." -foregroundcolor red
                $ComputerName = $Null
            }
        }
        #Check computer name in AzureAD
        if($null -ne $ComputerName){
            $AllDevices = Get-AzureADDevice -All $True
            foreach($Device in $AllDevices){
                if($ComputerName -eq $Device.displayName){     
                    Write-Host "It looks like this device name ($ComputerName) was already taken by a device in Azure. Please try again." -foregroundcolor red
                    $ComputerName = $Null
                }
            }
        }
    }
    Write-Host "It looks like this device name ($ComputerName) is available!" -foregroundcolor green

    #'Apostrophe' is also a banned character but I could not pass this in a variable
    $BannedCharacters = '.', '\', '/', ':', '*', '?', '"', '<', '<', '|', ',', '~', '!', '@', '#', '$', '%', '^', '&', '(', ')', '{', '}', '_', ' '
    $CheckBannedCharacters = ($BannedCharacters | %{$ComputerName.contains($_)})
    While ($CheckBannedCharacters -contains 'True'){
        Write-Host "It does look like you entered ($ComputerName) a banned character for netbios and/or the computer name.
    Please do not use $BannedCharacters or spaces in the computer name" -ForegroundColor Red
        $ComputerName = Read-Host 'What would you like to name this device? (NOTE name applies after white glove is completed)'
        $CheckBannedCharacters = ($BannedCharacters | %{$ComputerName.contains($_)})
    }

    #Azure group name and Autopilot GroupTag
    $GroupName = $GroupAssignment
    #endregion

    #Check for valid group
    $QueryGroup = Get-AzureADGroup | Where-Object{$_.displayName -like "*$GroupName*"}
    while($null -eq $QueryGroup){
        $GroupName = Read-Host 'It does not look like the Group provided matches anything in Azure. Group name we looked for '$GroupName' Please enter another group name'
        while(($GroupName -eq "") -or ($null -eq $GroupName)){
            $GroupName = Read-Host 'It does not look like the Group provided matches anything in Azure. Please enter another group name'}
            $QueryGroup = Get-AzureADGroup | Where-Object{$_.displayName -like "*$GroupName*"}
        }

    #Kick off device upload process
    if(($null -eq $UPN) -or ($UPN -eq "")){
        Get-WindowsAutoPilotInfo -Online -AddToGroup $GroupName -Assign -AssignedComputerName $ComputerName
    }else{
        Get-WindowsAutoPilotInfo -Online -AddToGroup $GroupName -Assign -AssignedUser $UPN -AssignedComputerName $ComputerName
    }

    #Get Autopilot assignment info
    $session = New-CimSession
    $serial = (Get-CimInstance -CimSession $session -Class Win32_BIOS).SerialNumber
    $device = Get-AutopilotDevice -serial $serial

    #region - Assign device details
    #Get Variables
    $id = $Device.id
    $groupTag = $Device.groupTag
    $addressableUserName = $Device.addressableUserName #What shows up on the enrollment status page when the user gets their pc
    $userPrincipalName = $Device.userPrincipalName
    $displayName = $Device.displayName

    Write-Host "Starting loop that ensures the variables for user assignment (if applicable) and the computer name are assigned.
    " -ForegroundColor Yellow
    if($null -ne $UPN){
        while(($addressableUserName -eq "") -and ($userPrincipalName -eq "")){
            Set-AutopilotDevice -userPrincipalName $UPN -Id $id -addressableUserName $QueryDisplayName -displayName $ComputerName
            Start-Sleep -Seconds 5
            $device = Get-AutopilotDevice -serial $serial
            $addressableUserName = $Device.addressableUserName
            $userPrincipalName = $Device.userPrincipalName
            $displayName = $Device.displayName
            Write-Host "
    Could not find the assigned user $QueryDisplayName ($UPN) assigned to device $serial. Trying to apply these paramaters again and will query after a 5 second wait timer."
        }
    }Else{
            Write-Host "
    It does look like the Display Name (addressableUserName) and userPrincipalName (Users username to login) assigned fine. It is $QueryDisplayName and $userPrincipalName resptively" -ForegroundColor Green
        }

    While($displayName -eq ""){
        Set-AutopilotDevice -Id $id -displayName $ComputerName
        Start-Sleep -Seconds 5
        $device = Get-AutopilotDevice -serial $serial
        $displayName = $Device.displayName
        if($displayName -eq ""){
            Write-Host "
        Could not find the computer name $ComputerName assigned to device $serial. Trying to apply these paramaters again and will query after a 5 second wait timer."
        }Else{
            Write-Host "
        It does look like the displayName (computer name) assigned fine. It is set as $ComputerName " -ForegroundColor Green
        }
    }
    
    #endregion

    $device = Get-AutopilotDevice -serial $serial

    $groupTag = $Device.groupTag
    $addressableUserName = $Device.addressableUserName #What shows up on the enrollment status page when the user gets their pc
    $userPrincipalName = $Device.userPrincipalName
    $displayName = $Device.displayName
    $serialNumber = $Device.serialNumber

    Write-Host "

    ==================================================================
    Script has finished (Import-Module -Name Skyrim -assignDialog 'Gods be praised').
    Please REVIEW the below paramaters and ensure they are correct.
    If they are continue with the deployment please.
    ------------------------------------------------------------------" -ForegroundColor Green
    Write-Host "

    Device Name: $displayName
    Serial Number: $serialNumber
    Assigned User: $addressableUserName
    NOTE: Microsoft changed how this behaves. Assigning the user no longer shows it as an 'Assigned User' during White Glove nor does it show the users name once the user logs in. This information is still grabbed for per user LoB MSI app and LoB store apps though.

    Username: $userPrincipalName
    NOTE: Microsoft changed how this behaves. Assigning the user no longer shows it as an 'Assigned User' during White Glove nor does it show the users name once the user logs in. This information is still grabbed for per user LoB MSI app and LoB store apps though.

    Group Tag: $groupTag
    NOTE: Not typically needed
    
    ========================================================================
    Checking for updates. If there are any available they will be installed.
    If a reboot is needed for an update it will be initiated." -ForegroundColor Magenta

    UpdateWindows -InstallUpdates "Yes"
    Stop-Transcript
}
#Autopilot Nuke pulled from here: https://www.powershellgallery.com/packages/AutopilotNuke/2.3/Content/AutopilotNuke.ps1
Function AutopilotNuke(){

    <#PSScriptInfo
    
    .VERSION 2.3
    
    .GUID b608a45b-6cd0-405e-bfb2-aa11450821b5
    
    .AUTHOR Alexey Semibratov
    
    .COMPANYNAME
    
    .COPYRIGHT Alexey Semibratov
    
    .TAGS
    
    .LICENSEURI
    
    .PROJECTURI
    
    .ICONURI
    
    .EXTERNALMODULEDEPENDENCIES
    
    .REQUIREDSCRIPTS
    
    .EXTERNALSCRIPTDEPENDENCIES
    
    .RELEASENOTES
    Version 2.1: Bugfix
    Version 2.0: Bugfix
    Version 1.9: Bugfix
    Version 1.8: Streamlined all logic with found Intune/AAD devices, changed output of found objects to a table
    Version 1.7: Fixed a situation where there can be multiple Intune devices
    Version 1.6: Added assigned user and tag - we will capture the old values, and will allow to change those if needed
    Version 1.5: Some change in language around on-prem domain. Added wait for sync if it was less then 10 minutes ago. Fixed a bug when there is no AP devices, but we still want to delete Intune/AAD/AD devices.
    Version 1.2: Added more documentation and set of required rights. Now if the device is not found in Autopilot, but exists in Intune (by serial number), it still cleans it from AD DS and AAD
    Version 1.1: Invoke-AutopilotSync, when called too soon, error out
    Version 1.0: Original public version.
    
    #>

    <#
    
    .SYNOPSIS
    Interactive script that helps to provision Autopilot machines. Identifies and fixes issues by removing the computer from Intune, AAD, AD and Autopilot, then adds it.
    
    MIT LICENSE
    
    Copyright (c) 2021 Alexey Semibratov
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    
    .DESCRIPTION
    Runs from OOBE screen, connects to Azure AD, Intune and optionally to AD DS, finds all objects for the serial number of the machine it is running on, then deletes it from everywhere, then adds it to Autopilot again.
    Asks for deletion of each object
    Usage:
    - The script can work from running Windows 10, but be careful removing native Azure AD joined Intune Devices - you can lock yourself out, if you do not know local administrator's password
    - Intended usage – from OOBE (Out of Box Experience)
    - While in OOBE, hits Shift+F10
    - Powershell.exe
    - Install-Script AutopilotNuke
    - Accept all prompts
    - & 'C:\Program Files\WindowsPowerShell\Scripts\AutopilotNuke.ps1'
    - The script will:
            Download and install all required modules (accept all prompts)
            Show you the Serial Number of the machine
            Prompt to connect you to Azure AD and Intune Graph
            Ask you if you want to connect to local AD (ADDS, NT Domain) so it could delete old records from there. Enter the local FQDN (domain.com, contoso.local) of your AD Domain
            If you entered local AD domain, it will ask you for the username and password, for the username, use <NetbiosName>\User format
            Search in Autopilot for the serial number
            Show you all objects in Intune and AAD related to that Serial Number
            Ask if you want to delete in from Intune then deletes
            Ask if you want to delete in from Autopilot then deletes
            Loop through all AAD and AD (if it was selected) objects and ask to delete them
            Ask if you want to add it to AP then adds
    
    Minimum security rights needed:
    • To authorize Intune Graph, you will need global admin, but this is just one time. Ask your GA to run:
        Install-PackageProvider -Name NuGet
        Install-Module AzureAD
        Install-Module WindowsAutopilotIntune
        Install-Module Microsoft.Graph.Intune
        Connect-AzureAD
        Connect-MSGraph
        Accept the consent prompt
    • Custom role with the following permissions required in Intune:
        Managed devices
            Read
            Delete
            Update
            Enrollment programs
            Create device
            Delete device
            Read device
            Sync device
        Assigned to All Devices (did not try scoping it with RBAC, but should work in theory)
    • Cloud device administrator role required in Azure AD
    • AD DS rights similar to Intune Connector rights: https://docs.microsoft.com/en-us/mem/autopilot/windows-autopilot-hybrid#:~:text=The%20Intune%20Connector%20for%20your,the%20rights%20to%20create%20computers.
    
    
    #> 
    [CmdletBinding()]
    param(
    )

    Write-Host "Downloading and installing all required modules, please accept all prompts"

    #Install-PackageProvider -Name NuGet
    #Region - Check for AzureAD Module
Write-Host("Checking if the AzureAD Module is installed.")
if (Get-Module -ListAvailable -Name AzureAD) {
    Write-Host "AzureAD is already installed" -ForegroundColor green
}else{
    try {
        Write-Host("AzureAD is installing now") -ForegroundColor yellow
        Install-Module -Name AzureAD -AllowClobber -Force
    }
    catch [Exception] {
        $_.message
        exit
    }
}
#EndRegion - Check for AzureAD Module

    #WindowsAutoPilotIntune: https://www.powershellgallery.com/packages/WindowsAutoPilotIntune/5.0
    Write-Host("
    Checking if the WindowsAutoPilotIntune Module is installed.")
    if (Get-Module -ListAvailable -Name WindowsAutoPilotIntune) {
        Write-Host "    WindowsAutoPilotIntune is already installed!!" -ForegroundColor Green
    }else {
        try {
            Write-Host("    WindowsAutoPilotIntune Module is installing now") -ForegroundColor Yellow
            Install-Module -Name WindowsAutoPilotIntune -Force
        }
        catch [Exception] {
            $_.message
            exit
        }
    }

    #Checking if Get-WindowsAutoPilotInfo.ps1 script is downloaded.")
    $ScriptLocation = "C:\Program Files\WindowsPowerShell\Scripts\"
    $AutoPilotInfoScript = "$ScriptLocation\Get-WindowsAutoPilotInfo.ps1"
    $CheckAutoPilotInfo = Test-Path -Path $AutoPilotInfoScript -PathType Leaf
    Write-Host "
    Checking to See if $AutoPilotInfoScript  is already installed"
    If($CheckAutoPilotInfo -eq 'True'){
        Write-Host("    Get-WindowsAutoPilotInfo.ps1 looks like it installed fine. Congrats, next phase will commence.")
    }Else{
        Write-Host("    Downloading the Get-WindowsAutoPilotInfo.ps1 script now.") -ForegroundColor Yellow
        Install-Script -Name Get-WindowsAutoPilotInfo -Force
        }

    Import-Module -Name WindowsAutoPilotIntune -Force
    Install-Module Microsoft.Graph.Intune

    $session = New-CimSession
    $DomainIP = $null
    $de = $null
    $autopilotDevices = $null
    $aadDevices = $null
    $intuneDevices = $null
    $localADfqdn = $null
    $DomainIP = $null
    $de = $null
    $relatedIntuneDevice=$null
    $FoundAADDevices=$null

    $groupTag=""
    $userPrincipalName=""
    $displayName=""
    $newdisplayName=""

    $serial = (Get-CimInstance -CimSession $session -Class Win32_BIOS).SerialNumber


    Write-Host "Will be processing device with serial number: " -NoNewline
    Write-Host $serial -ForegroundColor Green

    Write-Host "Connecting to AzureAD and Intune Graph"

    #Get global admin username if it's not provided already
    While(($null -eq $GlobalAdmin) -or ($GlobalAdmin -eq "") -or ($GlobalAdmin -notlike "*@*")){
        $GlobalAdmin = Read-Host '
    What is username of the global admin you are running wanting to connect with?'
    }

   #Connect to MS Graph if needed
    Try{
        $IntuneConnectionTest = Get-Groups
        if($null -ne $IntuneConnectionTest){
            Write-Host "Looks like you're already connected to MS Graph" -foregroundcolor green
        }
    }
    Catch{
        Write-Host "Connecting to MS Graph now." -foregroundcolor yellow
        while($null -eq $IntuneConnectionTest){
            Connect-MSGraph
            $IntuneConnectionTest = Get-Groups
        }
    }

    #Connect to AzureAD if it's not connected already
    Try{
        $AzureADConnectionTest = Get-AzureADTenantDetail
        if(($null -ne $AzureADConnectionTest) -or ($AzureADConnectionTest -ne "")){
            Write-Host "Looks like you're already connected to Azure AD" -foregroundcolor green
        }

    }
    Catch{
        while(($null -eq $AzureADConnectionTest) -or ($AzureADConnectionTest -eq "")){
            Write-Host "Connecting to Azure AD now" -foregroundcolor yellow
	        Connect-AzureAD -AccountId $GlobalAdmin
            $AzureADConnectionTest = Get-AzureADTenantDetail
        }
    }

    Write-Host "Loading all objects. This can take a while on large tenants"
    $aadDevices = Get-AzureADDevice -All $true
    $intuneDevices = Get-IntuneManagedDevice -Filter "contains(operatingsystem, 'Windows')" | Get-MSGraphAllPages
    $autopilotDevices = Get-AutopilotDevice | Get-MSGraphAllPages

    <# $localADfqdn = Read-Host -Prompt 'If you want to *DELETE* this computer from your local Active Directory domain and have Domain Controllers in line of sight, please enter the DNS of your AD DS domain (ie domain.local or contoso.com), otherwise, to skip AD DS deletion, hit "Enter"'
    if($localADfqdn -ne "" -and $localADfqdn -ne $null)
    {
        $DomainIP = (Test-Connection -ComputerName $localADfqdn -Count 1 -ErrorAction SilentlyContinue).IPV4Address.IPAddressToString
    }


    # Let's connect to on-prem AD

    if($DomainIP -ne $null)
    {

        Write-Host Connecting to $DomainIP
        Write-Host "Please provide the username and the password (DOMAIN\UserName)"
        $ADUserName = Read-Host -Prompt 'Username'
        $ADPassword = Read-Host -Prompt 'Password' -AsSecureString
        $ADPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ADPassword))
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainIP", $ADUserName, $ADPassword) -ErrorAction Stop
        Write-Host Connected to $de.distinguishedName   
    } #>


    $currentAutopilotDevice = $autopilotDevices | ? {$_.serialNumber -eq $serial}

    if ($currentAutopilotDevice -ne $null)
    {

        # Find the objects linked to the Autopilot device

        Write-Verbose $currentAutopilotDevice |  Format-List -Property *
        
        [array]$relatedIntuneDevice = $intuneDevices | ? {
        $_.serialNumber -eq $currentAutopilotDevice.serialNumber -or 
        $_.serialNumber -eq $currentAutopilotDevice.serialNumber.replace(' ','') -or 
        $_.id -eq $currentAutopilotDevice.managedDeviceId -or 
        $_.azureADDeviceId -eq $currentAutopilotDevice.azureActiveDirectoryDeviceId}       
    
        [array]$FoundAADDevices = $aadDevices | ? { 
            $_.DeviceId -eq $currentAutopilotDevice.azureActiveDirectoryDeviceId -or 
            $_.DeviceId -iin $relatedIntuneDevice.azureADDeviceId -or 
            $_.DevicePhysicalIds -match $currentAutopilotDevice.Id
            }

        # Display a summary for this device and found related Intune /AAD devices

        Write-Host "User:" $currentAutopilotDevice.userPrincipalName
        Write-Host "Group Tag:" $currentAutopilotDevice.groupTag

        $userPrincipalName = $currentAutopilotDevice.userPrincipalName
        $groupTag = $currentAutopilotDevice.groupTag

        Write-Host "Found Related Intune Devices:"

        $relatedIntuneDevice | Format-Table -Property deviceName, id, userID, enrolledDateTime, LastSyncDateTime, operatingSystem, osVersion, deviceEnrollmentType

        Write-Host "Found Related AAD Devices:"

        $FoundAADDevices | Format-Table -Property DisplayName, ObjectID, DeviceID, AccountEnabled, ApproximateLastLogonTimeStamp, DeviceTrustType, DirSyncEnabled, LastDirSyncTime -AutoSize  


        if($relatedIntuneDevice -ne $null){
            foreach($relIntuneDevice in $relatedIntuneDevice)        {
                $displayName=$relIntuneDevice.deviceName
                if($Host.UI.PromptForChoice('Delete Intune Device', 'Do you want to *DELETE* ' + $relIntuneDevice.deviceName +' from the Intune?', @('&Yes'; '&No'), 1) -eq 0){
                Remove-IntuneManagedDevice –managedDeviceId $relIntuneDevice.id -ErrorAction Continue
                }
            }

        }


    
        if($Host.UI.PromptForChoice('Delete Autopilot Device', 'Do you want to *DELETE* the device with serial number ' + $currentAutopilotDevice.serialNumber +' from the Autopilot?', @('&Yes'; '&No'), 1) -eq 0){
        

            Remove-AutopilotDevice -id $currentAutopilotDevice.id -ErrorAction Continue
            $SecondsSinceLastSync = $null
            $SecondsSinceLastSync = (New-Timespan -Start (Get-AutopilotSyncInfo).lastSyncDateTime.ToUniversalTime()  -End (Get-Date).ToUniversalTime()).TotalSeconds
            If ($SecondsSinceLastSync -ge 610){
                Invoke-AutopilotSync 
                
            }else{
                Write-Host "Last sync was" $SecondsSinceLastSync "seconds ago, will sleep for" (610-$SecondsSinceLastSync) "seconds before trying to sync."
                if($Host.UI.PromptForChoice('Autopilot Sync','Do you want to wait?', @('&Yes'; '&No'), 1) -eq 0){Start-Sleep -Seconds (610-$SecondsSinceLastSync) ; Invoke-AutopilotSync}            
            }
            while (Get-AutopilotDevice | Get-MSGraphAllPages | ? {$_.serialNumber -eq $serial} -ne $null){
                Start-Sleep -Seconds 5                        
        }
        Write-Host "Deleted"

        }

    }

    if($relatedIntuneDevice -eq $null -and $FoundAADDevices -eq $null ){
        # this serial number was not found in Autopilot Devices, but we still want to check intune devices with this serial number and search AAD and AD DS for that one
        [array]$relatedIntuneDevice = $intuneDevices | ? {$_.serialNumber -eq $serial -or $_.serialNumber -eq $serial.replace(' ','')}
        [array]$FoundAADDevices = $aadDevices | ? { $_.DeviceId -eq $relatedIntuneDevice.azureADDeviceId }
        Write-Host "Found Related Intune Devices:"

        $relatedIntuneDevice | Format-Table -Property deviceName, id, userID, enrolledDateTime, LastSyncDateTime, operatingSystem, osVersion, deviceEnrollmentType

        Write-Host "Found Related AAD Devices:"

        $FoundAADDevices | Format-Table -Property DisplayName, ObjectID, DeviceID, AccountEnabled, ApproximateLastLogonTimeStamp, DeviceTrustType, DirSyncEnabled, LastDirSyncTime -AutoSize  


        if($relatedIntuneDevice -ne $null){
            foreach($relIntuneDevice in $relatedIntuneDevice)        {
                $displayName=$relIntuneDevice.deviceName
                if($Host.UI.PromptForChoice('Delete Intune Device', 'Do you want to *DELETE* ' + $relIntuneDevice.deviceName +' from the Intune?', @('&Yes'; '&No'), 1) -eq 0){
                Remove-IntuneManagedDevice –managedDeviceId $relIntuneDevice.id -ErrorAction Stop
                }
            }

        }

    }



    foreach($aadDevice in $FoundAADDevices){
        if($de -ne $null){            
            $escapedguid = “\” + ((([GUID]$aadDevice.deviceID).ToByteArray() |% {“{0:x}” -f $_}) -join ‘\’)
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($de,"(&(objectCategory=Computer)(ObjectGUID=$escapedguid))")
            $obj = $searcher.FindOne()
            if ($obj -ne $null){
                $objdel = $obj.GetDirectoryEntry()
                if($Host.UI.PromptForChoice('Delete Active Directory Device', 'Do you want to *DELETE* the device with the name ' + $objdel.Name +' from AD DS?', @('&Yes'; '&No'), 1) -eq 0){
                $objdel.DeleteTree()
                }
                    
            }
        
        }
        if($Host.UI.PromptForChoice('Delete Azure Active Directory Device', 'Do you want to *DELETE* the device with the name ' + $aadDevice.DisplayName +' from Azure AD?', @('&Yes'; '&No'), 1) -eq 0){
            
            Remove-AzureADDevice -ObjectId $aadDevice.ObjectID -ErrorAction SilentlyContinue
        }
        
    }


    # Get the hash (if available)
    $devDetail = (Get-CimInstance -CimSession $session -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'")
    if ($devDetail)
    {
        $hash = $devDetail.DeviceHardwareData
        if($Host.UI.PromptForChoice('Add Autopilot Device', 'Do you want to *ADD* the device with serial number ' + $serial +' to Autopilot?', @('&Yes'; '&No'), 1) -eq 0){
            
            $newuserPrincipalName = Read-Host -Prompt "Change assigned user [$userPrincipalName] (type a new value or hit enter to keep the old one)"
            if (![string]::IsNullOrWhiteSpace($newuserPrincipalName)){ $userPrincipalName = $newuserPrincipalName }

            $newgroupTag = Read-Host -Prompt "Change group tag [$groupTag] (type a new value or hit enter to keep the old one)"
            if (![string]::IsNullOrWhiteSpace($newgroupTag)){ $groupTag = $newgroupTag }
            

            Add-AutopilotImportedDevice -serialNumber $serial -hardwareIdentifier $hash -groupTag $groupTag -assignedUser $userPrincipalName        

            $SecondsSinceLastSync = $null
            $SecondsSinceLastSync = (New-Timespan -Start (Get-AutopilotSyncInfo).lastSyncDateTime.ToUniversalTime()  -End (Get-Date).ToUniversalTime()).TotalSeconds
            If ($SecondsSinceLastSync -ge 610){
                Invoke-AutopilotSync            
            }else{
                Write-Host "Last sync was" $SecondsSinceLastSync "seconds ago, will sleep for" (610-$SecondsSinceLastSync) "seconds before trying to sync."
                if($Host.UI.PromptForChoice('Autopilot Sync','Do you want to wait?', @('&Yes'; '&No'), 0) -eq 0){Start-Sleep -Seconds (610-$SecondsSinceLastSync); Invoke-AutopilotSync}
                
            }
            
        }

    }

    if($Host.UI.PromptForChoice('Computer name','Do you want to configure a unique name for a device? This name will be ignored in Hybrid Azure AD joined deployments. Device name still comes from the domain join profile for Hybrid Azure AD devices. This will only work if you have not deleted the device from AP recently.', @('&Yes'; '&No'), 1) -eq 0){

        $newdisplayName = Read-Host -Prompt "[$displayName] (type a new value or hit enter to keep the old one)"
        if (![string]::IsNullOrWhiteSpace($displayName) -or ![string]::IsNullOrWhiteSpace($newdisplayName)){ 
        
            if (![string]::IsNullOrWhiteSpace($newdisplayName) ){ $displayName = $newdisplayName }
            
            $autopilotDevices = Get-AutopilotDevice | Get-MSGraphAllPages

            [array]$currentAutopilotDevices = $autopilotDevices | ? {$_.serialNumber -eq $serial}

            foreach($currentAutopilotDevice in $currentAutopilotDevices){
            
                Set-AutopilotDevice -id $currentAutopilotDevice.id -displayName $displayName 
            }
                
        }

    }
}
#Pulled from here: https://www.powershellgallery.com/packages/Get-AutopilotESPStatus/4.1/Content/Get-AutopilotESPStatus.ps1
Function Get-AutopilotESPStatus(){
    <#PSScriptInfo
    
    .VERSION 4.1
    
    .GUID 0f67a69a-b32f-4b56-a101-1394715d7fb5
    
    .AUTHOR Michael Niehaus
    
    .COMPANYNAME Microsoft
    
    .COPYRIGHT
    
    .TAGS Windows AutoPilot
    
    .LICENSEURI
    
    .PROJECTURI
    
    .ICONURI
    
    .EXTERNALMODULEDEPENDENCIES
    
    .REQUIREDSCRIPTS
    
    .EXTERNALSCRIPTDEPENDENCIES
    
    .RELEASENOTES
    Version 4.1: Marked as obsolete; use Get-AutopilotDiagnostics instead.
    Version 4.0: Added sidecar installation info.
    Version 3.9: Bug fixes.
    Version 3.8: Bug fixes.
    Version 3.7: Modified Office logic to ensure it accurately reflected what ESP thinks the status is. Added ShowPolicies option.
    Version 3.2: Fixed sidecar detection logic
    Version 3.1: Fixed ODJ applied output
    Version 3.0: Added the ability to process logs as well
    Version 2.2: Added new IME MSI guid, new -AllSessions switch
    Version 2.0: Added -online parameter to look up app and policy details.
    Version 1.0: Original published version.
    
    #>


    <#
    .SYNOPSIS
    Displays Windows Autopilot ESP tracking information from the current PC.
    
    .DESCRIPTION
    
    *NOTE* This script has been replaced by Get-AutopilotDiagnostics, available from https://www.powershellgallery.com/packages/Get-AutopilotDiagnostics. As a result, this script is no longer being maintained or enhanced.
    
    This script dumps out the Windows Autopilot ESP tracking information from the registry. This should work with Windows 10 1903 and later (earlier versions have not been validated).
    
    This script will not work on ARM64 systems due to registry redirection from the use of x86 PowerShell.exe.
    
    .PARAMETER Online
    Look up the actual policy names via the Intune Graph API
    
    .PARAMETER AllSessions
    Show all ESP sessions (where each session reflects one ESP execution, e.g. device ESP #1, device ESP #2 after a reboot, user) instead of just the last one.
    
    .PARAMETER CABFile
    Processes the information in the specified CAB file (captured by MDMDiagnosticsTool.exe -area Autopilot -cab filename.cab) instead of from the registry.
    
    .PARAMETER ShowPolicies
    Shows the policy details as recorded in the NodeCache registry keys.
    
    .EXAMPLE
    .\Get-AutopilotESPStatus.ps1
    
    .EXAMPLE
    .\Get-AutopilotESPStatus.ps1 -Online
    
    .EXAMPLE
    .\Get-AutopilotESPStatus.ps1 -AllSessions
    
    .EXAMPLE
    .\Get-AutopilotESPStatus.ps1 -CABFile C:\Autopilot.cab -Online -AllSessions
    
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$False)] [String] $CABFile = $null,
        [Parameter(Mandatory=$False)] [Switch] $Online = $false,
        [Parameter(Mandatory=$False)] [Switch] $AllSessions = $false,
        [Parameter(Mandatory=$False)] [Switch] $ShowPolicies = $false
    )

    Begin
    {
        # If using a CAB file, load up the registry information
        if ($CABFile) {

            # Extract the needed files
            if (-not (Test-Path "$($env:TEMP)\ESPStatus.tmp"))
            {
                New-Item -Path "$($env:TEMP)\ESPStatus.tmp" -ItemType "directory" | Out-Null
            }
            $null = & expand.exe "$CABFile" -F:MdmDiagReport_RegistryDump.reg "$($env:TEMP)\ESPStatus.tmp\" 
            if (-not (Test-Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_RegistryDump.reg"))
            {
                Write-Error "Unable to extract registrion information from $CABFile"
            }
            $null = & expand.exe "$CABFile" -F:microsoft-windows-devicemanagement-enterprise-diagnostics-provider-admin.evtx "$($env:TEMP)\ESPStatus.tmp\" 
            if (-not (Test-Path "$($env:TEMP)\ESPStatus.tmp\microsoft-windows-devicemanagement-enterprise-diagnostics-provider-admin.evtx"))
            {
                Write-Error "Unable to extract event information from $CABFile"
            }

            # Edit the path in the .reg file
            $content = Get-Content -Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_RegistryDump.reg"
            $content = $content -replace "\[HKEY_CURRENT_USER\\", "[HKEY_CURRENT_USER\ESPStatus.tmp\USER\"
            $content = $content -replace "\[HKEY_LOCAL_MACHINE\\", "[HKEY_CURRENT_USER\ESPStatus.tmp\MACHINE\"
            $content = $content -replace '^ "','"'
            $content = $content -replace '^ @','@'
            $content = $content -replace 'DWORD:','dword:'
            "Windows Registry Editor Version 5.00`n" | Set-Content -Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_Edited.reg"
            $content | Add-Content -Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_Edited.reg"

            # Remove the registry info if it exists
            if (Test-Path "HKCU:\ESPStatus.tmp")
            {
                Remove-Item -Path "HKCU:\ESPStatus.tmp" -Recurse -Force
            }

            # Import the .reg file
            $null = & reg.exe IMPORT "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_Edited.reg" 2>&1

            # Configure the (not live) constants
            $script:provisioningPath =  "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\provisioning"
            $script:autopilotDiagPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\provisioning\Diagnostics\Autopilot"
            $script:omadmPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\provisioning\OMADM"
            $script:path = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics"
            $script:msiPath = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\EnterpriseDesktopAppManagement"
            $script:officePath = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\OfficeCSP"
            $script:sidecarPath = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\IntuneManagementExtension\Win32Apps"
        }else {
            # Configure live constants
            $script:provisioningPath =  "HKLM:\software\microsoft\provisioning"
            $script:autopilotDiagPath = "HKLM:\software\microsoft\provisioning\Diagnostics\Autopilot"
            $script:omadmPath = "HKLM:\software\microsoft\provisioning\OMADM"
            $script:path = "HKLM:\Software\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics"
            $script:msiPath = "HKLM:\Software\Microsoft\EnterpriseDesktopAppManagement"
            $script:officePath = "HKLM:\Software\Microsoft\OfficeCSP"
            $script:sidecarPath = "HKLM:\Software\Microsoft\IntuneManagementExtension\Win32Apps"
        }

        # Configure other constants
        $script:officeStatus = @{"10" = "Initialized"; "20" = "Download In Progress"; "25" = "Pending Download Retry";
            "30" = "Download Failed"; "40" = "Download Completed"; "48" = "Pending User Session"; "50" = "Enforcement In Progress"; 
            "55" = "Pending Enforcement Retry"; "60" = "Enforcement Failed"; "70" = "Success / Enforcement Completed"}
        $script:espStatus = @{"1" = "Not Installed"; "2" = "Downloading / Installing"; "3" = "Success / Installed"; "4" = "Error / Failed"}
        $script:policyStatus = @{"0" = "Not Processed"; "1" = "Processed"}
    }

    Process
    {
        #------------------------
        # Functions
        #------------------------

        Function ProcessApps() {
        param
        (
            [Parameter(Mandatory=$true,ValueFromPipeline=$True)] [Microsoft.Win32.RegistryKey] $currentKey,
            [Parameter(Mandatory=$true)] $currentUser
        )

        Begin {
            Write-Host "Apps:"
        }

        Process {
            Write-Host " $($currentKey.PSChildName)"
            $currentKey.Property | % {
                if ($_.StartsWith("./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/")) {
                    $msiKey = [URI]::UnescapeDataString(($_.Split("/"))[6])
                    $fullPath = "$msiPath\$currentUser\MSI\$msiKey"
                    if (Test-Path $fullPath) {
                        $status = Get-ItemPropertyValue -Path $fullPath -Name Status
                        $msiFile = Get-ItemPropertyValue -Path $fullPath -Name CurrentDownloadUrl
                    }else{
                        $status = "Not found"
                        $msiFile = "Unknown"
                    } 
                    if ($msiFile -match "IntuneWindowsAgent.msi"){
                        $msiKey = "Intune Management Extensions ($($msiKey))"
                    }elseif ($Online) {
                        $found = $apps | ? {$_.ProductCode -contains $msiKey}
                        $msiKey = "$($found.DisplayName) ($($msiKey))"
                    }
                    if ($status -eq 70) {
                        Write-Host " MSI $msiKey : $status ($($officeStatus[$status.ToString()]))" -ForegroundColor Green
                    }else {
                        Write-Host " MSI $msiKey : $status ($($officeStatus[$status.ToString()]))" -ForegroundColor Yellow
                    }
                }elseif ($_.StartsWith("./Vendor/MSFT/Office/Installation/")) {
                    # Report the main status based on what ESP is tracking
                    $status = Get-ItemPropertyValue -Path $currentKey.PSPath -Name $_

                    # Then try to get the detailed Office status
                    $officeKey = [URI]::UnescapeDataString(($_.Split("/"))[5])
                    $fullPath = "$officepath\$officeKey"
                    if (Test-Path $fullPath) {
                        $oStatus = (Get-ItemProperty -Path $fullPath).FinalStatus

                        if ($oStatus -eq $null)
                        {
                            $oStatus = (Get-ItemProperty -Path $fullPath).Status
                            if ($oStatus -eq $null)
                            {
                                $oStatus = "None"
                            }
                        }
                    }else {
                        $oStatus = "None"
                    }
                    if ($officeStatus.Keys -contains $oStatus.ToString())
                    {
                        $officeStatusText = $officeStatus[$oStatus.ToString()]
                    }else {
                        $officeStatusText = $oStatus
                    }
                    if ($status -eq 1) {
                        Write-Host " Office $officeKey : $status ($($policyStatus[$status.ToString()]) / $officeStatusText)" -ForegroundColor Green
                    }else {
                        Write-Host " Office $officeKey : $status ($($policyStatus[$status.ToString()]) / $officeStatusText)" -ForegroundColor Yellow
                    }
                }else{
                    Write-Host " $_ : Unknown app"
                }
            }
        }

        }

        Function ProcessModernApps() {
        param
        (
            [Parameter(Mandatory=$true,ValueFromPipeline=$True)] [Microsoft.Win32.RegistryKey] $currentKey,
            [Parameter(Mandatory=$true)] $currentUser
        )

        Begin {
            Write-Host "Modern Apps:"
        }

        Process {
            Write-Host " $($currentKey.PSChildName)"
            $currentKey.Property | % {
                $status = (Get-ItemPropertyValue -path $currentKey.PSPath -Name $_).ToString()
                if ($_.StartsWith("./User/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/")) {
                    $appID = [URI]::UnescapeDataString(($_.Split("/"))[7])
                    $type = "User UWP"
                }elseif ($_.StartsWith("./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/")) {
                    $appID = [URI]::UnescapeDataString(($_.Split("/"))[7])
                    $type = "Device UWP"
                }else
                {
                    $appID = $_
                    $type = "Unknown UWP"
                }
                if ($status -eq "1") {
                    Write-Host " $type $appID : $status ($($policyStatus[$status]))" -ForegroundColor Green
                }else {
                    Write-Host " $type $appID : $status ($($policyStatus[$status]))" -ForegroundColor Yellow
                }
            }
        }

        }

        Function ProcessSidecar() {
        param
        (
            [Parameter(Mandatory=$true,ValueFromPipeline=$True)] [Microsoft.Win32.RegistryKey] $currentKey,
            [Parameter(Mandatory=$true)] $currentUser
        )

        Begin {
            Write-Host "Sidecar apps:"
        }

        Process {
            Write-Host " $($currentKey.PSChildName)"
            $currentKey.Property | % {
                $win32Key = [URI]::UnescapeDataString(($_.Split("/"))[9])
                $status = Get-ItemPropertyValue -path $currentKey.PSPath -Name $_
                if ($Online) {
                    $found = $apps | ? {$win32Key -match $_.Id }
                    $win32Key = "$($found.DisplayName) ($($win32Key))"
                }
                $appGuid = $win32Key.Substring(9)
                $sidecarApp = "$sidecarPath\$currentUser\$appGuid"
                $exitCode = $null
                if (Test-Path $sidecarApp)
                {
                    $exitCode = (Get-ItemProperty -Path $sidecarApp).ExitCode
                }
                if ($status -eq "3") {
                    if ($exitCode -ne $null) {
                        Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]), rc = $exitCode)" -ForegroundColor Green
                    }else {
                        Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]))" -ForegroundColor Green
                    }
                }else {
                    if ($exitCode -ne $null)
                    {
                        Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]), rc = $exitCode)" -ForegroundColor Yellow
                    }else {
                        Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]))" -ForegroundColor Yellow
                    }
                }
            }
        }

        }

        Function ProcessPolicies() {
        param
        (
            [Parameter(Mandatory=$true,ValueFromPipeline=$True)] [Microsoft.Win32.RegistryKey] $currentKey
        )

        Begin {
            Write-Host "Policies:"
        }

        Process {
            Write-Host " $($currentKey.PSChildName)"
            $currentKey.Property | % {
                $status = Get-ItemPropertyValue -path $currentKey.PSPath -Name $_
                Write-Host " Policy $_ : $status ($($policyStatus[$status.ToString()]))"
            }
        }

        }


        Function ProcessCerts() {
        param
        (
            [Parameter(Mandatory=$true,ValueFromPipeline=$True)] [Microsoft.Win32.RegistryKey] $currentKey
        )

        Begin {
            Write-Host "Certificates:"
        }

        Process {
            Write-Host " $($currentKey.PSChildName)"
            $currentKey.Property | % {
                $certKey = [URI]::UnescapeDataString(($_.Split("/"))[6])
                $status = Get-ItemPropertyValue -path $currentKey.PSPath -Name $_
                if ($Online) {
                    $found = $policies | ? { $certKey.Replace("_","-") -match $_.Id }
                    $certKey = "$($found.DisplayName) ($($certKey))"
                }
                if ($status -eq "1") {
                    Write-Host " Cert $certKey : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Green
                }else {
                    Write-Host " Cert $certKey : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Yellow
                }
            }
        }

        }

        Function ProcessNodeCache() {

        Begin {
            Write-Host " "
            Write-Host "Policies processed:"
        }
        
        Process {
            $nodeCount = 0
            while ($true) {
                # Get the nodes in order. This won't work after a while because the older numbers are deleted as new ones are added
                # but it will work out OK shortly after provisioning. The alternative would be to get all the subkeys and then sort
                # them numerically instead of alphabetically, but that can be saved for later...
                $node = Get-ItemProperty "$provisioningPath\NodeCache\CSP\Device\MS DM Server\Nodes\$nodeCount" -ErrorAction SilentlyContinue
                if ($node -eq $null)
                {
                    break
                }
                $nodeCount += 1
                $node | Select NodeUri, ExpectedValue
            }
        }

        }

        Function ProcessSidecarInfo() {

            Process {
                Get-ChildItem -path "$msiPath\S-0-0-00-0000000000-0000000000-000000000-000\MSI" | % {
                    $file = Get-ItemPropertyValue -Path $_.PSPath -Name CurrentDownloadUrl
                    if ($file -match "IntuneWindowsAgent.msi")
                    {
                        $productCode = Get-ItemPropertyValue -Path $_.PSPath -Name ProductCode
                        Write-Host " "
                        Write-Host "INTUNE MANAGEMENT EXTENSIONS installation details:"
                        if ($CABFile) {
                            Get-WinEvent -Path "$($env:TEMP)\ESPStatus.tmp\microsoft-windows-devicemanagement-enterprise-diagnostics-provider-admin.evtx" -Oldest | ? {($_.Message -match $productCode -and $_.Id -in 1905,1906,1920,1922) -or $_.Id -eq 72}
                        }else {
                            Get-WinEvent -LogName Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin -Oldest | ? {($_.Message -match $productCode -and $_.Id -in 1905,1906,1920,1922) -or $_.Id -eq 72}
                        }
                    }
                }
            }
        
            }
        
        Function GetIntuneObjects() {
            param
            (
                [Parameter(Mandatory=$true)] [String] $uri
            )

            Process {

                Write-Verbose "GET $uri"
                try {
                    $response = Invoke-MSGraphRequest -Url $uri -HttpMethod Get

                    $objects = $response.value
                    $objectsNextLink = $response."@odata.nextLink"
        
                    while ($objectsNextLink -ne $null){
                        $response = (Invoke-MSGraphRequest -Url $devicesNextLink -HttpMethod Get)
                        $objectsNextLink = $response."@odata.nextLink"
                        $objects += $response.value
                    }

                    return $objects
                }
                catch {
                    Write-Error $_.Exception
                    return $null
                    break
                }

            }
        }

        #------------------------
        # Main code
        #------------------------

        # Display Autopilot diag details
        if (Test-Path $autopilotDiagPath)
        {
            Write-Host ""
            Write-Host "AUTOPILOT DIAGNOSTICS"
            Write-Host ""

            $values = Get-ItemProperty "$autopilotDiagPath"
            Write-Host "TenantDomain: $($values.CloudAssignedTenantDomain)"
            Write-Host "TenantID: $($values.CloudAssignedTenantId)"
            Write-Host "OobeConfig: $($values.CloudAssignedOobeConfig)"
            $values = Get-ItemProperty "$autopilotDiagPath\EstablishedCorrelations"
            Write-Host "EntDMID: $($values.EntDMID)"
            if (Test-Path "$omadmPath\SyncML\ODJApplied")
            {
                Write-Host "ODJ applied: YES"
            }
        }

        # Display sidecar info
        ProcessSidecarInfo

        # Display the list of policies
        if ($ShowPolicies)
        {
            ProcessNodeCache | Format-Table -Wrap
        }
        
        # Make sure the tracking path exists
        if (-not (Test-Path $path)) {
            Write-Host "ESP diagnostics info does not (yet) exist."
            exit 0
        }

        # If online, make sure we are able to authenticate
        if ($Online) {

            # Make sure we can connect
            $module = Import-Module Microsoft.Graph.Intune -PassThru -ErrorAction Ignore
            if (-not $module) {
                Write-Host "Installing module Microsoft.Graph.Intune"
                Install-Module Microsoft.Graph.Intune -Force
            }
            Import-Module Microsoft.Graph.Intune
            $graph = Connect-MSGraph
            Write-Host "Connected to tenant $($graph.TenantId)"

            # Get a list of apps
            Write-Host "Getting list of apps"
            $script:apps = GetIntuneObjects("https://graph.microsoft.com/beta/deviceAppManagement/mobileApps")

            # Get a list of policies (for certs)
            Write-Host "Getting list of policies"
            $script:policies = GetIntuneObjects("https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations")
        }
        
        # Process device ESP sessions
        Write-Host " "
        Write-Host "DEVICE ESP:"
        Write-Host " "

        if (Test-Path "$path\ExpectedMSIAppPackages") {
            $items = Get-ChildItem "$path\ExpectedMSIAppPackages"
            if ($AllSessions) {
                $items | ProcessApps -currentUser "S-0-0-00-0000000000-0000000000-000000000-000"
            }elseif ($items.Count -gt 0) {
                $items[$items.Count - 1] | ProcessApps -currentUser "S-0-0-00-0000000000-0000000000-000000000-000"
            }
        }
        if (Test-Path "$path\ExpectedModernAppPackages") {
            $items = Get-ChildItem "$path\ExpectedModernAppPackages"
            if ($AllSessions) {
                $items | ProcessModernApps -currentUser "S-0-0-00-0000000000-0000000000-000000000-000"
            }elseif ($items.Count -gt 0) {
                $items[$items.Count - 1] | ProcessModernApps -currentUser "S-0-0-00-0000000000-0000000000-000000000-000"
            }
        }
        if (Test-Path "$path\Sidecar") {
            $items = Get-ChildItem "$path\Sidecar"
            if ($AllSessions) {
                $items | ProcessSidecar -currentUser "00000000-0000-0000-0000-000000000000"
            }elseif ($items.Count -gt 0) {
                $items[$items.Count - 1] | ProcessSidecar -currentUser "00000000-0000-0000-0000-000000000000"
            }
        }
        if (Test-Path "$path\ExpectedPolicies") {
            $items = Get-ChildItem "$path\ExpectedPolicies" 
            if ($AllSessions) {
                $items | ProcessPolicies
            }elseif ($items.Count -gt 0) {
                $items[$items.Count - 1] | ProcessPolicies
            }
        }
        if (Test-Path "$path\ExpectedSCEPCerts") {
            $items = Get-ChildItem "$path\ExpectedSCEPCerts"
            if ($AllSessions) {
                $items | ProcessCerts
            }elseif ($items.Count -gt 0) {
                $items[$items.Count - 1] | ProcessCerts
            }
        }

        # Process user ESP sessions
        Get-ChildItem "$path" | ? { $_.PSChildName.StartsWith("S-") } | % {
            $userPath = $_.PSPath
            $userSid = $_.PSChildName
            Write-Host " "
            Write-Host "USER ESP for $($userSid):"
            Write-Host " "
            if (Test-Path "$userPath\ExpectedMSIAppPackages") {
                $items = Get-ChildItem "$userPath\ExpectedMSIAppPackages" 
                if ($AllSessions) {
                    $items | ProcessApps -currentUser $userSid
                }elseif ($items.Count -gt 0) {
                    $items[$items.Count - 1] | ProcessApps -currentUser $userSid
                }
            }
            if (Test-Path "$userPath\ExpectedModernAppPackages") {
                $items = Get-ChildItem "$userPath\ExpectedModernAppPackages"
                if ($AllSessions) {
                    $items | ProcessModernApps -currentUser $userSid
                }elseif ($items.Count -gt 0) {
                    $items[$items.Count - 1] | ProcessModernApps -currentUser $userSid
                }
            }
            if (Test-Path "$userPath\Sidecar") {
                $items = Get-ChildItem "$userPath\Sidecar"
                if ($AllSessions) {
                    $items | ProcessSidecar -currentUser $userSid
                }elseif ($items.Count -gt 0) {
                    $items[$items.Count - 1] | ProcessSidecar -currentUser $userSid
                }
            }
            if (Test-Path "$userPath\ExpectedPolicies") {
                $items = Get-ChildItem "$userPath\ExpectedPolicies"
                if ($AllSessions) {
                    $items | ProcessPolicies
                }elseif ($items.Count -gt 0) {
                    $items[$items.Count - 1] | ProcessPolicies
                }
            }
            if (Test-Path "$userPath\ExpectedSCEPCerts") {
                $items = Get-ChildItem "$userPath\ExpectedSCEPCerts"
                if ($AllSessions) {
                    $items | ProcessCerts
                }elseif ($items.Count -gt 0) {
                    $items[$items.Count - 1] | ProcessCerts
                }
            }
        }

        Write-Host ""
    }

    End {

        # Remove the registry info if it exists
        if (Test-Path "HKCU:\ESPStatus.tmp")
        {
            Remove-Item -Path "HKCU:\ESPStatus.tmp" -Recurse -Force
        }
    }
}
#EndRegion - Functions

#Region - Get-WindowsAutoPilotInfo
#Originally from PS Gallery: https://www.powershellgallery.com/packages/Get-WindowsAutoPilotInfo/3.5/Content/Get-WindowsAutoPilotInfo.ps1
#Was taken from here as the Connect-AzureAD function broke for a period of time - AT 5/24/2023
Function Get-WindowsAutoPilotInfo(){
    <#PSScriptInfo
    
    .VERSION 3.5
    
    .GUID ebf446a3-3362-4774-83c0-b7299410b63f
    
    .AUTHOR Michael Niehaus
    
    .COMPANYNAME Microsoft
    
    .COPYRIGHT
    
    .TAGS Windows AutoPilot
    
    .LICENSEURI
    
    .PROJECTURI
    
    .ICONURI
    
    .EXTERNALMODULEDEPENDENCIES
    
    .REQUIREDSCRIPTS
    
    .EXTERNALSCRIPTDEPENDENCIES
    
    .RELEASENOTES
    Version 1.0: Original published version.
    Version 1.1: Added -Append switch.
    Version 1.2: Added -Credential switch.
    Version 1.3: Added -Partner switch.
    Version 1.4: Switched from Get-WMIObject to Get-CimInstance.
    Version 1.5: Added -GroupTag parameter.
    Version 1.6: Bumped version number (no other change).
    Version 2.0: Added -Online parameter.
    Version 2.1: Bug fix.
    Version 2.3: Updated comments.
    Version 2.4: Updated "online" import logic to wait for the device to sync, added new parameter.
    Version 2.5: Added AssignedUser for Intune importing, and AssignedComputerName for online Intune importing.
    Version 2.6: Added support for app-based authentication via Connect-MSGraphApp.
    Version 2.7: Added new Reboot option for use with -Online -Assign.
    Version 2.8: Fixed up parameter sets.
    Version 2.9: Fixed typo installing AzureAD module.
    Version 3.0: Fixed typo for app-based auth, added logic to explicitly install NuGet (silently).
    Version 3.2: Fixed logic to explicitly install NuGet (silently).
    Version 3.3: Added more logging and error handling for group membership.
    Version 3.4: Added logic to verify that devices were added successfully. Fixed a bug that could cause all Autopilot devices to be added to the specified AAD group.
    Version 3.5: Added logic to display the serial number of the gathered device.
    #>

    <#
    .SYNOPSIS
    Retrieves the Windows AutoPilot deployment details from one or more computers
    
    MIT LICENSE
    
    Copyright (c) 2020 Microsoft
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    
    .DESCRIPTION
    This script uses WMI to retrieve properties needed for a customer to register a device with Windows Autopilot. Note that it is normal for the resulting CSV file to not collect a Windows Product ID (PKID) value since this is not required to register a device. Only the serial number and hardware hash will be populated.
    .PARAMETER Name
    The names of the computers. These can be provided via the pipeline (property name Name or one of the available aliases, DNSHostName, ComputerName, and Computer).
    .PARAMETER OutputFile
    The name of the CSV file to be created with the details for the computers. If not specified, the details will be returned to the PowerShell
    pipeline.
    .PARAMETER Append
    Switch to specify that new computer details should be appended to the specified output file, instead of overwriting the existing file.
    .PARAMETER Credential
    Credentials that should be used when connecting to a remote computer (not supported when gathering details from the local computer).
    .PARAMETER Partner
    Switch to specify that the created CSV file should use the schema for Partner Center (using serial number, make, and model).
    .PARAMETER GroupTag
    An optional tag value that should be included in a CSV file that is intended to be uploaded via Intune (not supported by Partner Center or Microsoft Store for Business).
    .PARAMETER AssignedUser
    An optional value specifying the UPN of the user to be assigned to the device. This can only be specified for Intune (not supported by Partner Center or Microsoft Store for Business).
    .PARAMETER Online
    Add computers to Windows Autopilot via the Intune Graph API
    .PARAMETER AssignedComputerName
    An optional value specifying the computer name to be assigned to the device. This can only be specified with the -Online switch and only works with AAD join scenarios.
    .PARAMETER AddToGroup
    Specifies the name of the Azure AD group that the new device should be added to.
    .PARAMETER Assign
    Wait for the Autopilot profile assignment. (This can take a while for dynamic groups.)
    .PARAMETER Reboot
    Reboot the device after the Autopilot profile has been assigned (necessary to download the profile and apply the computer name, if specified).
    .EXAMPLE
    .\Get-WindowsAutoPilotInfo.ps1 -ComputerName MYCOMPUTER -OutputFile .\MyComputer.csv
    .EXAMPLE
    .\Get-WindowsAutoPilotInfo.ps1 -ComputerName MYCOMPUTER -OutputFile .\MyComputer.csv -GroupTag Kiosk
    .EXAMPLE
    .\Get-WindowsAutoPilotInfo.ps1 -ComputerName MYCOMPUTER -OutputFile .\MyComputer.csv -GroupTag Kiosk -AssignedUser JohnDoe@contoso.com
    .EXAMPLE
    .\Get-WindowsAutoPilotInfo.ps1 -ComputerName MYCOMPUTER -OutputFile .\MyComputer.csv -Append
    .EXAMPLE
    .\Get-WindowsAutoPilotInfo.ps1 -ComputerName MYCOMPUTER1,MYCOMPUTER2 -OutputFile .\MyComputers.csv
    .EXAMPLE
    Get-ADComputer -Filter * | .\GetWindowsAutoPilotInfo.ps1 -OutputFile .\MyComputers.csv
    .EXAMPLE
    Get-CMCollectionMember -CollectionName "All Systems" | .\GetWindowsAutoPilotInfo.ps1 -OutputFile .\MyComputers.csv
    .EXAMPLE
    .\Get-WindowsAutoPilotInfo.ps1 -ComputerName MYCOMPUTER1,MYCOMPUTER2 -OutputFile .\MyComputers.csv -Partner
    .EXAMPLE
    .\GetWindowsAutoPilotInfo.ps1 -Online
    
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$False,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)][alias("DNSHostName","ComputerName","Computer")] [String[]] $Name = @("localhost"),
        [Parameter(Mandatory=$False)] [String] $OutputFile = "", 
        [Parameter(Mandatory=$False)] [String] $GroupTag = "",
        [Parameter(Mandatory=$False)] [String] $AssignedUser = "",
        [Parameter(Mandatory=$False)] [Switch] $Append = $false,
        [Parameter(Mandatory=$False)] [System.Management.Automation.PSCredential] $Credential = $null,
        [Parameter(Mandatory=$False)] [Switch] $Partner = $false,
        [Parameter(Mandatory=$False)] [Switch] $Force = $false,
        [Parameter(Mandatory=$True,ParameterSetName = 'Online')] [Switch] $Online = $false,
        [Parameter(Mandatory=$False,ParameterSetName = 'Online')] [String] $TenantId = "",
        [Parameter(Mandatory=$False,ParameterSetName = 'Online')] [String] $AppId = "",
        [Parameter(Mandatory=$False,ParameterSetName = 'Online')] [String] $AppSecret = "",
        [Parameter(Mandatory=$False,ParameterSetName = 'Online')] [String] $AddToGroup = "",
        [Parameter(Mandatory=$False,ParameterSetName = 'Online')] [String] $AssignedComputerName = "",
        [Parameter(Mandatory=$False,ParameterSetName = 'Online')] [Switch] $Assign = $false, 
        [Parameter(Mandatory=$False,ParameterSetName = 'Online')] [Switch] $Reboot = $false
    )

    Begin
    {
        # Initialize empty list
        $computers = @()

        # If online, make sure we are able to authenticate
        if ($Online) {

            # Get NuGet
            $provider = Get-PackageProvider NuGet -ErrorAction Ignore
            if (-not $provider) {
                Write-Host "Installing provider NuGet"
                Find-PackageProvider -Name NuGet -ForceBootstrap -IncludeDependencies
            }
            
            # Get WindowsAutopilotIntune module (and dependencies)
            $module = Import-Module WindowsAutopilotIntune -PassThru -ErrorAction Ignore
            if (-not $module) {
                Write-Host "Installing module WindowsAutopilotIntune"
                Install-Module WindowsAutopilotIntune -Force
            }
            Import-Module WindowsAutopilotIntune -Scope Global

            # Get Azure AD if needed
            if ($AddToGroup)
            {
                $module = Import-Module AzureAD -PassThru -ErrorAction Ignore
                if (-not $module)
                {
                    Write-Host "Installing module AzureAD"
                    Install-Module AzureAD -Force
                }
            }

            # Connect
            if ($AppId -ne "")
            {
                $graph = Connect-MSGraphApp -Tenant $TenantId -AppId $AppId -AppSecret $AppSecret
                Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
            }
            else {
                $graph = Connect-MSGraph
                Write-Host "Connected to Intune tenant $($graph.TenantId)"
                if ($AddToGroup)
                {
                    $aadId = Connect-AzureAD
                    Write-Host "Connected to Azure AD tenant $($aadId.TenantId.GUID)"
                }
            }

            # Force the output to a file
            if ($OutputFile -eq "")
            {
                $OutputFile = "$($env:TEMP)\autopilot.csv"
            } 
        }
    }

    Process
    {
        foreach ($comp in $Name)
        {
            $bad = $false

            # Get a CIM session
            if ($comp -eq "localhost") {
                $session = New-CimSession
            }
            else
            {
                $session = New-CimSession -ComputerName $comp -Credential $Credential
            }

            # Get the common properties.
            Write-Verbose "Checking $comp"
            $serial = (Get-CimInstance -CimSession $session -Class Win32_BIOS).SerialNumber

            # Get the hash (if available)
            $devDetail = (Get-CimInstance -CimSession $session -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'")
            if ($devDetail -and (-not $Force))
            {
                $hash = $devDetail.DeviceHardwareData
            }
            else
            {
                $bad = $true
                $hash = ""
            }

            # If the hash isn't available, get the make and model
            if ($bad -or $Force)
            {
                $cs = Get-CimInstance -CimSession $session -Class Win32_ComputerSystem
                $make = $cs.Manufacturer.Trim()
                $model = $cs.Model.Trim()
                if ($Partner)
                {
                    $bad = $false
                }
            }
            else
            {
                $make = ""
                $model = ""
            }

            # Getting the PKID is generally problematic for anyone other than OEMs, so let's skip it here
            $product = ""

            # Depending on the format requested, create the necessary object
            if ($Partner)
            {
                # Create a pipeline object
                $c = New-Object psobject -Property @{
                    "Device Serial Number" = $serial
                    "Windows Product ID" = $product
                    "Hardware Hash" = $hash
                    "Manufacturer name" = $make
                    "Device model" = $model
                }
                # From spec:
                # "Manufacturer Name" = $make
                # "Device Name" = $model

            }
            else
            {
                # Create a pipeline object
                $c = New-Object psobject -Property @{
                    "Device Serial Number" = $serial
                    "Windows Product ID" = $product
                    "Hardware Hash" = $hash
                }
                
                if ($GroupTag -ne "")
                {
                    Add-Member -InputObject $c -NotePropertyName "Group Tag" -NotePropertyValue $GroupTag
                }
                if ($AssignedUser -ne "")
                {
                    Add-Member -InputObject $c -NotePropertyName "Assigned User" -NotePropertyValue $AssignedUser
                }
            }

            # Write the object to the pipeline or array
            if ($bad)
            {
                # Report an error when the hash isn't available
                Write-Error -Message "Unable to retrieve device hardware data (hash) from computer $comp" -Category DeviceError
            }
            elseif ($OutputFile -eq "")
            {
                $c
            }
            else
            {
                $computers += $c
                Write-Host "Gathered details for device with serial number: $serial"
            }

            Remove-CimSession $session
        }
    }

    End
    {
        if ($OutputFile -ne "")
        {
            if ($Append)
            {
                if (Test-Path $OutputFile)
                {
                    $computers += Import-CSV -Path $OutputFile
                }
            }
            if ($Partner)
            {
                $computers | Select "Device Serial Number", "Windows Product ID", "Hardware Hash", "Manufacturer name", "Device model" | ConvertTo-CSV -NoTypeInformation | % {$_ -replace '"',''} | Out-File $OutputFile
            }
            elseif ($AssignedUser -ne "")
            {
                $computers | Select "Device Serial Number", "Windows Product ID", "Hardware Hash", "Group Tag", "Assigned User" | ConvertTo-CSV -NoTypeInformation | % {$_ -replace '"',''} | Out-File $OutputFile
            }
            elseif ($GroupTag -ne "")
            {
                $computers | Select "Device Serial Number", "Windows Product ID", "Hardware Hash", "Group Tag" | ConvertTo-CSV -NoTypeInformation | % {$_ -replace '"',''} | Out-File $OutputFile
            }
            else
            {
                $computers | Select "Device Serial Number", "Windows Product ID", "Hardware Hash" | ConvertTo-CSV -NoTypeInformation | % {$_ -replace '"',''} | Out-File $OutputFile
            }
        }
        if ($Online)
        {
            # Add the devices
            $importStart = Get-Date
            $imported = @()
            $computers | % {
                # Write-Host "-SerialNumber $($_.'Device Serial Number')"
                # Write-Host "-hardwareIdentifier $($_.'Hardware Hash')"
                # Write-Host "-groupTag $($_.'Group Tag')"
                # Write-Host "-assignedUser $($_.'Assigned User')"
                $imported += Add-AutopilotImportedDevice -serialNumber $_.'Device Serial Number' -hardwareIdentifier $_.'Hardware Hash' -assignedUser $_.'Assigned User'
            }

            # Wait until the devices have been imported
            $processingCount = 1
            while ($processingCount -gt 0)
            {
                $current = @()
                $processingCount = 0
                $imported | % {
                    $device = Get-AutopilotImportedDevice -id $_.id
                    if ($device.state.deviceImportStatus -eq "unknown") {
                        $processingCount = $processingCount + 1
                    }
                    $current += $device
                }
                $deviceCount = $imported.Length
                Write-Host "Waiting for $processingCount of $deviceCount to be imported"
                if ($processingCount -gt 0){
                    Start-Sleep 30
                }
            }
            $importDuration = (Get-Date) - $importStart
            $importSeconds = [Math]::Ceiling($importDuration.TotalSeconds)
            $successCount = 0
            $current | % {
                Write-Host "$($device.serialNumber): $($device.state.deviceImportStatus) $($device.state.deviceErrorCode) $($device.state.deviceErrorName)"
                if ($device.state.deviceImportStatus -eq "complete") {
                    $successCount = $successCount + 1
                }
            }
            Write-Host "$successCount devices imported successfully. Elapsed time to complete import: $importSeconds seconds"
            
            # Wait until the devices can be found in Intune (should sync automatically)
            $syncStart = Get-Date
            $processingCount = 1
            while ($processingCount -gt 0)
            {
                $autopilotDevices = @()
                $processingCount = 0
                $current | % {
                    if ($device.state.deviceImportStatus -eq "complete") {
                        $device = Get-AutopilotDevice -id $_.state.deviceRegistrationId
                        if (-not $device) {
                            $processingCount = $processingCount + 1
                        }
                        $autopilotDevices += $device
                    }    
                }
                $deviceCount = $autopilotDevices.Length
                Write-Host "Waiting for $processingCount of $deviceCount to be synced"
                if ($processingCount -gt 0){
                    Start-Sleep 30
                }
            }
            $syncDuration = (Get-Date) - $syncStart
            $syncSeconds = [Math]::Ceiling($syncDuration.TotalSeconds)
            Write-Host "All devices synced. Elapsed time to complete sync: $syncSeconds seconds"

            # Add the device to the specified AAD group
            if ($AddToGroup)
            {
                $aadGroup = Get-AzureADGroup -Filter "DisplayName eq '$AddToGroup'"
                if ($aadGroup)
                {
                    $autopilotDevices | % {
                        $aadDevice = Get-AzureADDevice -ObjectId "deviceid_$($_.azureActiveDirectoryDeviceId)"
                        if ($aadDevice) {
                            Write-Host "Adding device $($_.serialNumber) to group $AddToGroup"
                            Add-AzureADGroupMember -ObjectId $aadGroup.ObjectId -RefObjectId $aadDevice.ObjectId
                        }
                        else {
                            Write-Error "Unable to find Azure AD device with ID $($_.azureActiveDirectoryDeviceId)"
                        }
                    }
                    Write-Host "Added devices to group '$AddToGroup' ($($aadGroup.ObjectId))"
                }
                else {
                    Write-Error "Unable to find group $AddToGroup"
                }
            }

            # Assign the computer name
            if ($AssignedComputerName -ne "")
            {
                $autopilotDevices | % {
                    Set-AutopilotDevice -Id $_.Id -displayName $AssignedComputerName
                }
            }

            # Wait for assignment (if specified)
            if ($Assign)
            {
                $assignStart = Get-Date
                $processingCount = 1
                while ($processingCount -gt 0)
                {
                    $processingCount = 0
                    $autopilotDevices | % {
                        $device = Get-AutopilotDevice -id $_.id -Expand
                        if (-not ($device.deploymentProfileAssignmentStatus.StartsWith("assigned"))) {
                            $processingCount = $processingCount + 1
                        }
                    }
                    $deviceCount = $autopilotDevices.Length
                    Write-Host "Waiting for $processingCount of $deviceCount to be assigned"
                    if ($processingCount -gt 0){
                        Start-Sleep 30
                    }    
                }
                $assignDuration = (Get-Date) - $assignStart
                $assignSeconds = [Math]::Ceiling($assignDuration.TotalSeconds)
                Write-Host "Profiles assigned to all devices. Elapsed time to complete assignment: $assignSeconds seconds"    
                if ($Reboot)
                {
                    Restart-Computer -Force
                }
            }
        }
    }
}
#EndRegion - Get-WindowsAutopilotInfo
#Region - Menu
do {
    do {

        Write-Host "-----
        Please make a selection for action" -f Cyan 
        
        $userAction = Read-Host "
[1] Add Device to Intune
[2] REMOVE Device from Autopilot, Intune, and Azure | Use this if a deployment fails before just trying again
[3] Get devices deployment status | Useful for getting the ID's of apps a deployment is hung on
[4] Update windows | Use this if it's a brand new computer and you sense there will be updates to install. Run BEFORE you enroll the device in Intune

[0] Exit Script
-----
"
        switch ($userAction) {
            1 { Enroll-Device}
            2 { 
            
            # Identify all the Bitlocker volumes.
            $BitlockerVolumers = Get-BitLockerVolume

            # For each volume, get the RecoveryPassowrd and display it.
            $BitlockerVolumers |
            ForEach-Object {
                $MountPoint = $_.MountPoint 
                $RecoveryKey = [string]($_.KeyProtector).RecoveryPassword       
                if ($RecoveryKey.Length -gt 5) {
                    Write-Output ("The drive $MountPoint has a recovery key $RecoveryKey.")
                    }        
                }
                if ($null -ne $RecoveryKey) {
                    Write-Host "A Recovery Key was found. Please save the Recovery Key to a USB before proceeding.
                    $RecoveryKey" -ForegroundColor Yellow
                    While ($RecoveryKey_Exists -ne "Yes") {                      
                        $RecoveryKey_Exists = Read-Host "Please type Yes once the Recovery Key has been saved." }

                        }
                  
            
            AutopilotNuke }
            3 { Get-AutopilotESPStatus -Online }
            4 { UpdateWindows }
            0 { Stop-Transcript;exit }
        }
    }  while($userAction -notmatch "[12340]")
} until($userAction -eq "0")
#EndRegion - Menu
