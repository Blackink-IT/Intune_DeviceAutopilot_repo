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

#Region - PRP-70 — UCPD pre-configure helper (OOBE-side, before ImmyBot onboarding)
# PRP-70 (2026-05-07) — Configure the User Choice Protection Driver (UCPD)
# while the device is still in OOBE under this script's control. Routes
# around the suppress-reboots constraint that PRP-26 enforces during
# ImmyBot onboarding sessions: ImmyBot's Configure UCPD task aborts when
# `$RebootPreference -eq 'Suppress'`, but allowing reboots mid-chain
# breaks the Autopilot reseal flow (commit 9bb8fa4). UCPD has to be set
# before ImmyBot ever sees the device.
#
# `$Enabled` hardcoded `$false` — matches the existing ImmyBot Configure
# UCPD deployment's parameter value (operator-confirmed 2026-05-07).
# No per-tenant override; if a tenant ever needs UCPD enabled, that's a
# follow-up PRP.
#
# De-Immy'd version of the operator's ImmyBot script:
#   - `Invoke-ImmyCommand{}` wrappers stripped (we ARE on the endpoint).
#   - `ScheduledTaskShould-Be` replaced with native Get/Disable/Enable
#     -ScheduledTask cmdlets.
#   - `Restart-ComputerAndWait` replaced with `Restart-Computer -Force`
#     (script terminates; OOBE resumes on next boot).
#   - `Throw "...reboots were suppressed"` removed — in OOBE we always
#     allow reboots, by construction.
#
# Idempotent: if the service is already in the desired state, no reboot
# is triggered.
Function Invoke-BiitOobeUcpdConfigure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [bool]$Enabled
    )

    Write-Host "`n--- UCPD pre-configuration ---" -ForegroundColor Cyan
    $Service = Get-Service -Name 'UCPD' -ErrorAction SilentlyContinue
    if (-not $Service) {
        Write-Host "[UCPD] Service not present on this Windows build — skipping." -ForegroundColor Yellow
        return $true
    }

    $ServiceDesiredState = if ($Enabled) { 'Running' } else { 'Stopped' }
    $TaskDesiredState    = if ($Enabled) { 'Ready'   } else { 'Disabled' }

    $ServiceInDesiredState = ($Service.Status.ToString() -eq $ServiceDesiredState)
    $Task = Get-ScheduledTask -TaskName 'UCPD velocity' -ErrorAction SilentlyContinue
    $TaskInDesiredState = $Task -and ($Task.State.ToString() -eq $TaskDesiredState)

    # Reconcile the scheduled task first — no reboot needed.
    if ($Task -and -not $TaskInDesiredState) {
        try {
            if ($TaskDesiredState -eq 'Disabled') {
                Disable-ScheduledTask -TaskName 'UCPD velocity' -ErrorAction Stop | Out-Null
                Write-Host "[UCPD] Scheduled task 'UCPD velocity' -> Disabled" -ForegroundColor Gray
            } else {
                Enable-ScheduledTask -TaskName 'UCPD velocity' -ErrorAction Stop | Out-Null
                Write-Host "[UCPD] Scheduled task 'UCPD velocity' -> Ready" -ForegroundColor Gray
            }
        } catch {
            Write-Host "[UCPD] Scheduled task reconcile failed: $_" -ForegroundColor Yellow
            # Non-fatal — service-state reconcile below is the load-bearing piece.
        }
    }

    if ($ServiceInDesiredState) {
        Write-Host "[UCPD] Service already $ServiceDesiredState — no reboot needed." -ForegroundColor Green
        return $true
    }

    # Service config requires sc.exe and a reboot to take effect.
    $startMode = if ($Enabled) { 'system' } else { 'disabled' }
    Write-Host "[UCPD] Configuring service start mode -> $startMode (reboot required)" -ForegroundColor Yellow
    Start-Process 'sc.exe' -ArgumentList "config UCPD start= $startMode" -Wait -NoNewWindow

    # 30-second visible warning per PRP-70 §"Locked-in answers" item 3a.
    # Single static message + sleep — no countdown loop. Operators
    # confirmed silent-run preference, but the pre-reboot warning is the
    # operator-awareness step.
    Write-Host ''
    Write-Host '====================================================' -ForegroundColor Yellow
    Write-Host '  UCPD configured. Computer will reboot in 30 seconds.' -ForegroundColor Yellow
    Write-Host '  DO NOT INTERRUPT. OOBE will resume on next boot.' -ForegroundColor Yellow
    Write-Host '====================================================' -ForegroundColor Yellow
    Write-Host ''
    Start-Sleep -Seconds 30
    Restart-Computer -Force
    # script execution ends here.
}
#EndRegion - PRP-70

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
    try{
        Write-Host "Script has been initiated. USB no longer needs to be plugged in to this device. Feel free to unplug it and move on to the next PC" -foregroundcolor Yellow

        Write-Host "

        Checking for and setting up the needed PowerShell package providers, modules, and scripts. Please wait:"

        #Enable TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        #Region - Install Modules and scripts
        Check-PowerShellModule -ModuleName Microsoft.Graph.Users
        Check-PowerShellModule -ModuleName Microsoft.Graph.Groups
        Check-PowerShellModule -ModuleName Microsoft.Graph.Identity.DirectoryManagement
        Check-PowerShellModule -ModuleName NuGet
        Check-PowerShellModule -ModuleName WindowsAutoPilotIntune
        Check-PowerShellModule -ModuleName Microsoft.Graph.Intune
        
        #WindowsAutoPilotIntune: https://www.powershellgallery.com/packages/WindowsAutoPilotIntune/5.0

        #Region Get and assign variables
        Write-Host("

        Please provide the needed data to upload the device info to the clients Intune portal. If you get an error about incorrect sign in info YOU entered info wrong.") -ForegroundColor Yellow

        #Connect to Microsoft Graph
        Write-Host "Please sign in to Microsoft Graph to begin the device upload process" -ForegroundColor Yellow
        Connect-MgGraph -Scopes "User.Read.All", "DeviceManagementServiceConfig.ReadWrite.All", "Group.ReadWrite.All", "Device.ReadWrite.All", "DeviceManagementManagedDevices.ReadWrite.All"
        $context = Get-MgContext
        Write-Host "Connected to tenant: $($context.TenantId)"

        #Username of person that needs to be assigned
        while(($StandardDeployment -eq "") -or ($null -eq $StandardDeployment) -or ("yes","no" -notcontains $StandardDeployment)){
        $StandardDeployment = Read-host 'Is this PC going to be used as a SPARE or does it need a different Autopilot enrollment profile/status page (Please enter "yes" or "no")?'}

        if($StandardDeployment -eq 'No'){
            # Get all enabled users and display in Out-GridView for selection
            Write-Host "Loading all enabled users from Azure AD. Please wait..." -ForegroundColor Yellow
            
            $AllUsers = Get-MgUser -Filter "accountEnabled eq true" -All | 
                        Select-Object DisplayName, UserPrincipalName, Mail, Department, JobTitle | 
                        Sort-Object DisplayName
            
            Write-Host "Please select the user from the grid view..." -ForegroundColor Cyan
            
            $SelectedUser = $AllUsers | Out-GridView -Title "Select the user for this device" -PassThru
            
            if($null -eq $SelectedUser){
                Write-Host "No user was selected. Please try again." -ForegroundColor Red
                while($null -eq $SelectedUser){
                    $SelectedUser = $AllUsers | Out-GridView -Title "Select the user for this device (REQUIRED)" -PassThru
                }
            }
            
            $UPN = $SelectedUser.UserPrincipalName
            $QueryDisplayName = $SelectedUser.DisplayName
            $UPNId = (Get-MgUser -Filter "userPrincipalName eq '$UPN'").Id
            
            Write-Host "User Confirmed. Looks like $QueryDisplayName ($UPN) is getting a new computer." -ForegroundColor green
        }


        #Get desired computer name
        while(($ComputerName -eq "") -or ($null -eq $ComputerName)){
            $ComputerName = Read-Host 'What would you like to name this device? (NOTE name applies after white glove is completed)'
            Write-Host "Checking to see if that device name is already taken..."
            While ($ComputerName.length -gt 15) {
                Write-Host "
            Please enter 15 or less than characters for the computer name. Windows does not allow more than 15 characters." -foregroundcolor red
                $ComputerName = Read-Host 'What would you like to name this device? (NOTE name applies after white glove is completed)'
            }
            #Check computer name in Autopilot devices
            $AllDevices = Get-AutopilotDevice
            ForEach($Device in $AllDevices){
                if($ComputerName -eq $Device.displayName){
                    Write-Host "It looks like this device name ($ComputerName) was already taken by another autopilot device. Please try again." -foregroundcolor red
                    $ComputerName = $Null
                }
            }
            #Check computer name in Azure AD (now using Microsoft Graph)
            if($null -ne $ComputerName){
                $AllDevices = Get-MgDevice -All
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
        $GroupName = "Intune_Devices_AutopilotDeployed"
        #endregion

        #Check for valid group (using Microsoft Graph)
        $QueryGroup = Get-MgGroup -All | Where-Object{$_.displayName -like "*$GroupName*"}
        while($null -eq $QueryGroup){
            $QueryGroup = Get-MgGroup -All | Select-Object DisplayName,Description,Id
            if($QueryGroup.DisplayName -notcontains "Enroll_AutoPilot_v1"){
                $QueryGroup += New-Object psobject -Property @{
                    DisplayName = "Enroll_AutoPilot_v1"
                    Description = "This group is for all devices that have been deployed using this Autopilot profile 'Enroll_AutoPilot_v1' as well as any 'Generic Installers'. Devices deployed through BIIT's script are placed in this group."
                    Id = $null
                }
                Write-Host "The AutoPilot profile 'Enroll_AutoPilot_v1' may not exist because the group Intune_Devices_AutopilotDeployed does not yet exist" -ForegroundColor Red
                Write-Host "Please talk to infrastructure about ensuring the autopilot profile exists in Intune for this client" -ForegroundColor Red
            }
            $QueryGroup = $QueryGroup | Select-Object DisplayName,Description,Id | Sort-Object DisplayName | Out-GridView -PassThru -Title "Please select which group you would like to put the device in"
            if(($null -eq $QueryGroup.Id) -and ($null -ne $QueryGroup)){
                $groupParams = @{
                    DisplayName = $QueryGroup.DisplayName
                    MailEnabled = $false
                    SecurityEnabled = $true
                    MailNickname = "NotSet"
                    Description = $QueryGroup.Description
                }
                New-MgGroup -BodyParameter $groupParams
            }
        }

        #To save time start checking for windows updates
        $SilentWindowsUpdateBlock = {Import-Module -Name PSWindowsUpdate -Force
        Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot -silent}
        Write-Host "
        While things are running windows updates will be installed silently in the background" -foregroundcolor Magenta
        $JobStart = Start-Job -ScriptBlock $SilentWindowsUpdateBlock

        #Get Serial Number
        $serial = (Get-WmiObject -class win32_bios).SerialNumber  

        #Kick off device upload process
        if(($null -eq $UPN) -or ($UPN -eq "")){
            Get-WindowsAutoPilotInfo -Online -AddToGroup $GroupName -Assign -AssignedComputerName $ComputerName
        }else{
            Get-WindowsAutoPilotInfo -Online -AddToGroup $GroupName -Assign -AssignedUser $UPN -AssignedComputerName $ComputerName
        }

        #Get Autopilot assignment info
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
                #Ensure device is in group (using Microsoft Graph)
                $DeviceObjectID = $(Get-MgDevice -Filter "displayName eq '$serial'").Id
                $GroupMembershipCheck = $(Get-MgGroupMember -GroupId $QueryGroup.Id -All)
                if(!($GroupMembershipCheck.Id -contains $DeviceObjectID)){
                    Write-host "The Azure AD Group $($QueryGroup.DisplayName) did not contain the device $serial | Attempting to add it now. If it fails this will loop forever. To fix this login to the 365 and add the device to the group manually" -ForegroundColor Yellow
                    $bodyParam = @{
                        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$DeviceObjectID"
                    }
                    New-MgGroupMemberByRef -GroupId $QueryGroup.Id -BodyParameter $bodyParam
                }
                $DeviceObjectID = $null
                $GroupMembershipCheck = $null

                Set-AutopilotDevice -userPrincipalName $UPN -Id $id -addressableUserName $QueryDisplayName -displayName $ComputerName
                Start-Sleep -Seconds 5
                $device = Get-AutopilotDevice -serial $serial
                $addressableUserName = $Device.addressableUserName
                $userPrincipalName = $Device.userPrincipalName
                $displayName = $Device.displayName
                Write-Host "
        Could not find the assigned user $QueryDisplayName ($UPN) assigned to device $serial. Trying to apply these parameters again and will query after a 5 second wait timer."
            }
        }Else{
                Write-Host "
        It does look like the Display Name (addressableUserName) and userPrincipalName (Users username to login) assigned fine. It is $QueryDisplayName and $userPrincipalName respectively" -ForegroundColor Green
            }

        While($displayName -eq ""){
            #Ensure device is in group (using Microsoft Graph)
            $DeviceObjectID = $(Get-MgDevice -Filter "displayName eq '$serial'").Id
            $GroupMembershipCheck = $(Get-MgGroupMember -GroupId $QueryGroup.Id -All)
            if(!($GroupMembershipCheck.Id -contains $DeviceObjectID)){
                Write-host "The Azure AD Group $($QueryGroup.DisplayName) did not contain the device $serial | Attempting to add it now. If it fails this will loop forever. To fix this login to the 365 and add the device to the group manually" -ForegroundColor Yellow
                $bodyParam = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$DeviceObjectID"
                }
                New-MgGroupMemberByRef -GroupId $QueryGroup.Id -BodyParameter $bodyParam
            }
            $DeviceObjectID = $null
            $GroupMembershipCheck = $null

            Set-AutopilotDevice -Id $id -displayName $ComputerName
            Start-Sleep -Seconds 5
            $device = Get-AutopilotDevice -serial $serial
            $displayName = $Device.displayName
            if($displayName -eq ""){
                Write-Host "
            Could not find the computer name $ComputerName assigned to device $serial. Trying to apply these parameters again and will query after a 5 second wait timer."
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
        Please REVIEW the below parameters and ensure they are correct.
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
        Write-Host "
    Installing windows updates at this section removed. If you desire to update windows please use option 4" -foregroundcolor yellow
        $StopJob = Get-Job | Stop-Job
        #UpdateWindows -InstallUpdates "Yes"
        Stop-Transcript
    }catch{
        # Handle the exception
        Write-Output "
        
        
An error occurred: $_"
        Write-Output "Error message: $($_.Exception.Message)"
        Write-Output "Error line number: $($_.InvocationInfo.ScriptLineNumber)"
    }
}

#Autopilot Nuke pulled from here: https://www.powershellgallery.com/packages/AutopilotNuke/3.6/Content/autopilotnuke.ps1
Function AutopilotNuke(){
    <#PSScriptInfo
    .VERSION 3.6
    .GUID b608a45b-6cd0-405e-bfb2-aa11450821b5
    .AUTHOR Alexey Semibratov - Updated by Andrew Taylor
    .COMPANYNAME
    .COPYRIGHT Alexey Semibratov
    .TAGS
    .LICENSEURI https://github.com/andrew-s-taylor/WindowsAutopilotInfo/blob/main/LICENSE
    .PROJECTURI
    .ICONURI
    .EXTERNALMODULEDEPENDENCIES
    .REQUIREDSCRIPTS
    .EXTERNALSCRIPTDEPENDENCIES
    .RELEASENOTES
    Version 3.6: Added None option for assigned user
    Version 3.5: Function update
    Version 3.4: Fix in function name
    Version 3.3: Changed method to grab devices
    Version 3.2: Second fix
    Version 3.1: Fix
    Version 3.0: Updated to work with SDK v2
    Version 2.9: Remove-MgDevice ObjectID switched to ID to match updated module
    Version 2.8: Fixed speechmarks issue
    Version 2.7: Changed Autopilot delete method
    Version 2.6: Fixed mg-device command
    Version 2.5: Typo
    Version 2.4: Switched to MgGraph SDK and added support for app reg
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
    - Intended usage - from OOBE (Out of Box Experience)
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
    • This script will install the required modules
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
        [Parameter(Mandatory = $False)] [String] $TenantId = "",
        [Parameter(Mandatory = $False)] [String] $AppId = "",
        [Parameter(Mandatory = $False)] [String] $AppSecret = ""
    )


    Function Connect-ToGraph {
        <#
    .SYNOPSIS
    Authenticates to the Graph API via the Microsoft.Graph.Authentication module.
    
    .DESCRIPTION
    The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.
    
    .PARAMETER Tenant
    Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
    
    .PARAMETER AppId
    Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.
    
    .PARAMETER AppSecret
    Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.
    
    .PARAMETER Scopes
    Specifies the user scopes for interactive authentication.
    
    .EXAMPLE
    Connect-ToGraph -TenantId $tenantID -AppId $app -AppSecret $secret
    
    -#>
        [cmdletbinding()]
        param
        (
            [Parameter(Mandatory = $false)] [string]$Tenant,
            [Parameter(Mandatory = $false)] [string]$AppId,
            [Parameter(Mandatory = $false)] [string]$AppSecret,
            [Parameter(Mandatory = $false)] [string]$scopes
        )

        Process {
            Import-Module Microsoft.Graph.Authentication
            $version = (get-module microsoft.graph.authentication | Select-Object -expandproperty Version).major

            if ($AppId -ne "") {
                $body = @{
                    grant_type    = "client_credentials";
                    client_id     = $AppId;
                    client_secret = $AppSecret;
                    scope         = "https://graph.microsoft.com/.default";
                }
        
                $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token -Body $body
                $accessToken = $response.access_token
        
                $accessToken
                if ($version -eq 2) {
                    write-host "Version 2 module detected"
                    $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
                }
                else {
                    write-host "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                    $accesstokenfinal = $accessToken
                }
                $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
                Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
            }
            else {
                if ($version -eq 2) {
                    write-host "Version 2 module detected"
                }
                else {
                    write-host "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                }
                $graph = Connect-MgGraph -scopes $scopes
                Write-Host "Connected to Intune tenant $($graph.TenantId)"
            }
        }
    }    

    function getdevicesandusers() {
        $alldevices = getallpagination -url "https://graph.microsoft.com/beta/devicemanagement/manageddevices"
        $outputarray = @()
        foreach ($value in $alldevices) {
            $objectdetails = [pscustomobject]@{
                DeviceID = $value.id
                DeviceName = $value.deviceName
                OSVersion = $value.operatingSystem
                PrimaryUser = $value.userPrincipalName
                operatingSystem = $value.operatingSystem
                AADID = $value.azureActiveDirectoryDeviceId
                SerialNumber = $value.serialnumber

            }
        
        
            $outputarray += $objectdetails
        
        }
        
        return $outputarray
        }

        function getallpagination () {
            <#
        .SYNOPSIS
        This function is used to grab all items from Graph API that are paginated
        .DESCRIPTION
        The function connects to the Graph API Interface and gets all items from the API that are paginated
        .EXAMPLE
        getallpagination -url "https://graph.microsoft.com/v1.0/groups"
        Returns all items
        .NOTES
        NAME: getallpagination
        #>
        [cmdletbinding()]
            
        param
        (
            $url
        )
            $response = (Invoke-MgGraphRequest -uri $url -Method Get -OutputType PSObject)
            $alloutput = $response.value
            
            $alloutputNextLink = $response."@odata.nextLink"
            
            while ($null -ne $alloutputNextLink) {
                $alloutputResponse = (Invoke-MGGraphRequest -Uri $alloutputNextLink -Method Get -outputType PSObject)
                $alloutputNextLink = $alloutputResponse."@odata.nextLink"
                $alloutput += $alloutputResponse.value
            }
            
            return $alloutput
            }

    Write-Host "Downloading and installing all required modules, please accept all prompts"

            # Get NuGet
            $provider = Get-PackageProvider NuGet -ErrorAction Ignore
            if (-not $provider) {
                Write-Host "Installing provider NuGet"
                Find-PackageProvider -Name NuGet -ForceBootstrap -IncludeDependencies
            }
            
            # Get Graph Authentication module (and dependencies)
            $module = Import-Module microsoft.graph.authentication -PassThru -ErrorAction Ignore
            if (-not $module) {
                Write-Host "Installing module microsoft.graph.authentication"
                Install-Module microsoft.graph.authentication -Force -ErrorAction Ignore
            }
            Import-Module microsoft.graph.authentication -Scope Global

                $module = Import-Module microsoft.graph.groups -PassThru -ErrorAction Ignore
                if (-not $module) {
                    Write-Host "Installing module MS Graph Groups"
                    Install-Module microsoft.graph.groups -Force -ErrorAction Ignore
                }
                Import-Module microsoft.graph.groups -Scope Global


            $module2 = Import-Module Microsoft.Graph.Identity.DirectoryManagement -PassThru -ErrorAction Ignore
            if (-not $module2) {
                Write-Host "Installing module MS Graph Identity Management"
                Install-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction Ignore
            }
            Import-Module microsoft.graph.Identity.DirectoryManagement -Scope Global

            $module3 = Import-Module WindowsAutopilotIntuneCommunity -PassThru -ErrorAction Ignore
            if (-not $module3) {
                Write-Host "Installing module WindowsAutopilotIntuneCommunity"
                Install-Module WindowsAutopilotIntuneCommunity -Force -ErrorAction Ignore
            }
            Import-Module WindowsAutopilotIntuneCommunity -Scope Global


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

    Write-Host "Connecting to Intune Graph"

    if ($AppId -ne "") {
        Connect-ToGraph -Tenant $TenantId -AppId $AppId -AppSecret $AppSecret
        Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
    }
    else {
        $graph = Connect-ToGraph -scopes "Group.ReadWrite.All, Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, GroupMember.ReadWrite.All"
        Write-Host "Connected to Intune tenant $($graph.TenantId)"
        if ($AddToGroup) {
            $aadId = Connect-ToGraph -scopes "Group.ReadWrite.All, Device.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, GroupMember.ReadWrite.All"
            Write-Host "Connected to Azure AD tenant $($aadId.TenantId)"
        }
    }

    Write-Host "Loading all objects. This can take a while on large tenants"
    $aadDevices = getallpagination -url "https://graph.microsoft.com/beta/devices"

    $devices = getdevicesandusers

        $intunedevices = $devices | Where-Object {$_.operatingSystem -eq "Windows"}

    ##$autopilotDevices = Get-AutopilotDevice | Get-MSGraphAllPages
    $autopilotDevices = Get-AutopilotDevice


    $localADfqdn = Read-Host -Prompt 'If you want to *DELETE* this computer from your local Active Directory domain and have Domain Controllers in line of sight, please enter the DNS of your AD DS domain (ie domain.local or contoso.com), otherwise, to skip AD DS deletion, hit "Enter"'
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
    }


    $currentAutopilotDevice = $autopilotDevices | Where-Object {$_.serialNumber -eq $serial}

    if ($currentAutopilotDevice -ne $null)
    {

        # Find the objects linked to the Autopilot device

        Write-Verbose $currentAutopilotDevice |  Format-List -Property *
        
        [array]$relatedIntuneDevice = $intuneDevices | Where-Object {
        $_.serialNumber -eq $currentAutopilotDevice.serialNumber -or 
        $_.serialNumber -eq $currentAutopilotDevice.serialNumber.replace(' ','') -or 
        $_.id -eq $currentAutopilotDevice.managedDeviceId -or 
        $_.azureADDeviceId -eq $currentAutopilotDevice.azureActiveDirectoryDeviceId}       
    
        [array]$FoundAADDevices = $aadDevices | Where-Object { 
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
                    $deviceid = $relIntuneDevice.id
                    $url = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceid"
                    $response = Invoke-MgGraphRequest -Uri $url -Method Delete -OutputType PSObject
                #Remove-IntuneManagedDevice -managedDeviceId $relIntuneDevice.id -ErrorAction Continue
                }
            }

        }


    
        if($Host.UI.PromptForChoice('Delete Autopilot Device', 'Do you want to *DELETE* the device with serial number ' + $currentAutopilotDevice.serialNumber +' from the Autopilot?', @('&Yes'; '&No'), 1) -eq 0){
        
            $id = $currentAutopilotDevice.id
            $graphApiVersion = "beta"
            $Resource = "deviceManagement/windowsAutopilotDeviceIdentities"    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"
            Invoke-MGGraphRequest -Uri $uri -Method DELETE
            #Remove-AutopilotDevice -id $currentAutopilotDevice.id -ErrorAction Continue
            $SecondsSinceLastSync = $null
            $SecondsSinceLastSync = (New-Timespan -Start (Get-AutopilotSyncInfo).lastSyncDateTime.ToUniversalTime()  -End (Get-Date).ToUniversalTime()).TotalSeconds
            If ($SecondsSinceLastSync -ge 610)
            {
                Invoke-AutopilotSync 
                
            }
            else
            {
                Write-Host "Last sync was" $SecondsSinceLastSync "seconds ago, will sleep for" (610-$SecondsSinceLastSync) "seconds before trying to sync."
                if($Host.UI.PromptForChoice('Autopilot Sync','Do you want to wait?', @('&Yes'; '&No'), 1) -eq 0){Start-Sleep -Seconds (610-$SecondsSinceLastSync) ; Invoke-AutopilotSync}            
            }
            while (Get-AutopilotDevice  | Where-Object {$_.serialNumber -eq $serial} -ne $null){
                Start-Sleep -Seconds 5                        
        }
        Write-Host "Deleted"

        }

    }

    if($relatedIntuneDevice -eq $null -and $FoundAADDevices -eq $null ){
        # this serial number was not found in Autopilot Devices, but we still want to check intune devices with this serial number and search AAD and AD DS for that one
        [array]$relatedIntuneDevice = $intuneDevices | Where-Object {$_.serialNumber -eq $serial -or $_.serialNumber -eq $serial.replace(' ','')}
        [array]$FoundAADDevices = $aadDevices | Where-Object { $_.DeviceId -eq $relatedIntuneDevice.azureADDeviceId }
        Write-Host "Found Related Intune Devices:"

        $relatedIntuneDevice | Format-Table -Property deviceName, id, userID, enrolledDateTime, LastSyncDateTime, operatingSystem, osVersion, deviceEnrollmentType

        Write-Host "Found Related AAD Devices:"

        $FoundAADDevices | Format-Table -Property DisplayName, ObjectID, DeviceID, AccountEnabled, ApproximateLastLogonTimeStamp, DeviceTrustType, DirSyncEnabled, LastDirSyncTime -AutoSize  


        if($relatedIntuneDevice -ne $null){
            foreach($relIntuneDevice in $relatedIntuneDevice)        {
                $displayName=$relIntuneDevice.deviceName
                if($Host.UI.PromptForChoice('Delete Intune Device', 'Do you want to *DELETE* ' + $relIntuneDevice.deviceName +' from the Intune?', @('&Yes'; '&No'), 1) -eq 0){
                    $deviceid = $relIntuneDevice.id
                    $url = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceid"
                    $response = Invoke-MgGraphRequest -Uri $url -Method Delete -OutputType PSObject
                #Remove-IntuneManagedDevice -managedDeviceId $relIntuneDevice.id -ErrorAction Stop
                }
            }

        }

    }



    foreach($aadDevice in $FoundAADDevices){
        if($de -ne $null){            
            $escapedguid = "\" + ((([GUID]$aadDevice.deviceID).ToByteArray() |ForEach-Object {"{0:x}" -f $_}) -join '\')
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
            
            Remove-mgdevice -DeviceId $aadDevice.Id -ErrorAction SilentlyContinue
        }
        
    }


    # Get the hash (if available)
    $devDetail = (Get-CimInstance -CimSession $session -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'")
    if ($devDetail)
    {
        $hash = $devDetail.DeviceHardwareData
        if($Host.UI.PromptForChoice('Add Autopilot Device', 'Do you want to *ADD* the device with serial number ' + $serial +' to Autopilot?', @('&Yes'; '&No'), 1) -eq 0){
            
            $newuserPrincipalName = Read-Host -Prompt "Change assigned user [$userPrincipalName] (type a new value or hit enter to keep the old one. Enter None to not set a user)"
            if (![string]::IsNullOrWhiteSpace($newuserPrincipalName)){ $userPrincipalName = $newuserPrincipalName }

            $newgroupTag = Read-Host -Prompt "Change group tag [$groupTag] (type a new value or hit enter to keep the old one)"
            if (![string]::IsNullOrWhiteSpace($newgroupTag)){ $groupTag = $newgroupTag }

            ##If "None has been selected, don't add assigneduser"
            
            if ($userPrincipalName -eq "None") {
            Add-AutopilotImportedDevice -serialNumber $serial -hardwareIdentifier $hash -groupTag $groupTag
            }
            else {
            Add-AutopilotImportedDevice -serialNumber $serial -hardwareIdentifier $hash -groupTag $groupTag -assignedUser $userPrincipalName        
            }

            $SecondsSinceLastSync = $null
            $SecondsSinceLastSync = (New-Timespan -Start (Get-AutopilotSyncInfo).lastSyncDateTime.ToUniversalTime()  -End (Get-Date).ToUniversalTime()).TotalSeconds
            If ($SecondsSinceLastSync -ge 610)
            {
                Invoke-AutopilotSync            
            }
            else
            {
                Write-Host "Last sync was" $SecondsSinceLastSync "seconds ago, will sleep for" (610-$SecondsSinceLastSync) "seconds before trying to sync."
                if($Host.UI.PromptForChoice('Autopilot Sync','Do you want to wait?', @('&Yes'; '&No'), 0) -eq 0){Start-Sleep -Seconds (610-$SecondsSinceLastSync); Invoke-AutopilotSync}
                
            }
            
        }

    }

    if($Host.UI.PromptForChoice('Computer name','Do you want to configure a unique name for a device? This name will be ignored in Hybrid Azure AD joined deployments. Device name still comes from the domain join profile for Hybrid Azure AD devices. This will only work if you have not deleted the device from AP recently.', @('&Yes'; '&No'), 1) -eq 0){

        $newdisplayName = Read-Host -Prompt "[$displayName] (type a new value or hit enter to keep the old one)"
        if (![string]::IsNullOrWhiteSpace($displayName) -or ![string]::IsNullOrWhiteSpace($newdisplayName)){ 
        
            if (![string]::IsNullOrWhiteSpace($newdisplayName) ){ $displayName = $newdisplayName }
            
            $autopilotDevices = Get-AutopilotDevice

            [array]$currentAutopilotDevices = $autopilotDevices | Where-Object {$_.serialNumber -eq $serial}

            foreach($currentAutopilotDevice in $currentAutopilotDevices){
            
                Set-AutopilotDevice -id $currentAutopilotDevice.id -displayName $displayName 
            }
                
        }

    }
}

#Pulled from here: https://www.powershellgallery.com/packages/Get-AutopilotDiagnosticsCommunity/5.9
function Get-AutopilotDiagnostics{
    param(
        [Parameter(Mandatory = $False)] [String] $CABFile = $null,
        [Parameter(Mandatory = $False)] [String] $ZIPFile = $null,
        [Parameter(Mandatory = $False)] [Switch] $Online = $false,
        [Parameter(Mandatory = $False)] [Switch] $AllSessions = $false,
        [Parameter(Mandatory = $False)] [Switch] $ShowPolicies = $false,
        [Parameter(Mandatory = $false)] [string]$Tenant,
        [Parameter(Mandatory = $false)] [string]$AppId,
        [Parameter(Mandatory = $false)] [string]$AppSecret
    )

    Begin {
        # Process log files if needed
        $script:useFile = $false
        if ($CABFile -or $ZIPFile) {

            if (-not (Test-Path "$($env:TEMP)\ESPStatus.tmp")) {
                New-Item -Path "$($env:TEMP)\ESPStatus.tmp" -ItemType "directory" | Out-Null
            }
            Remove-Item -Path "$($env:TEMP)\ESPStatus.tmp\*.*" -Force -Recurse        
            $script:useFile = $true

            # If using a CAB file, extract the needed files from it
            if ($CABFile) {
                $fileList = @("MdmDiagReport_RegistryDump.reg", "microsoft-windows-devicemanagement-enterprise-diagnostics-provider-admin.evtx",
                    "microsoft-windows-user device registration-admin.evtx", "AutopilotDDSZTDFile.json", "*.csv")

                $fileList | % {
                    $null = & expand.exe "$CABFile" -F:$_ "$($env:TEMP)\ESPStatus.tmp\" 
                    if (-not (Test-Path "$($env:TEMP)\ESPStatus.tmp\$_")) {
                        Write-Error "Unable to extract $_ from $CABFile"
                    }
                }
            }
            else {
                # If using a ZIP file, just extract the entire contents (not as easy to do selected files)
                Expand-Archive -Path $ZIPFile -DestinationPath "$($env:TEMP)\ESPStatus.tmp\"
            }

            # Get the hardware hash information
            $csvFile = (Get-ChildItem "$($env:TEMP)\ESPStatus.tmp\*.csv").FullName
            if ($csvFile) {
                $csv = Get-Content $csvFile | ConvertFrom-Csv
                $hash = $csv.'Hardware Hash'
            }

            # Edit the path in the .reg file
            $content = Get-Content -Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_RegistryDump.reg"
            $content = $content -replace "\[HKEY_CURRENT_USER\\", "[HKEY_CURRENT_USER\ESPStatus.tmp\USER\"
            $content = $content -replace "\[HKEY_LOCAL_MACHINE\\", "[HKEY_CURRENT_USER\ESPStatus.tmp\MACHINE\"
            $content = $content -replace '^ "', '"'
            $content = $content -replace '^ @', '@'
            $content = $content -replace 'DWORD:', 'dword:'
            "Windows Registry Editor Version 5.00`n" | Set-Content -Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_Edited.reg"
            $content | Add-Content -Path "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_Edited.reg"

            # Remove the registry info if it exists
            if (Test-Path "HKCU:\ESPStatus.tmp") {
                Remove-Item -Path "HKCU:\ESPStatus.tmp" -Recurse -Force
            }

            # Import the .reg file
            $null = & reg.exe IMPORT "$($env:TEMP)\ESPStatus.tmp\MdmDiagReport_Edited.reg" 2>&1

            # Configure the (not live) constants
            $script:provisioningPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\provisioning"
            $script:autopilotDiagPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\provisioning\Diagnostics\Autopilot"
            $script:omadmPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\provisioning\OMADM"
            $script:path = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics"
            $script:msiPath = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\EnterpriseDesktopAppManagement"
            $script:officePath = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\OfficeCSP"
            $script:sidecarPath = "HKCU:\ESPStatus.tmp\MACHINE\Software\Microsoft\IntuneManagementExtension\Win32Apps"
            $script:enrollmentsPath = "HKCU:\ESPStatus.tmp\MACHINE\software\microsoft\enrollments"
        }
        else {
            # Configure live constants
            $script:provisioningPath = "HKLM:\software\microsoft\provisioning"
            $script:autopilotDiagPath = "HKLM:\software\microsoft\provisioning\Diagnostics\Autopilot"
            $script:omadmPath = "HKLM:\software\microsoft\provisioning\OMADM"
            $script:path = "HKLM:\Software\Microsoft\Windows\Autopilot\EnrollmentStatusTracking\ESPTrackingInfo\Diagnostics"
            $script:msiPath = "HKLM:\Software\Microsoft\EnterpriseDesktopAppManagement"
            $script:officePath = "HKLM:\Software\Microsoft\OfficeCSP"
            $script:sidecarPath = "HKLM:\Software\Microsoft\IntuneManagementExtension\Win32Apps"
            $script:enrollmentsPath = "HKLM:\Software\Microsoft\enrollments"

            $hash = (Get-WmiObject -Namespace root/cimv2/mdm/dmmap -Class MDM_DevDetail_Ext01 -Filter "InstanceID='Ext' AND ParentID='./DevDetail'").DeviceHardwareData
        }

        # Configure other constants
        $script:officeStatus = @{"0" = "None"; "10" = "Initialized"; "20" = "Download In Progress"; "25" = "Pending Download Retry";
            "30" = "Download Failed"; "40" = "Download Completed"; "48" = "Pending User Session"; "50" = "Enforcement In Progress"; 
            "55" = "Pending Enforcement Retry"; "60" = "Enforcement Failed"; "70" = "Success / Enforcement Completed"
        }
        $script:espStatus = @{"1" = "Not Installed"; "2" = "Downloading / Installing"; "3" = "Success / Installed"; "4" = "Error / Failed" }
        $script:policyStatus = @{"0" = "Not Processed"; "1" = "Processed" }

        # Configure any other global variables
        $script:observedTimeline = @()
    }

    Process {
        #------------------------
        # Functions
        #------------------------

        
    Function Connect-ToGraph {
        <#
    .SYNOPSIS
    Authenticates to the Graph API via the Microsoft.Graph.Authentication module.
    
    .DESCRIPTION
    The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.
    
    .PARAMETER Tenant
    Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
    
    .PARAMETER AppId
    Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.
    
    .PARAMETER AppSecret
    Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.
    
    .PARAMETER Scopes
    Specifies the user scopes for interactive authentication.
    
    .EXAMPLE
    Connect-ToGraph -TenantId $tenantID -AppId $app -AppSecret $secret
    
    -#>
        [cmdletbinding()]
        param
        (
            [Parameter(Mandatory = $false)] [string]$Tenant,
            [Parameter(Mandatory = $false)] [string]$AppId,
            [Parameter(Mandatory = $false)] [string]$AppSecret,
            [Parameter(Mandatory = $false)] [string]$scopes
        )

        Process {
            Import-Module Microsoft.Graph.Authentication
            $version = (get-module microsoft.graph.authentication | Select-Object -expandproperty Version).major

            if ($AppId -ne "") {
                $body = @{
                    grant_type    = "client_credentials";
                    client_id     = $AppId;
                    client_secret = $AppSecret;
                    scope         = "https://graph.microsoft.com/.default";
                }
        
                $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token -Body $body
                $accessToken = $response.access_token
        
                $accessToken
                if ($version -eq 2) {
                    write-host "Version 2 module detected"
                    $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
                }
                else {
                    write-host "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                    $accesstokenfinal = $accessToken
                }
                $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
                Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
            }
            else {
                if ($version -eq 2) {
                    write-host "Version 2 module detected"
                }
                else {
                    write-host "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                }
                $graph = Connect-MgGraph -scopes $scopes
                Write-Host "Connected to Intune tenant $($graph.TenantId)"
            }
        }
    }    

        Function RecordStatus() {
            param
            (
                [Parameter(Mandatory = $true)] [String] $detail,
                [Parameter(Mandatory = $true)] [String] $status,
                [Parameter(Mandatory = $true)] [String] $color,
                [Parameter(Mandatory = $true)] [datetime] $date
            )

            # See if there is already an entry for this policy and status
            $found = $script:observedTimeline | ? { $_.Detail -eq $detail -and $_.Status -eq $status }
            if (-not $found) {
                $script:observedTimeline += New-Object PSObject -Property @{
                    "Date"   = $date
                    "Detail" = $detail
                    "Status" = $status
                    "Color"  = $color
                }
            }
        }

        Function AddDisplay() {
            param
            (
                [Parameter(Mandatory = $true)] [ref]$items
            )
            $items.Value | % {
                Add-Member -InputObject $_ -NotePropertyName display -NotePropertyValue $AllSessions
            }
            $items.Value[$items.Value.Count - 1].display = $true
        }
        
        Function ProcessApps() {
            param
            (
                [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
                [Parameter(Mandatory = $true)] $currentUser,
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
            )

            Begin {
                if ($display) { Write-Host "Apps:" }
            }

            Process {
                if ($display) { Write-Host " $(([datetime]$currentKey.PSChildName).ToString('u'))" }
                $currentKey.Property | % {
                    if ($_.StartsWith("./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/")) {
                        $msiKey = [URI]::UnescapeDataString(($_.Split("/"))[6])
                        $fullPath = "$msiPath\$currentUser\MSI\$msiKey"
                        if (Test-Path $fullPath) {
                            $status = (Get-ItemProperty -Path $fullPath).Status
                            $msiFile = (Get-ItemProperty -Path $fullPath).CurrentDownloadUrl
                        }
                        if ($status -eq "" -or $status -eq $null) {
                            $status = 0
                        } 
                        if ($msiFile -match "IntuneWindowsAgent.msi") {
                            $msiKey = "Intune Management Extensions ($($msiKey))"
                        }
                        elseif ($Online) {
                            $found = $apps | ? { $_.ProductCode -contains $msiKey }
                            $msiKey = "$($found.DisplayName) ($($msiKey))"
                        }
                        if ($status -eq 70) {
                            if ($display) { Write-Host " MSI $msiKey : $status ($($officeStatus[$status.ToString()]))" -ForegroundColor Green }
                            RecordStatus -detail "MSI $msiKey" -status $officeStatus[$status.ToString()] -color "Green" -date $currentKey.PSChildName
                        }
                        elseif ($status -eq 60) {
                            if ($display) { Write-Host " MSI $msiKey : $status ($($officeStatus[$status.ToString()]))" -ForegroundColor Red }
                            RecordStatus -detail "MSI $msiKey" -status $officeStatus[$status.ToString()] -color "Red" -date $currentKey.PSChildName
                        }
                        else {
                            if ($display) { Write-Host " MSI $msiKey : $status ($($officeStatus[$status.ToString()]))" -ForegroundColor Yellow }
                            RecordStatus -detail "MSI $msiKey" -status $officeStatus[$status.ToString()] -color "Yellow" -date $currentKey.PSChildName
                        }
                    }
                    elseif ($_.StartsWith("./Vendor/MSFT/Office/Installation/")) {
                        # Report the main status based on what ESP is tracking
                        $status = Get-ItemPropertyValue -Path $currentKey.PSPath -Name $_

                        # Then try to get the detailed Office status
                        $officeKey = [URI]::UnescapeDataString(($_.Split("/"))[5])
                        $fullPath = "$officepath\$officeKey"
                        if (Test-Path $fullPath) {
                            $oStatus = (Get-ItemProperty -Path $fullPath).FinalStatus

                            if ($oStatus -eq $null) {
                                $oStatus = (Get-ItemProperty -Path $fullPath).Status
                                if ($oStatus -eq $null) {
                                    $oStatus = "None"
                                }
                            }
                        }
                        else {
                            $oStatus = "None"
                        }
                        if ($officeStatus.Keys -contains $oStatus.ToString()) {
                            $officeStatusText = $officeStatus[$oStatus.ToString()]
                        }
                        else {
                            $officeStatusText = $oStatus
                        }
                        if ($status -eq 1) {
                            if ($display) { Write-Host " Office $officeKey : $status ($($policyStatus[$status.ToString()]) / $officeStatusText)" -ForegroundColor Green }
                            RecordStatus -detail "Office $officeKey" -status "$($policyStatus[$status.ToString()]) / $officeStatusText" -color "Green" -date $currentKey.PSChildName
                        }
                        else {
                            if ($display) { Write-Host " Office $officeKey : $status ($($policyStatus[$status.ToString()]) / $officeStatusText)" -ForegroundColor Yellow }
                            RecordStatus -detail "Office $officeKey" -status "$($policyStatus[$status.ToString()]) / $officeStatusText" -color "Yellow" -date $currentKey.PSChildName
                        }
                    }
                    else {
                        if ($display) { Write-Host " $_ : Unknown app" }
                    }
                }
            }

        }

        Function ProcessModernApps() {
            param
            (
                [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
                [Parameter(Mandatory = $true)] $currentUser,
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
            )

            Begin {
                if ($display) { Write-Host "Modern Apps:" }
            }

            Process {
                if ($display) { Write-Host " $(([datetime]$currentKey.PSChildName).ToString('u'))" }
                $currentKey.Property | % {
                    $status = (Get-ItemPropertyValue -path $currentKey.PSPath -Name $_).ToString()
                    if ($_.StartsWith("./User/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/")) {
                        $appID = [URI]::UnescapeDataString(($_.Split("/"))[7])
                        $type = "User UWP"
                    }
                    elseif ($_.StartsWith("./Device/Vendor/MSFT/EnterpriseModernAppManagement/AppManagement/")) {
                        $appID = [URI]::UnescapeDataString(($_.Split("/"))[7])
                        $type = "Device UWP"
                    }
                    else {
                        $appID = $_
                        $type = "Unknown UWP"
                    }
                    if ($status -eq "1") {
                        if ($display) { Write-Host " $type $appID : $status ($($policyStatus[$status]))" -ForegroundColor Green }
                        RecordStatus -detail "UWP $appID" -status $policyStatus[$status] -color "Green" -date $currentKey.PSChildName
                    }
                    else {
                        if ($display) { Write-Host " $type $appID : $status ($($policyStatus[$status]))" -ForegroundColor Yellow }
                    }
                }
            }

        }

        Function ProcessSidecar() {
            param
            (
                [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
                [Parameter(Mandatory = $true)] $currentUser,
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
            )

            Begin {
                if ($display) { Write-Host "Sidecar apps:" }
            }

            Process {
                if ($display) { Write-Host " $(([datetime]$currentKey.PSChildName).ToString('u'))" }
                $currentKey.Property | % {
                    $win32Key = [URI]::UnescapeDataString(($_.Split("/"))[9])
                    $status = Get-ItemPropertyValue -path $currentKey.PSPath -Name $_
                    if ($Online) {
                        $found = $apps | ? { $win32Key -match $_.Id }
                        $win32Key = "$($found.DisplayName) ($($win32Key))"
                    }
                    $appGuid = $win32Key.Substring(9)
                    $sidecarApp = "$sidecarPath\$currentUser\$appGuid"
                    $exitCode = $null
                    if (Test-Path $sidecarApp) {
                        $exitCode = (Get-ItemProperty -Path $sidecarApp).ExitCode
                    }
                    if ($status -eq "3") {
                        if ($exitCode -ne $null) {
                            if ($display) { Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]), rc = $exitCode)" -ForegroundColor Green }
                        }
                        else {
                            if ($display) { Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]))" -ForegroundColor Green }
                        }
                        RecordStatus -detail "Win32 $win32Key" -status $espStatus[$status.ToString()] -color "Green" -date $currentKey.PSChildName
                    }
                    elseif ($status -eq "4") {
                        if ($exitCode -ne $null) {
                            if ($display) { Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]), rc = $exitCode)" -ForegroundColor Red }
                        }
                        else {
                            if ($display) { Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]))" -ForegroundColor Red }
                        }
                        RecordStatus -detail "Win32 $win32Key" -status $espStatus[$status.ToString()] -color "Red" -date $currentKey.PSChildName
                    }
                    else {
                        if ($exitCode -ne $null) {
                            if ($display) { Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]), rc = $exitCode)" -ForegroundColor Yellow }
                        }
                        else {
                            if ($display) { Write-Host " Win32 $win32Key : $status ($($espStatus[$status.ToString()]))" -ForegroundColor Yellow }
                        }
                        if ($status -ne "1") {
                            RecordStatus -detail "Win32 $win32Key" -status $espStatus[$status.ToString()] -color "Yellow" -date $currentKey.PSChildName
                        }
                    }
                }
            }

        }

        Function ProcessPolicies() {
            param
            (
                [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
            )

            Begin {
                if ($display) { Write-Host "Policies:" }
            }

            Process {
                if ($display) { Write-Host " $(([datetime]$currentKey.PSChildName).ToString('u'))" }
                $currentKey.Property | % {
                    $status = Get-ItemPropertyValue -path $currentKey.PSPath -Name $_
                    if ($status -eq "1") {
                        if ($display) { Write-Host " Policy $_ : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Green }
                        RecordStatus -detail "Policy $_" -status $policyStatus[$status.ToString()] -color "Green" -date $currentKey.PSChildName
                    }
                    else {
                        if ($display) { Write-Host " Policy $_ : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Yellow }
                    }
                }
            }

        }

        Function ProcessCerts() {
            param
            (
                [Parameter(Mandatory = $true, ValueFromPipeline = $True)] [Microsoft.Win32.RegistryKey] $currentKey,
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $True)] [bool] $display
            )

            Begin {
                if ($display) { Write-Host "Certificates:" }
            }

            Process {
                if ($display) { Write-Host " $(([datetime]$currentKey.PSChildName).ToString('u'))" }
                $currentKey.Property | % {
                    $certKey = [URI]::UnescapeDataString(($_.Split("/"))[6])
                    $status = Get-ItemPropertyValue -path $currentKey.PSPath -Name $_
                    if ($Online) {
                        $found = $policies | ? { $certKey.Replace("_", "-") -match $_.Id }
                        $certKey = "$($found.DisplayName) ($($certKey))"
                    }
                    if ($status -eq "1") {
                        if ($display) { Write-Host " Cert $certKey : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Green }
                        RecordStatus -detail "Cert $certKey" -status $policyStatus[$status.ToString()] -color "Green" -date $currentKey.PSChildName
                    }
                    else {
                        if ($display) { Write-Host " Cert $certKey : $status ($($policyStatus[$status.ToString()]))" -ForegroundColor Yellow }
                    }
                }
            }

        }

        Function ProcessNodeCache() {

            Process {
                $nodeCount = 0
                while ($true) {
                    # Get the nodes in order. This won't work after a while because the older numbers are deleted as new ones are added
                    # but it will work out OK shortly after provisioning. The alternative would be to get all the subkeys and then sort
                    # them numerically instead of alphabetically, but that can be saved for later...
                    $node = Get-ItemProperty "$provisioningPath\NodeCache\CSP\Device\MS DM Server\Nodes\$nodeCount" -ErrorAction SilentlyContinue
                    if ($node -eq $null) {
                        break
                    }
                    $nodeCount += 1
                    $node | Select NodeUri, ExpectedValue
                }
            }

        }

        Function ProcessEvents() {

            Process {

                $productCode = 'IME-Not-Yet-Installed'
                if (Test-Path "$msiPath\S-0-0-00-0000000000-0000000000-000000000-000\MSI") {
                    Get-ChildItem -path "$msiPath\S-0-0-00-0000000000-0000000000-000000000-000\MSI" | % {
                        $file = (Get-ItemProperty -Path $_.PSPath).CurrentDownloadUrl
                        if ($file -match "IntuneWindowsAgent.msi") {
                            $productCode = Get-ItemPropertyValue -Path $_.PSPath -Name ProductCode
                        }
                    }
                }

                # Process device management events
                if ($script:useFile) {
                    $events = Get-WinEvent -Path "$($env:TEMP)\ESPStatus.tmp\microsoft-windows-devicemanagement-enterprise-diagnostics-provider-admin.evtx" -Oldest | ? { ($_.Message -match $productCode -and $_.Id -in 1905, 1906, 1920, 1922) -or $_.Id -in (72, 100, 107, 109, 110, 111) }
                }
                else {
                    $events = Get-WinEvent -LogName Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin -Oldest | ? { ($_.Message -match $productCode -and $_.Id -in 1905, 1906, 1920, 1922) -or $_.Id -in (72, 100, 107, 109, 110, 111) }
                }
                $events | % {
                    $message = $_.Message
                    $detail = "Sidecar"
                    $color = "Yellow"
                    $event = $_
                    switch ($_.id) {
                        { $_ -in (110, 109) } { 
                            $detail = "Offline Domain Join"
                            switch ($event.Properties[0].Value) {
                                0 { $message = "Offline domain join not configured" }
                                1 { $message = "Waiting for ODJ blob" }
                                2 { $message = "Processed ODJ blob" }
                                3 { $message = "Timed out waiting for ODJ blob or connectivity" }
                            }
                        }
                        111 { $detail = "Offline Domain Join"; $message = "Starting wait for ODJ blob" }
                        107 { $detail = "Offline Domain Join"; $message = "Successfully applied ODJ blob" }
                        100 { $detail = "Offline Domain Join"; $message = "Could not establish connectivity"; $color = "Red" }
                        72 { $detail = "MDM Enrollment" }
                        1905 { $message = "Download started" }
                        1906 { $message = "Download finished" }
                        1920 { $message = "Installation started" }
                        1922 { $message = "Installation finished" }
                        { $_ -in (1922, 72) } { $color = "Green" }
                    }
                    RecordStatus -detail $detail -date $_.TimeCreated -status $message -color $color
                }

                # Process device registration events
                if ($script:useFile) {
                    $events = Get-WinEvent -Path "$($env:TEMP)\ESPStatus.tmp\microsoft-windows-user device registration-admin.evtx" -Oldest | ? { $_.Id -in (306, 101) }
                }
                else {
                    $events = Get-WinEvent -LogName 'Microsoft-Windows-User Device Registration/Admin' -Oldest | ? { $_.Id -in (306, 101) }
                }
                $events | % {
                    $message = $_.Message
                    $detail = "Device Registration"
                    $color = "Yellow"
                    $event = $_
                    switch ($_.id) {
                        101 { $detail = "Device Registration"; $message = "SCP discovery successful." }
                        304 { $detail = "Device Registration"; $message = "Hybrid AADJ device registration failed." }
                        306 { $detail = "Device Registration"; $message = "Hybrid AADJ device registration succeeded."; $color = 'Green' }
                    }
                    RecordStatus -detail $detail -date $_.TimeCreated -status $message -color $color
                }

            }
        
        }
        
        #------------------------
        # Main code
        #------------------------

        # If online, make sure we are able to authenticate
        if ($Online) {

            #Check if modules are already imported
            $deviceManagementModule = Get-Module -ListAvailable -Name Microsoft.Graph.Beta.DeviceManagement
            $corporateManagementModule = Get-Module -ListAvailable -Name Microsoft.Graph.Beta.Devices.CorporateManagement

            if (-not $deviceManagementModule -or -not $corporateManagementModule) {
                #Try importing the modules and handle errors if they occur
                try {
                    $deviceManagementModule = Import-Module Microsoft.Graph.Beta.DeviceManagement -ErrorAction Stop
                    $corporateManagementModule = Import-Module Microsoft.Graph.Beta.Devices.CorporateManagement -ErrorAction Stop
                }
                catch {
                    Write-Host "Modules not found. Installing required modules..."
                    #Install the modules if import fails
                    Install-Module Microsoft.Graph.Beta.DeviceManagement -Force -AllowClobber
                    Install-Module Microsoft.Graph.Beta.Devices.CorporateManagement -Force -AllowClobber
                    Write-Host "Modules installed successfully."
                }
            }

            #Import the modules again to make them available in the current session
            Import-Module Microsoft.Graph.Beta.DeviceManagement
            Import-Module Microsoft.Graph.Beta.Devices.CorporateManagement

            Write-Host "Connect to Graph!"
            #Connect to Graph
            if ($AppId -and $AppSecret -and $tenant) {

                $graph = Connect-ToGraph -Tenant $tenant -AppId $clientid -AppSecret $clientsecret
                write-output "Graph Connection Established"
                }
                else {
                ##Connect to Graph
                
                $graph = Connect-ToGraph -Scopes "DeviceManagementApps.Read.All, DeviceManagementConfiguration.Read.All"
                }
            Write-Host "Connected to tenant $($graph.TenantId)"

            # Get a list of apps
            Write-Host "Getting list of apps"
            $script:apps = Get-MgBetaDeviceAppManagementMobileApp -All

            # Get a list of policies (for certs)
            Write-Host "Getting list of policies"
            $script:policies = Get-MgBetaDeviceManagementConfigurationPolicy -All
        }

        # Display Autopilot diag details
        Write-Host ""
        Write-Host "AUTOPILOT DIAGNOSTICS" -ForegroundColor Magenta
        Write-Host ""

        $values = Get-ItemProperty "$autopilotDiagPath"
        if (-not $values.CloudAssignedTenantId) {
            Write-Host "This is not an Autopilot device.`n"
            exit 0
        }

        if (-not $script:useFile) {
            $osVersion = (Get-WmiObject win32_operatingsystem).Version
            Write-Host "OS version: $osVersion"
        }
        Write-Host "Profile: $($values.DeploymentProfileName)"
        Write-Host "TenantDomain: $($values.CloudAssignedTenantDomain)"
        Write-Host "TenantID: $($values.CloudAssignedTenantId)"
        $correlations = Get-ItemProperty "$autopilotDiagPath\EstablishedCorrelations"
        Write-Host "ZTDID: $($correlations.ZTDRegistrationID)"
        Write-Host "EntDMID: $($correlations.EntDMID)"

        Write-Host "OobeConfig: $($values.CloudAssignedOobeConfig)"

        if (($values.CloudAssignedOobeConfig -band 1024) -gt 0) {
            Write-Host " Skip keyboard: Yes 1 - - - - - - - - - -"
        }
        else {
            Write-Host " Skip keyboard: No 0 - - - - - - - - - -"
        }
        if (($values.CloudAssignedOobeConfig -band 512) -gt 0) {
            Write-Host " Enable patch download: Yes - 1 - - - - - - - - -"
        }
        else {
            Write-Host " Enable patch download: No - 0 - - - - - - - - -"
        }
        if (($values.CloudAssignedOobeConfig -band 256) -gt 0) {
            Write-Host " Skip Windows upgrade UX: Yes - - 1 - - - - - - - -"
        }
        else {
            Write-Host " Skip Windows upgrade UX: No - - 0 - - - - - - - -"
        }
        if (($values.CloudAssignedOobeConfig -band 128) -gt 0) {
            Write-Host " AAD TPM Required: Yes - - - 1 - - - - - - -"
        }
        else {
            Write-Host " AAD TPM Required: No - - - 0 - - - - - - -"
        }
        if (($values.CloudAssignedOobeConfig -band 64) -gt 0) {
            Write-Host " AAD device auth: Yes - - - - 1 - - - - - -"
        }
        else {
            Write-Host " AAD device auth: No - - - - 0 - - - - - -"
        }
        if (($values.CloudAssignedOobeConfig -band 32) -gt 0) {
            Write-Host " TPM attestation: Yes - - - - - 1 - - - - -"
        }
        else {
            Write-Host " TPM attestation: No - - - - - 0 - - - - -"
        }
        if (($values.CloudAssignedOobeConfig -band 16) -gt 0) {
            Write-Host " Skip EULA: Yes - - - - - - 1 - - - -"
        }
        else {
            Write-Host " Skip EULA: No - - - - - - 0 - - - -"
        }
        if (($values.CloudAssignedOobeConfig -band 8) -gt 0) {
            Write-Host " Skip OEM registration: Yes - - - - - - - 1 - - -"
        }
        else {
            Write-Host " Skip OEM registration: No - - - - - - - 0 - - -"
        }
        if (($values.CloudAssignedOobeConfig -band 4) -gt 0) {
            Write-Host " Skip express settings: Yes - - - - - - - - 1 - -"
        }
        else {
            Write-Host " Skip express settings: No - - - - - - - - 0 - -"
        }
        if (($values.CloudAssignedOobeConfig -band 2) -gt 0) {
            Write-Host " Disallow admin: Yes - - - - - - - - - 1 -"
        }
        else {
            Write-Host " Disallow admin: No - - - - - - - - - 0 -"
        }

        # In theory we could read these values from the profile cache registry key, but it's so bungled
        # up in the registry export that it doesn't import without some serious massaging for embedded
        # quotes. So this is easier.
        if ($script:useFile) {
            $jsonFile = "$($env:TEMP)\ESPStatus.tmp\AutopilotDDSZTDFile.json"
        }
        else {
            $jsonFile = "$($env:WINDIR)\ServiceState\wmansvc\AutopilotDDSZTDFile.json" 
        }
        if (Test-Path $jsonFile) {
            $json = Get-Content $jsonFile | ConvertFrom-Json
            $date = [datetime]$json.PolicyDownloadDate
            RecordStatus -date $date -detail "Autopilot profile" -status "Profile downloaded" -color "Yellow" 
            if ($json.CloudAssignedDomainJoinMethod -eq 1) {
                Write-Host "Scenario: Hybrid Azure AD Join"
                if (Test-Path "$omadmPath\SyncML\ODJApplied") {
                    Write-Host "ODJ applied: Yes"
                }
                else {
                    Write-Host "ODJ applied: No"                
                }
                if ($json.HybridJoinSkipDCConnectivityCheck -eq 1) {
                    Write-Host "Skip connectivity check: Yes"
                }
                else {
                    Write-Host "Skip connectivity check: No"
                }

            }
            else {
                Write-Host "Scenario: Azure AD Join"
            }
        }
        else {
            Write-Host "Scenario: Not available (JSON not found)"
        }

        # Get ESP properties
        Get-ChildItem $enrollmentsPath | ? { Test-Path "$($_.PSPath)\FirstSync" } | % {
            $properties = Get-ItemProperty "$($_.PSPath)\FirstSync"
            Write-Host "Enrollment status page:"
            Write-Host " Device ESP enabled: $($properties.SkipDeviceStatusPage -eq 0)"
            Write-Host " User ESP enabled: $($properties.SkipUserStatusPage -eq 0)"
            Write-Host " ESP timeout: $($properties.SyncFailureTimeout)"
            if ($properties.BlockInStatusPage -eq 0) {
                Write-Host " ESP blocking: No"
            }
            else {
                Write-Host " ESP blocking: Yes"
                if ($properties.BlockInStatusPage -band 1) {
                    Write-Host " ESP allow reset: Yes"
                }
                if ($properties.BlockInStatusPage -band 2) {
                    Write-Host " ESP allow try again: Yes"
                }
                if ($properties.BlockInStatusPage -band 4) {
                    Write-Host " ESP continue anyway: Yes"
                }
            }
        }

        # Get Delivery Optimization statistics (when available)
        if (-not $script:useFile) {
            $stats = Get-DeliveryOptimizationPerfSnapThisMonth
            if ($stats.DownloadHttpBytes -ne 0) {
                $peerPct = [math]::Round( ($stats.DownloadLanBytes / $stats.DownloadHttpBytes) * 100 )
                $ccPct = [math]::Round( ($stats.DownloadCacheHostBytes / $stats.DownloadHttpBytes) * 100 )
            }
            else {
                $peerPct = 0
                $ccPct = 0
            }
            Write-Host "Delivery Optimization statistics:"
            Write-Host " Total bytes downloaded: $($stats.DownloadHttpBytes)"
            Write-Host " From peers: $($peerPct)% ($($stats.DownloadLanBytes))"
            Write-host " From Connected Cache: $($ccPct)% ($($stats.DownloadCacheHostBytes))"
        }

        # If the ADK is installed, get some key hardware hash info
        $adkPath = Get-ItemPropertyValue "HKLM:\Software\Microsoft\Windows Kits\Installed Roots" -Name KitsRoot10 -ErrorAction SilentlyContinue
        $oa3Tool = "$adkPath\Assessment and Deployment Kit\Deployment Tools\$($env:PROCESSOR_ARCHITECTURE)\Licensing\OA30\oa3tool.exe"
        if ($hash -and (Test-Path $oa3Tool)) {
            $commandLineArgs = "/decodehwhash:$hash"
            $output = & "$oa3Tool" $commandLineArgs
            [xml] $hashXML = $output | Select -skip 8 -First ($output.Count - 12)
            Write-Host "Hardware information:"
            Write-Host " Operating system build: " $hashXML.SelectSingleNode("//p[@n='OsBuild']").v
            Write-Host " Manufacturer: " $hashXML.SelectSingleNode("//p[@n='SmbiosSystemManufacturer']").v
            Write-Host " Model: " $hashXML.SelectSingleNode("//p[@n='SmbiosSystemProductName']").v
            Write-Host " Serial number: " $hashXML.SelectSingleNode("//p[@n='SmbiosSystemSerialNumber']").v
            Write-Host " TPM version: " $hashXML.SelectSingleNode("//p[@n='TPMVersion']").v
        }
        
        # Process event log info
        ProcessEvents

        # Display the list of policies
        if ($ShowPolicies) {
            Write-Host " "
            Write-Host "POLICIES PROCESSED" -ForegroundColor Magenta   
            ProcessNodeCache | Format-Table -Wrap
        }
        
        # Make sure the tracking path exists
        if (Test-Path $path) {

            # Process device ESP sessions
            Write-Host " "
            Write-Host "DEVICE ESP:" -ForegroundColor Magenta
            Write-Host " "

            if (Test-Path "$path\ExpectedPolicies") {
                [array]$items = Get-ChildItem "$path\ExpectedPolicies"
                AddDisplay ([ref]$items)
                $items | ProcessPolicies
            }
            if (Test-Path "$path\ExpectedMSIAppPackages") {
                [array]$items = Get-ChildItem "$path\ExpectedMSIAppPackages"
                AddDisplay ([ref]$items)
                $items | ProcessApps -currentUser "S-0-0-00-0000000000-0000000000-000000000-000" 
            }
            if (Test-Path "$path\ExpectedModernAppPackages") {
                [array]$items = Get-ChildItem "$path\ExpectedModernAppPackages"
                AddDisplay ([ref]$items)
                $items | ProcessModernApps -currentUser "S-0-0-00-0000000000-0000000000-000000000-000"
            }
            if (Test-Path "$path\Sidecar") {
                [array]$items = Get-ChildItem "$path\Sidecar" | ? { $_.Property -match "./Device" -and $_.Name -notmatch "LastLoggedState" }
                AddDisplay ([ref]$items)
                $items | ProcessSidecar -currentUser "00000000-0000-0000-0000-000000000000"
            }
            if (Test-Path "$path\ExpectedSCEPCerts") {
                [array]$items = Get-ChildItem "$path\ExpectedSCEPCerts"
                AddDisplay ([ref]$items)
                $items | ProcessCerts
            }

            # Process user ESP sessions
            Get-ChildItem "$path" | ? { $_.PSChildName.StartsWith("S-") } | % {
                $userPath = $_.PSPath
                $userSid = $_.PSChildName
                Write-Host " "
                Write-Host "USER ESP for $($userSid):" -ForegroundColor Magenta
                Write-Host " "
                if (Test-Path "$userPath\ExpectedPolicies") {
                    [array]$items = Get-ChildItem "$userPath\ExpectedPolicies"
                    AddDisplay ([ref]$items)
                    $items | ProcessPolicies
                }
                if (Test-Path "$userPath\ExpectedMSIAppPackages") {
                    [array]$items = Get-ChildItem "$userPath\ExpectedMSIAppPackages" 
                    AddDisplay ([ref]$items)
                    $items | ProcessApps -currentUser $userSid
                }
                if (Test-Path "$userPath\ExpectedModernAppPackages") {
                    [array]$items = Get-ChildItem "$userPath\ExpectedModernAppPackages"
                    AddDisplay ([ref]$items)
                    $items | ProcessModernApps -currentUser $userSid
                }
                if (Test-Path "$userPath\Sidecar") {
                    [array]$items = Get-ChildItem "$path\Sidecar" | ? { $_.Property -match "./User" }
                    AddDisplay ([ref]$items)
                    $items | ProcessSidecar -currentUser $userSid
                }
                if (Test-Path "$userPath\ExpectedSCEPCerts") {
                    [array]$items = Get-ChildItem "$userPath\ExpectedSCEPCerts"
                    AddDisplay ([ref]$items)
                    $items | ProcessCerts
                }
            }
        }
        else {
            Write-Host "ESP diagnostics info does not (yet) exist."
        }

        # Display timeline
        Write-Host ""
        Write-Host "OBSERVED TIMELINE:" -ForegroundColor Magenta
        Write-Host ""
        $observedTimeline | Sort-Object -Property Date |
        Format-Table @{
            Label      = "Date"
            Expression = { $_.Date.ToString("u") } 
        }, 
        @{
            Label      = "Status"
            Expression =
            {
                switch ($_.Color) {
                    'Red' { $color = "91"; break }
                    'Yellow' { $color = '93'; break }
                    'Green' { $color = "92"; break }
                    default { $color = "0" }
                }
                $e = [char]27
                "$e[${color}m$($_.Status)$e[0m"
            }
        },
        Detail

        Write-Host ""
    }

    End {

        # Remove the registry info if it exists
        if (Test-Path "HKCU:\ESPStatus.tmp") {
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

            # Microsoft Graph modules are already loaded by the main Enroll-Device function
            # No need to load deprecated AzureAD module

            # Connect
            if ($AppId -ne "")
            {
                # $graph = Connect-MSGraphApp -Tenant $TenantId -AppId $AppId -AppSecret $AppSecret
                # Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
                Write-Host "Hit need to conenct to MSGraph but this is currently commented out"
            }
            else {
                # $graph = Connect-MSGraph
                # Write-Host "Connected to Intune tenant $($graph.TenantId)"
                Write-Host "Using existing Microsoft Graph connection from Enroll-Device function"
                # No need to connect to AzureAD separately - Microsoft Graph is already connected
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
                # Using Microsoft Graph instead of deprecated AzureAD module
                $aadGroup = Get-MgGroup -Filter "displayName eq '$AddToGroup'" -ErrorAction SilentlyContinue
                if ($aadGroup)
                {
                    $autopilotDevices | % {
                        $deviceId = $_.azureActiveDirectoryDeviceId
                        $serialNum = $_.serialNumber
                        
                        # Retry logic - device may not be immediately available in Azure AD
                        $maxRetries = 12
                        $retryCount = 0
                        $aadDevice = $null
                        
                        while (($null -eq $aadDevice) -and ($retryCount -lt $maxRetries)) {
                            $aadDevice = Get-MgDevice -Filter "deviceId eq '$deviceId'" -ErrorAction SilentlyContinue
                            if ($null -eq $aadDevice) {
                                $retryCount++
                                if ($retryCount -lt $maxRetries) {
                                    Write-Host "Device $serialNum not yet available in Azure AD. Waiting 15 seconds... (Attempt $retryCount of $maxRetries)"
                                    Start-Sleep -Seconds 15
                                }
                            }
                        }
                        
                        if ($aadDevice) {
                            Write-Host "Adding device $serialNum to group $AddToGroup"
                            try {
                                $bodyParam = @{
                                    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($aadDevice.Id)"
                                }
                                New-MgGroupMemberByRef -GroupId $aadGroup.Id -BodyParameter $bodyParam -ErrorAction Stop
                            }
                            catch {
                                if ($_.Exception.Message -like "*already exist*") {
                                    Write-Host "Device $serialNum is already a member of group $AddToGroup"
                                }
                                else {
                                    Write-Error "Failed to add device $serialNum to group: $($_.Exception.Message)"
                                }
                            }
                        }
                        else {
                            Write-Error "Unable to find Azure AD device with ID $deviceId after $maxRetries attempts"
                        }
                    }
                    Write-Host "Added devices to group '$AddToGroup' ($($aadGroup.Id))"
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

#Region - BIIT MSP Portal upload
# PRP-29 (2026-04-24) — Upload hardware hash + serial + model from this
# OOBE device directly into the BIIT MSP Portal's Autopilot intake queue.
# A tech on a BIIT laptop finishes the intake (sets primary user + final
# hostname + Autopilot profile) from /immy/autopilot/pending.
#
# Two auth paths:
#   [1] Sign in with BIIT credentials  — MSAL interactive on the OOBE
#       device itself (device-code fallback on interactive failure).
#   [2] Enroll with a 6-digit code     — BIIT tech generates a code in
#       the portal and hands it to the OOBE operator. No BIIT credentials
#       leave the portal laptop.

Function Invoke-BiitPortalUpload() {
    # Hardcoded constants — safe in a public repo (public-client app IDs
    # + app ID URI + api hostname only; no secrets).
    $BiitTenantId                = "fdec8e68-1a98-4a07-96ca-61d6960dd020"
    $BiitAutopilotIntakeClientId = "9446f70b-ad62-4bcb-aa07-7bc58fecc2f9"
    $BiitAutopilotIntakeScope    = "api://d0e751e8-fac8-429c-98a5-53939e92f535/Autopilot.Intake"
    $PortalApiBase               = "https://2xo4m98krh.execute-api.us-east-2.amazonaws.com/prod"

    Write-Host "`n--- BIIT MSP Portal Upload ---" -ForegroundColor Cyan
    Write-Host "[1] Sign in with BIIT credentials (default)"
    Write-Host "[2] Enroll with a 6-digit code from the portal"
    Write-Host "[3] Cancel"
    $uploadPath = Read-Host "`nSelect an option"
    if ($uploadPath -eq "3" -or [string]::IsNullOrWhiteSpace($uploadPath)) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }
    if ($uploadPath -notin @("1","2")) {
        Write-Host "Invalid selection." -ForegroundColor Red
        return
    }

    # Pull the hash + serial directly via WMI — mirrors what
    # Get-WindowsAutoPilotInfo does internally. Avoids that helper's
    # parameter-set quirk where omitting -Online prompts the operator
    # interactively because -Online is Mandatory in its parameter set.
    Write-Host "`nGathering hardware hash…" -ForegroundColor Gray
    $hardwareHash = $null
    $serialNumber = $null
    try {
        $bios = Get-CimInstance -Class Win32_BIOS -ErrorAction Stop
        $serialNumber = ($bios.SerialNumber | Out-String).Trim()
        $devDetail = Get-CimInstance -Namespace root/cimv2/mdm/dmmap `
            -Class MDM_DevDetail_Ext01 `
            -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" `
            -ErrorAction Stop
        $hardwareHash = $devDetail.DeviceHardwareData
    } catch {
        Write-Host "Hash capture failed via WMI: $_" -ForegroundColor Red
        return
    }

    if ([string]::IsNullOrWhiteSpace($hardwareHash) -or [string]::IsNullOrWhiteSpace($serialNumber)) {
        Write-Host "Hash or serial missing from Autopilot output — cannot upload." -ForegroundColor Red
        return
    }

    # Autopilot supportability gate — Windows Home cannot complete Autopilot
    # enrollment (no MDM/CSP provisioning support); it dies mid-OOBE at the
    # MDMEnrolling phase with 0x80180022. Block the upload here so a Home
    # device never enters the deployment queue and no tech burns cycles
    # re-imaging / re-importing a device that can never enroll. EditionID
    # (registry) is authoritative in OOBE — Core* = the Home family; the OS
    # Caption ("... Home") is the human-readable fallback.
    $editionId = $null
    try { $editionId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID } catch {}
    $osCaption = $null
    try { $osCaption = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
    if (($editionId -match '^Core') -or ($osCaption -match '\bHome\b')) {
        $editionLabel = if ([string]::IsNullOrWhiteSpace($editionId)) { $osCaption } else { $editionId }
        Write-Host ""
        Write-Host "BLOCKED: this device is running Windows Home ($editionLabel)." -ForegroundColor Red
        Write-Host "Windows Home is NOT supported by Windows Autopilot and will fail OOBE enrollment (0x80180022)." -ForegroundColor Red
        Write-Host "Fix: upgrade to Windows Pro / Enterprise / Education (Settings > System > Activation -> change" -ForegroundColor Yellow
        Write-Host "product key or subscription activation; no reinstall needed), then re-run this enrollment step." -ForegroundColor Yellow
        return
    }

    # Model + device type from CIM — independent of the AutoPilot CSV.
    $cs = Get-CimInstance -Class Win32_ComputerSystem
    $model = $cs.Model.Trim()
    # Map Win32_ComputerSystem PCSystemType to our intake enum.
    # 1=Desktop, 2=Mobile(Laptop), 3=Workstation, 4=EnterpriseServer, 5=SOHOServer,
    # 6=AppliancePC, 7=PerformanceServer, 8=Maximum. Surface/AllInOne aren't
    # distinguishable from Win32_ComputerSystem — tech picks at Finish.
    $deviceType = switch ($cs.PCSystemType) {
        1 { "Desktop" }
        2 { "Laptop" }
        3 { "Workstation" }
        default { "Laptop" }
    }

    Write-Host "  Serial: $serialNumber"
    Write-Host "  Model:  $model"
    Write-Host "  Type:   $deviceType"

    if ($uploadPath -eq "1") {
        # Path 1 — BIIT MSAL login on the OOBE device.
        Write-Host "`nAcquiring BIIT token…" -ForegroundColor Gray
        if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
            # OOBE / Windows Setup ships PowerShellGet 1.x which doesn't
            # know -AcceptLicense, often defaults to TLS 1.0 (PSGallery
            # rejects), and is missing the NuGet provider entirely. Force
            # TLS 1.2 + bootstrap NuGet silently + trust PSGallery for the
            # install only, then restore prior PSGallery trust in finally.
            try {
                # TLS 1.2 — older OOBE images default to TLS 1.0/1.1 and
                # silently fail to download from PSGallery without this.
                [Net.ServicePointManager]::SecurityProtocol = `
                    [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

                if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                    Write-Host "Bootstrapping NuGet provider…" -ForegroundColor Gray
                    Install-PackageProvider -Name NuGet `
                        -MinimumVersion 2.8.5.201 `
                        -Force -ForceBootstrap -Confirm:$false `
                        -Scope CurrentUser | Out-Null
                }

                # PSGallery is Untrusted by default; flip to Trusted for
                # the install, then restore in the finally below.
                $prevPolicy = (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue).InstallationPolicy
                if ($prevPolicy -and $prevPolicy -ne 'Trusted') {
                    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                }
                try {
                    Write-Host "Installing MSAL.PS from PSGallery…" -ForegroundColor Gray
                    Install-Module MSAL.PS `
                        -Force -Confirm:$false `
                        -Scope CurrentUser -ErrorAction Stop
                } finally {
                    if ($prevPolicy -and $prevPolicy -ne 'Trusted') {
                        Set-PSRepository -Name PSGallery -InstallationPolicy $prevPolicy
                    }
                }
            } catch {
                Write-Host "Could not install MSAL.PS — falling back to Path 2 (6-digit code) recommended." -ForegroundColor Red
                Write-Host "Error: $_" -ForegroundColor Red
                return
            }
        }
        Import-Module MSAL.PS -ErrorAction Stop

        # Reuse a token from earlier in this script session if one is still
        # valid (≥ 2 min until expiry). Avoids re-prompting MSAL every time
        # the operator picks option 5 again. Cleared automatically when
        # the script exits — no on-disk persistence.
        $token = $null
        if ($script:BiitIntakeToken -and $script:BiitIntakeTokenExpiresAt -and `
            $script:BiitIntakeTokenExpiresAt -gt (Get-Date).AddMinutes(2)) {
            $token = $script:BiitIntakeToken
            $expiresIn = [int](($script:BiitIntakeTokenExpiresAt - (Get-Date)).TotalMinutes)
            Write-Host "Using cached BIIT token (expires in ~$expiresIn min)." -ForegroundColor Gray
        }

        if (-not $token) {
            try {
                $msalToken = Get-MsalToken -ClientId $BiitAutopilotIntakeClientId `
                                           -TenantId $BiitTenantId `
                                           -Scopes  $BiitAutopilotIntakeScope `
                                           -Interactive -ErrorAction Stop
                $token = $msalToken.AccessToken
                $script:BiitIntakeToken          = $token
                $script:BiitIntakeTokenExpiresAt = $msalToken.ExpiresOn.LocalDateTime
            } catch {
                Write-Host "`nInteractive login failed or was cancelled." -ForegroundColor Yellow
                Write-Host "  Reason: $_" -ForegroundColor DarkGray
                Write-Host "`nDevice-code flow is an alternative — you'd visit https://microsoft.com/devicelogin"
                Write-Host "on a phone or another browser and enter a one-time code from this terminal."
                $tryDeviceCode = Read-Host "Try device-code flow now? [y/N]"
                if ($tryDeviceCode -notmatch '^[yY]') {
                    Write-Host "Cancelled. Use option [2] (6-digit portal code) if you can't sign in here." -ForegroundColor Yellow
                    return
                }
                try {
                    $msalToken = Get-MsalToken -ClientId $BiitAutopilotIntakeClientId `
                                               -TenantId $BiitTenantId `
                                               -Scopes  $BiitAutopilotIntakeScope `
                                               -DeviceCode -ErrorAction Stop
                    $token = $msalToken.AccessToken
                    $script:BiitIntakeToken          = $token
                    $script:BiitIntakeTokenExpiresAt = $msalToken.ExpiresOn.LocalDateTime
                } catch {
                    Write-Host "Could not acquire BIIT token: $_" -ForegroundColor Red
                    return
                }
            }
        }

        # Pick a tenant from the portal's tenant list.
        Write-Host "`nFetching BIIT tenant list…" -ForegroundColor Gray
        try {
            $tenantsResp = Invoke-RestMethod -Method GET `
                -Uri "$PortalApiBase/immy/autopilot/intake-from-script/tenants" `
                -Headers @{ Authorization = "Bearer $token" } `
                -TimeoutSec 30 -DisableKeepAlive
        } catch {
            Write-Host "Could not fetch tenant list: $_" -ForegroundColor Red
            return
        }
        $tenants = @($tenantsResp.tenants)
        if ($tenants.Count -eq 0) {
            Write-Host "No tenants returned from portal." -ForegroundColor Red
            return
        }
        Write-Host ""
        for ($i = 0; $i -lt $tenants.Count; $i++) {
            Write-Host ("  [{0,2}] {1} ({2})" -f ($i+1), $tenants[$i].displayName, $tenants[$i].clientIdentifier)
        }
        $choice = Read-Host "`nSelect tenant (number)"
        $idx = ($choice -as [int]) - 1
        if ($idx -lt 0 -or $idx -ge $tenants.Count) {
            Write-Host "Invalid selection." -ForegroundColor Red
            return
        }
        $clientIdentifier = $tenants[$idx].clientIdentifier

        $body = @{
            clientIdentifier = $clientIdentifier
            hardwareHash     = $hardwareHash
            serialNumber     = $serialNumber
            model            = $model
            deviceType       = $deviceType
        } | ConvertTo-Json -Compress

        try {
            Write-Host "`nUploading to portal (30s timeout)…" -ForegroundColor Gray
            $resp = Invoke-RestMethod -Method POST `
                -Uri "$PortalApiBase/immy/autopilot/intake-from-script" `
                -Headers @{ Authorization = "Bearer $token" } `
                -ContentType "application/json" `
                -Body $body `
                -TimeoutSec 30 -DisableKeepAlive
            Write-Host "`nUploaded." -ForegroundColor Green
            Write-Host "  Intake ID:  $($resp.intakeId)"
            Write-Host "  Portal:     https://portal.blackinkit.com/immy/autopilot/pending"

            # PRP-70 — pre-configure UCPD before ImmyBot ever sees the
            # device. Upload above is durable in DDB; reboot here is safe.
            try { Invoke-BiitOobeUcpdConfigure -Enabled $false | Out-Null }
            catch { Write-Host "UCPD pre-configure raised: $_" -ForegroundColor Yellow }
        } catch {
            Write-Host "Upload failed: $_" -ForegroundColor Red
        }
    }
    else {
        # Path 2 — 6-digit code (unauthenticated POST; code carries the auth).
        $code = Read-Host "`nEnter the 6-digit intake code the BIIT tech gave you"
        $code = $code.Trim()
        if ($code -notmatch '^\d{6}$') {
            Write-Host "Code must be 6 digits." -ForegroundColor Red
            return
        }

        # PRP-39 item 1+2 — name prompt for the audit trail. OPTIONAL on both
        # single-use and multi-use codes. It is never a blocker: pressing Enter
        # uploads without a name. The name, when given, pins a multi-use code
        # to that person for the rest of the batch.
        #
        # Do NOT make this mandatory. The original PRP-39 backend REQUIRED the
        # field on multi-use codes while this prompt sat in an unmerged PR, so
        # every multi-use code 401'd "Invalid or expired code" on its FIRST
        # redemption and the 5-strike counter then killed the code. The backend
        # gate was retired 2026-08-20; a hard abort here would just move the
        # same block onto the script side.
        $redeemedByName = (Read-Host "`nYour full name for the audit trail (press Enter to skip)").Trim()
        if ($redeemedByName.Length -gt 80) {
            $redeemedByName = $redeemedByName.Substring(0, 80)
        }

        $body = @{
            code         = $code
            hardwareHash = $hardwareHash
            serialNumber = $serialNumber
            model        = $model
            deviceType   = $deviceType
        }
        # Send the field only when it has a value — the backend 400s on a
        # present-but-blank redeemedByName.
        if (-not [string]::IsNullOrWhiteSpace($redeemedByName)) {
            $body.redeemedByName = $redeemedByName
        }
        $body = $body | ConvertTo-Json -Compress

        try {
            Write-Host "`nUploading to portal (30s timeout)…" -ForegroundColor Gray
            $resp = Invoke-RestMethod -Method POST `
                -Uri "$PortalApiBase/immy/autopilot/intake-by-code" `
                -ContentType "application/json" `
                -Body $body `
                -TimeoutSec 30 -DisableKeepAlive
            Write-Host "`nUploaded." -ForegroundColor Green
            Write-Host "  Intake ID: $($resp.intakeId)"
            Write-Host "  $($resp.message)"

            # PRP-70 — pre-configure UCPD before ImmyBot ever sees the
            # device. Upload above is durable in DDB; reboot here is safe.
            try { Invoke-BiitOobeUcpdConfigure -Enabled $false | Out-Null }
            catch { Write-Host "UCPD pre-configure raised: $_" -ForegroundColor Yellow }
        } catch {
            Write-Host "Upload failed: $_" -ForegroundColor Red
            Write-Host "(A code invalidates after 5 failed attempts — ask the tech for a fresh one rather than retrying.)" -ForegroundColor Yellow
        }
    }
}
#EndRegion - BIIT MSP Portal upload

#Region - BIIT MSP Portal diagnostic upload (PRP-57 Phase C)
Function Build-BiitOobeContextFile {
    <#
    Builds a single text file at C:\Windows\Temp\oobe-context-{serial}.txt
    containing the script-gathered diagnostics that aren't already in the
    MdmDiagnosticsTool CAB:
      - dsregcmd /status (load-bearing for AAD-join failures like 0x801c03f3
        DSREG_AUTOREG_DEVICE_NOT_FOUND — the AzureAdJoined / DomainJoined /
        WorkplaceJoined block + cert chain + DRS endpoint + tenant detail)
      - HKLM:\SOFTWARE\Microsoft\Enrollments registry tree (stale GUIDs
        commonly cause 0x801c03f3 by competing with new enrollment)
      - HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicy + DiagTracking
      - Recent Event Log entries from the channels Microsoft ships
        Autopilot/AAD/MDM events on (User Device Registration, AAD,
        ModernDeployment-Diagnostics-Provider Autopilot, Provisioning-
        Diagnostics-Provider, DeviceManagement-Enterprise-Diagnostics-Provider)
      - Network reachability for the four endpoints whiteglove device-setup
        depends on (enterpriseregistration / device.login / login /
        enrollment.manage.microsoft.com — port 443)
      - Time sync + UTC offset (clock skew breaks token validation)

    Returns the file path on success, $null on hard failure. Each section
    is wrapped in try/catch so one failure doesn't abort the rest.
    #>
    param([string]$Serial)

    $contextPath = "C:\Windows\Temp\oobe-context-$Serial.txt"
    $sb = New-Object System.Text.StringBuilder

    function Add-Section { param([string]$Title) [void]$sb.AppendLine(""); [void]$sb.AppendLine("=" * 72); [void]$sb.AppendLine($Title); [void]$sb.AppendLine("=" * 72) }
    function Add-Line { param([string]$Line) [void]$sb.AppendLine($Line) }

    Add-Section "BIIT MSP Portal — OOBE diagnostic context"
    Add-Line "Generated:  $((Get-Date).ToUniversalTime().ToString('o'))"
    Add-Line "Serial:     $Serial"
    Add-Line "Computer:   $env:COMPUTERNAME"
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        Add-Line "OS:         $($os.Caption) build $($os.BuildNumber)"
        # Autopilot supportability verdict — surfaces the edition as an explicit
        # PASS/FAIL instead of leaving it buried in the OS caption. Home fails
        # OOBE enrollment (0x80180022); Autopilot requires Pro/Enterprise/Education.
        $diagEditionId = $null
        try { $diagEditionId = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID } catch {}
        if (($diagEditionId -match '^Core') -or ($os.Caption -match '\bHome\b')) {
            Add-Line "AP support: *** UNSUPPORTED — Windows Home edition ($diagEditionId); Autopilot requires Pro/Enterprise/Education (fails OOBE with 0x80180022) ***"
        } else {
            Add-Line "AP support: OK (edition $diagEditionId)"
        }
        Add-Line "Last boot:  $($os.LastBootUpTime)"
    } catch { Add-Line "OS info: $_" }
    try { Add-Line "TZ:         $((Get-TimeZone).DisplayName)" } catch {}

    Add-Section "dsregcmd /status"
    try {
        $dsreg = & dsregcmd /status 2>&1 | Out-String
        Add-Line $dsreg
    } catch { Add-Line "dsregcmd failed: $_" }

    Add-Section "HKLM:\SOFTWARE\Microsoft\Enrollments"
    try {
        $regOut = & reg.exe query 'HKLM\SOFTWARE\Microsoft\Enrollments' /s 2>&1 | Out-String
        Add-Line $regOut
    } catch { Add-Line "Enrollments registry read failed: $_" }

    Add-Section "HKLM:\SOFTWARE\Microsoft\Provisioning\AutopilotPolicy"
    try {
        $regOut = & reg.exe query 'HKLM\SOFTWARE\Microsoft\Provisioning\AutopilotPolicy' /s 2>&1 | Out-String
        Add-Line $regOut
    } catch { Add-Line "AutopilotPolicy registry read failed: $_" }

    Add-Section "HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics"
    try {
        $regOut = & reg.exe query 'HKLM\SOFTWARE\Microsoft\Provisioning\Diagnostics\AutoPilot' /s 2>&1 | Out-String
        Add-Line $regOut
    } catch { Add-Line "Provisioning diagnostics registry read failed: $_" }

    # Per-channel MaxEvents — CSP/MDM channels get bigger windows because a
    # 30-minute ESP hang produces hundreds of CSP processing events that we
    # need to scan to find the specific provider that locked up. PaceAirFreight
    # MZ038GGC 2026-05-20 investigation: 50 events was too few; the MDM-sync
    # hang signal lived in events ~60-200 deep on the CSP channel.
    $eventLogConfig = @(
        @{Name='Microsoft-Windows-User Device Registration/Admin';                       Max=100},
        @{Name='Microsoft-Windows-AAD/Operational';                                       Max=300},
        @{Name='Microsoft-Windows-ModernDeployment-Diagnostics-Provider/Autopilot';       Max=300},
        @{Name='Microsoft-Windows-ModernDeployment-Diagnostics-Provider/ManagementService';Max=200},
        @{Name='Microsoft-Windows-Provisioning-Diagnostics-Provider/Admin';               Max=200},
        @{Name='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin';Max=500},
        # CAPI2 + Crypto-NCrypt surface cert chain / TPM key generation
        # activity that backs Sidecar's AAD device cert exchange. Both
        # disabled by default on Win11 26100 so often report 0 events —
        # capture-if-available pattern via try/catch below.
        # (Earlier draft included Microsoft-Windows-CloudAP/Operational +
        # Microsoft-Windows-AAD/Admin — both rejected by Get-WinEvent on
        # Win11 26100 because the channels don't exist. Sidecar's AAD
        # activity surfaces in AAD/Operational which is already captured.)
        @{Name='Microsoft-Windows-CAPI2/Operational';                                     Max=100},
        @{Name='Microsoft-Windows-Crypto-NCrypt/Operational';                             Max=100}
    )
    foreach ($cfg in $eventLogConfig) {
        $lg = $cfg.Name; $max = $cfg.Max
        Add-Section "Event Log — $lg (most recent $max events)"
        # SilentlyContinue (not Stop) so an empty channel doesn't emit a noisy
        # PS>TerminatingError into the transcript log even though try/catch
        # would swallow it. Both "channel doesn't exist on this SKU/build"
        # AND "channel exists but has no matching events" return null without
        # error spam. PaceAirFreight 2026-05-21 fleet-test enrollment log:
        # Get-WinEvent on Crypto-NCrypt/Operational (disabled by default on
        # Win11 26100) dumped the terminating error into the transcript even
        # though it was caught. Cleaned up here.
        $events = Get-WinEvent -LogName $lg -MaxEvents $max -ErrorAction SilentlyContinue
        if ($null -ne $events -and $events.Count -gt 0) {
            foreach ($ev in $events) {
                $msg = if ($ev.Message) { $ev.Message -replace "`r`n", " | " -replace "`n", " | " } else { "<no message>" }
                if ($msg.Length -gt 500) { $msg = $msg.Substring(0, 500) + "...[truncated]" }
                Add-Line ("[{0}] L={1} ID={2} Src={3} :: {4}" -f $ev.TimeCreated.ToString('s'), $ev.LevelDisplayName, $ev.Id, $ev.ProviderName, $msg)
            }
        } else {
            Add-Line "(no events — channel inaccessible, disabled, or empty)"
        }
    }

    # TPM state — TpmOwned=True after a Reset is normal (Win10/11 doesn't
    # clear TPM on reset), but leftover AAD-bound keys in the TPM can break
    # subsequent Autopilot attempts (per Pace MZ038GGC 2026-05-20). Capture
    # both Get-Tpm + Get-TpmEndorsementKeyInfo so we see EK presence.
    Add-Section "TPM state (Get-Tpm + Get-TpmEndorsementKeyInfo)"
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        Add-Line ($tpm | Format-List | Out-String)
        $ek = Get-TpmEndorsementKeyInfo -ErrorAction SilentlyContinue
        if ($ek) { Add-Line ($ek | Format-List | Out-String) }
    } catch { Add-Line "Get-Tpm failed: $_" }

    # BitLocker — Sidecar provisioning can race against BitLocker auto-encrypt
    # if the device meets hardware requirements. Capture volume + protector
    # state. If BitLocker engaged during a prior failed ESP and TPM was then
    # cleared, the volume key can be unrecoverable.
    Add-Section "BitLocker volumes (Get-BitLockerVolume)"
    try {
        $blv = Get-BitLockerVolume -ErrorAction SilentlyContinue
        if ($blv) {
            Add-Line ($blv | Format-Table MountPoint,VolumeStatus,ProtectionStatus,EncryptionPercentage,VolumeType -AutoSize | Out-String)
            foreach ($v in $blv) {
                Add-Line "Protectors on $($v.MountPoint):"
                Add-Line (($v.KeyProtector | Format-List | Out-String))
            }
        } else { Add-Line "No BitLocker volumes reported." }
    } catch { Add-Line "Get-BitLockerVolume failed: $_" }

    # MS-Organization-Access certificates — the AAD device cert lives here.
    # Multiple certs of this issuer = leftover joins from prior attempts =
    # likely cause of the 'AutoPilot device claimed' 0x801c03f2 directory_error.
    Add-Section "MS-Organization certificates (Cert:\LocalMachine\My + Root)"
    try {
        $certs = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
                 Where-Object { $_.Subject -like '*MS-Organization-Access*' -or $_.Issuer -like '*MS-Organization*' }
        if ($certs) {
            foreach ($c in $certs) {
                Add-Line "Subject: $($c.Subject)"
                Add-Line "  Issuer: $($c.Issuer)"
                Add-Line "  NotBefore: $($c.NotBefore)  NotAfter: $($c.NotAfter)"
                Add-Line "  Thumbprint: $($c.Thumbprint)"
                Add-Line ""
            }
        } else { Add-Line "No MS-Organization-Access certs found." }
    } catch { Add-Line "Cert store read failed: $_" }

    # OMA-DM session state — when an MDM sync session hangs (the Pace
    # 2026-05-20 root cause), the session id is recorded here. Compare
    # session GUIDs against the ManagementService event log to find which
    # CSP locked up.
    Add-Section "OMA-DM sessions (HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Sessions)"
    try {
        $omadmOut = & reg.exe query 'HKLM\SOFTWARE\Microsoft\Provisioning\OMADM' /s 2>&1 | Out-String
        Add-Line $omadmOut
    } catch { Add-Line "OMA-DM registry read failed: $_" }

    # Key services that Sidecar / AAD Cloud AP / MDM depend on. A stopped
    # service here can cause silent ESP timeout with no other smoking gun.
    Add-Section "Key Microsoft services (Get-Service)"
    $serviceNames = @('dmwappushservice','wuauserv','w32time','MpsSvc','IKEEXT',
                      'CryptSvc','BFE','EventLog','TrustedInstaller','DcomLaunch',
                      'lfsvc','TokenBroker','wlpasvc','UserManager','WlanSvc',
                      'wcncsvc','WebClient')
    # (Removed 'wppushservice' from earlier draft — typo for the real name
    # 'dmwappushservice' which is already in the list above.)
    foreach ($svc in $serviceNames) {
        try {
            $s = Get-Service -Name $svc -ErrorAction Stop
            Add-Line ("  {0,-25} Status={1,-10}  StartType={2}" -f $svc, $s.Status, $s.StartType)
        } catch { Add-Line "  $svc not found" }
    }

    # MDM-relevant processes — if one of these is missing or hung, ESP
    # blocks. Capture process state + start time so we can see if anything
    # crashed/restarted during the ESP window.
    Add-Section "MDM / AAD processes (Get-Process)"
    $procNames = @('dasHost','MdmDiagnosticsTool','OOBE_FirstLogon','OneSettingsClient',
                   'CloudExperienceHost','OOBE_LogonNoUI','svchost')
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $procNames -contains $_.ProcessName }
        if ($procs) {
            $procs | Sort-Object ProcessName | Format-Table Id,ProcessName,StartTime,@{n='WS_MB';e={[int]($_.WorkingSet64/1MB)}} -AutoSize | Out-String | ForEach-Object { Add-Line $_ }
        }
    } catch { Add-Line "Get-Process failed: $_" }

    # DNS resolver state — which server(s) is the device asking?
    # If Pace's network injects a filtering DNS (e.g. Cisco Umbrella, an
    # internal DNS that drops *.azureedge.net, a captive-portal helper),
    # this is where we'd see it. PaceAirFreight MZ038GGC 2026-05-20: the
    # AAD/MDM endpoints all resolved fine via 8.8.8.8-style upstreams,
    # but if Sidecar's IME content downloads go through a different
    # resolver path (some apps query directly via the configured DNS
    # rather than via the system stub), that resolver might filter
    # *.azureedge.net while leaving manage.microsoft.com alone.
    Add-Section "DNS resolver configuration (Get-DnsClientServerAddress)"
    try {
        $dnsClients = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
                      Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 }
        foreach ($d in $dnsClients) {
            Add-Line ("  {0,-30} (idx {1})  servers = {2}" -f $d.InterfaceAlias, $d.InterfaceIndex, ($d.ServerAddresses -join ','))
        }
    } catch { Add-Line "Get-DnsClientServerAddress failed: $_" }

    Add-Section "Network reachability + DNS + TLS handshake (Autopilot / AAD / MDM / IME endpoints)"
    # Endpoint categories (expanded 2026-05-20 after PaceAirFreight MZ038GGC
    # Sidecar timeout investigation):
    #   AAD/MDM core   — already needed for enrollment to begin (the original
    #                    set)
    #   Intune routing — manage.microsoft.com siblings that the MDM client uses
    #                    for content + policy refresh (referenced in OMA-DM
    #                    session URLs e.g. r.manage.microsoft.com/devicegateway...)
    #   IME content    — naprod*.azureedge.net + swda01-mscdn.azureedge.net
    #                    CDNs where the Intune Management Extension MSI and the
    #                    Win32 app payloads it manages are actually downloaded.
    #                    PaceAirFreight MZ038GGC 2026-05-20: "Policy provider
    #                    'Sidecar' installation timed out after 30 minutes" with
    #                    zero IME artifacts on disk strongly suggests Sidecar
    #                    can't reach these specific CDNs. They were NOT in the
    #                    earlier endpoint list — the AAD/MDM core all resolved
    #                    fine but Sidecar still failed.
    #   WNS push       — Sidecar uses WNS to receive policy-pushed notifications
    #                    during ESP. If WNS is blocked, IME install is silently
    #                    pending.
    #   Delivery Opt   — `*.delivery.mp.microsoft.com` is used by Microsoft's
    #                    content delivery network on Win32 app payloads.
    #   Time           — Sidecar token validation breaks on >5 min clock skew;
    #                    the device must reach a time source.
    $endpoints = @(
        # === AAD / MDM core ===
        'enterpriseregistration.windows.net',
        'device.login.microsoftonline.com',
        'login.microsoftonline.com',
        'enrollment.manage.microsoft.com',
        'manage.microsoft.com',
        'graph.microsoft.com',
        # Sidecar / Cloud Auth Provider specific endpoints. Microsoft routes
        # AAD Cloud AP plugin auth through these — a Test-NetConnection on
        # port 443 isn't enough; we want to see the DNS + TLS handshake
        # actually complete because Sidecar's auth retries don't always
        # surface specific endpoint failures in the event log.
        'aadcdn.msauth.net',
        'login.live.com',
        'autologon.microsoftazuread-sso.com',
        # === Intune service routing ===
        # r.manage.microsoft.com appears in the device's OMA-DM session URL
        # (https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx).
        # If reachable from the AAD/MDM enrollment endpoints but blocked here,
        # the device enrolls but can't sync.
        'r.manage.microsoft.com',
        'i.manage.microsoft.com',
        'fef.manage.microsoft.com',
        # === IME content delivery CDNs (load-bearing for Sidecar/IME install) ===
        # These are the actual download URLs the Intune Management Extension
        # uses for its own MSI + for the Win32 app content it manages.
        # naprod = North America Production, ime = Intune Management Extension.
        'naprodimedatapri.azureedge.net',
        'naprodimedatasec.azureedge.net',
        'naprodimedatahotfix.azureedge.net',
        'swda01-mscdn.azureedge.net',
        # === WNS push (policy notifications during ESP) ===
        'client.wns.windows.com',
        # === Delivery Optimization (Win32 app content) ===
        'dl.delivery.mp.microsoft.com',
        # === Time sync ===
        'time.windows.com'
    )
    foreach ($ep in $endpoints) {
        # DNS resolution — captures whether the hostname even resolves
        try {
            $dns = Resolve-DnsName -Name $ep -Type A -ErrorAction Stop -DnsOnly | Select-Object -First 5
            $ips = ($dns | ForEach-Object { $_.IPAddress }) -join ','
            Add-Line ("  DNS  {0,-45} = {1}" -f $ep, $ips)
        } catch {
            Add-Line ("  DNS  {0,-45} = FAILED: {1}" -f $ep, $_.Exception.Message)
            continue
        }
        # TCP 443 reachability
        try {
            $tnc = Test-NetConnection -ComputerName $ep -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
            Add-Line ("  TCP  {0,-45} = {1}" -f $ep, $tnc)
        } catch {
            Add-Line ("  TCP  {0,-45} = error: {1}" -f $ep, $_.Exception.Message)
        }
        # TLS handshake — confirms cert chain validates against trusted
        # roots, which catches the rare case where DNS+TCP work but TLS
        # fails (proxy MitM, missing root, time skew, etc.)
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.ReceiveTimeout = 5000
            $tcp.SendTimeout = 5000
            $tcp.Connect($ep, 443)
            $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, {param($s,$c,$h,$e) $true})
            $ssl.AuthenticateAsClient($ep)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($ssl.RemoteCertificate)
            Add-Line ("  TLS  {0,-45} = OK  CN={1}  NotAfter={2}" -f $ep, $cert.Subject, $cert.NotAfter.ToString('yyyy-MM-dd'))
            $ssl.Close(); $tcp.Close()
        } catch {
            Add-Line ("  TLS  {0,-45} = FAILED: {1}" -f $ep, $_.Exception.Message)
        }
    }

    # HTTP-level probe to a known IME CDN URL — confirms not just TLS but
    # that an actual HTTP request makes it through any in-path proxy. Naprod
    # IME CDN endpoints serve content over HTTPS; a HEAD against the index
    # path returns 200/403 (Azure CDN's "no specific object requested" reply)
    # if the path is reachable. A 502/503/504 or connection drop indicates
    # an in-path appliance is interfering. Anonymous request OK — these
    # endpoints don't require auth at the connection level, only at the
    # signed-URL level for actual content downloads.
    Add-Section "HTTP-level probe (anonymous HEAD against IME CDNs)"
    $httpProbes = @(
        'https://naprodimedatapri.azureedge.net/',
        'https://naprodimedatasec.azureedge.net/',
        'https://naprodimedatahotfix.azureedge.net/',
        'https://swda01-mscdn.azureedge.net/',
        'https://r.manage.microsoft.com/StatelessRedirector/clientstatus',
        # The Intune Management Extension's MSI is served from here.
        # We can't predict the full signed URL, but a HEAD on the root
        # confirms reachability.
        'https://i.manage.microsoft.com/'
    )
    foreach ($url in $httpProbes) {
        try {
            $req = [System.Net.HttpWebRequest]::Create($url)
            $req.Method = 'HEAD'
            $req.Timeout = 10000
            $req.AllowAutoRedirect = $false
            $req.UserAgent = 'BIIT-OOBE-DiagnosticProbe/1.0'
            $resp = $null
            try { $resp = $req.GetResponse() } catch [System.Net.WebException] {
                # 4xx/5xx still gives us a response with headers — that's
                # what we want. Only a raw socket failure indicates the
                # endpoint is blocked.
                $resp = $_.Exception.Response
                if (-not $resp) { throw }
            }
            $status = [int]$resp.StatusCode
            $hdrs = @()
            foreach ($h in @('Server','x-azure-ref','x-cache','Date','Content-Type')) {
                $v = $resp.Headers[$h]
                if ($v) { $hdrs += ("{0}={1}" -f $h, $v.Substring(0, [Math]::Min($v.Length, 50))) }
            }
            Add-Line ("  HTTP {0,-55} = {1}  {2}" -f $url, $status, ($hdrs -join '; '))
            $resp.Close()
        } catch {
            Add-Line ("  HTTP {0,-55} = FAILED: {1}" -f $url, $_.Exception.Message)
        }
    }

    # Path-MTU probe — large payloads (the IME MSI is ~9 MB, Win32 content
    # is often 50-500 MB) get fragmented; if the network path has a MTU
    # smaller than the device thinks, and the path drops DF=1 packets
    # silently (PMTU black-holes), large downloads stall while small
    # probes succeed. `ping -f -l <size>` sends a packet of <size> with
    # the Don't Fragment bit set; if it succeeds, the path supports at
    # least that MTU. We probe at standard 1500-byte (1472 payload) and
    # at a more conservative 1400 (Microsoft's recommended floor for
    # Intune content downloads). A failure at 1472 but success at 1400
    # is a strong "MTU black-hole" signal worth flagging.
    Add-Section "Path-MTU probe (ping -f -l N) to Microsoft endpoints"
    $mtuTargets = @(
        @{Host='manage.microsoft.com'; Label='Intune service'},
        @{Host='naprodimedatapri.azureedge.net'; Label='IME content CDN'}
    )
    $mtuSizes = @(1472, 1400, 1300)
    foreach ($t in $mtuTargets) {
        foreach ($size in $mtuSizes) {
            try {
                $out = & ping.exe -n 1 -f -l $size -w 3000 $t.Host 2>&1 | Out-String
                $ok = $out -match 'Received = 1'
                $fragNeeded = $out -match 'Packet needs to be fragmented'
                $unreach = $out -match 'unreachable'
                $marker = if ($ok) { 'OK    ' } elseif ($fragNeeded) { 'FRAGMENT' } elseif ($unreach) { 'UNREACH' } else { 'FAIL  ' }
                Add-Line ("  MTU  {0,-45} payload={1,5}  result={2}" -f ($t.Label + ' (' + $t.Host + ')'), $size, $marker)
            } catch {
                Add-Line ("  MTU  {0,-45} payload={1,5}  result=ERROR: {2}" -f $t.Label, $size, $_.Exception.Message)
            }
        }
    }

    # HTTP proxy detection — if a WPAD or PAC-injected proxy is being
    # consulted between our test code and an actual HTTP request, the
    # WinHttp default proxy section above (DIRECT) doesn't catch that.
    # Reading the system's effective .NET WebProxy reveals what the
    # CLR (and therefore IME, which is .NET-based) actually uses.
    Add-Section "Effective .NET WebProxy + WinINet proxy (per-user IE/WinINet view)"
    try {
        $defProxy = [System.Net.WebRequest]::DefaultWebProxy
        $probeUrl = 'https://manage.microsoft.com/'
        $effectiveUri = $defProxy.GetProxy([Uri]$probeUrl)
        if ($effectiveUri.AbsoluteUri -ne $probeUrl) {
            Add-Line "  .NET WebProxy for $probeUrl = $($effectiveUri.AbsoluteUri)"
        } else {
            Add-Line "  .NET WebProxy: DIRECT (no proxy for $probeUrl)"
        }
    } catch { Add-Line ".NET WebProxy probe failed: $_" }
    # WinINet (IE/Edge legacy) — different surface from WinHttp; some
    # apps use WinINet specifically.
    try {
        $wininet = & reg.exe query 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' /v ProxyServer 2>&1 | Out-String
        Add-Line "  WinINet ProxyServer (HKCU): $wininet"
        $wininetEnable = & reg.exe query 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings' /v ProxyEnable 2>&1 | Out-String
        Add-Line "  WinINet ProxyEnable (HKCU): $wininetEnable"
    } catch { Add-Line "WinINet registry probe failed: $_" }

    Add-Section "Time sync (w32tm /query /status)"
    try {
        $w32 = & w32tm /query /status 2>&1 | Out-String
        Add-Line $w32
    } catch { Add-Line "w32tm failed: $_" }

    Add-Section "ipconfig /all"
    try {
        $ipc = & ipconfig /all 2>&1 | Out-String
        Add-Line $ipc
    } catch { Add-Line "ipconfig failed: $_" }

    try {
        [System.IO.File]::WriteAllText($contextPath, $sb.ToString())
        return $contextPath
    } catch {
        Write-Host "  Failed to write oobe-context.txt: $_" -ForegroundColor Yellow
        return $null
    }
}

Function Build-BiitTempLogsZip {
    <#
    Bundles every PowerShell / Win32-deploy log file from C:\Windows\Temp
    into a single ZIP at C:\Windows\Temp\oobe-temp-logs-{serial}.zip.

    Why a ZIP: many Win32 apps land their script transcripts in
    C:\Windows\Temp under varying name patterns — `PS-*.log` (the
    PowerShell engine's own transcript), `PS_*.log` and
    `PSAppDeployToolkit_*.log` (PSAppDeployToolkit pattern), `Install-*.log`
    / `Uninstall-*.log` / `Detection-*.log` (custom installer scripts),
    plus this script's own `EnrollmentScript - *.log`. With a 5-file
    upload cap on the backend, picking ONE per pattern means you miss
    everything else; bundling them all into a single .zip gives the tech
    every relevant transcript in one upload slot.

    Per-file tail-trim at 5 MB (so a single bloated app log doesn't
    dominate the archive). All reads use FileShare.ReadWrite (the active
    EnrollmentScript transcript is held open by Start-Transcript at the
    top of this script).

    Excludes the CAB + oobe-context.txt + the zip itself (we don't want
    to re-zip our own output).

    Returns the ZIP file path on success, $null if no logs were found
    or the ZIP creation hard-failed. Empty ZIPs are skipped.
    #>
    param(
        [string]$Serial,
        [int]$PerFileMaxBytes = 5242880   # 5 MB per file inside the ZIP
    )

    $tempDir = 'C:\Windows\Temp'
    if (-not (Test-Path $tempDir)) { return $null }

    $zipPath = Join-Path $tempDir "oobe-temp-logs-$Serial.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }

    # Glob patterns to bundle. Order doesn't matter — we sort by
    # LastWriteTime DESC and bundle the most recent N candidates total.
    $patterns = @(
        'PS-*.log',                       # PowerShell engine transcripts
        'PS_*.log',                       # PSAppDeployToolkit-style
        'PSAppDeployToolkit*.log',        # Newer PSADT versions
        'EnrollmentScript - *.log',       # This script's transcripts
        'Install-*.log',                  # Custom Win32 install scripts
        'Uninstall-*.log',                # Custom Win32 uninstall scripts
        'Detection-*.log',                # Custom Win32 detection scripts
        'ImmyBot-*.log',                  # ImmyBot agent install
        'IntuneAgentScript*.log',         # Intune agent script logs
        'BiitDiagnostics*.log',           # Anything BIIT-flavored
        '*.cmd.log',                      # SCCM/MDT-style cmd transcripts
        '*-install.log',                  # Generic installer pattern
        'msi*.log',                       # MSI verbose logs
        'setup*.log'                      # Generic setup logs
    )

    $exclude = @(
        "autopilot-diag-$Serial.cab",
        "oobe-context-$Serial.txt",
        "oobe-temp-logs-$Serial.zip",
        "ime-and-debug-$Serial.zip",
        "mdm-diag-out-$Serial.zip"
    )

    $files = @()
    foreach ($pat in $patterns) {
        $hits = Get-ChildItem -Path $tempDir -Filter $pat -ErrorAction SilentlyContinue |
                Where-Object { $exclude -notcontains $_.Name }
        if ($hits) { $files += $hits }
    }

    # De-duplicate by FullName (a file matching two glob patterns shouldn't
    # appear twice) and sort newest-first; cap at 25 to bound ZIP size.
    $files = $files | Sort-Object FullName -Unique | Sort-Object LastWriteTime -Descending | Select-Object -First 25

    if (-not $files -or $files.Count -eq 0) {
        Write-Host "  No PowerShell/Win32-deploy logs in C:\Windows\Temp to bundle." -ForegroundColor Gray
        return $null
    }

    # Use System.IO.Compression directly so we can feed byte arrays from
    # FileShare.ReadWrite reads — Compress-Archive opens with restrictive
    # sharing and trips over Start-Transcript's active log.
    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    } catch { }

    $fs = $null
    $archive = $null
    $bundled = 0
    try {
        $fs = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $archive = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)

        foreach ($f in $files) {
            try {
                # Read with FileShare.ReadWrite so an in-progress transcript
                # writer (or in-progress IME install) doesn't block the read.
                $rs = [System.IO.File]::Open(
                    $f.FullName,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::ReadWrite
                )
                $bytes = $null
                try {
                    $len = $rs.Length
                    $buf = New-Object byte[] $len
                    $offset = 0
                    while ($offset -lt $len) {
                        $read = $rs.Read($buf, $offset, $len - $offset)
                        if ($read -le 0) { break }
                        $offset += $read
                    }
                    $bytes = $buf
                } finally { $rs.Dispose() }

                if ($bytes.Length -gt $PerFileMaxBytes) {
                    Write-Host "  ZIP: '$($f.Name)' is $([Math]::Round($bytes.Length / 1MB, 2)) MB — tail-trimming to $([Math]::Round($PerFileMaxBytes / 1MB, 2)) MB." -ForegroundColor Gray
                    $tail = New-Object byte[] $PerFileMaxBytes
                    [System.Array]::Copy($bytes, $bytes.Length - $PerFileMaxBytes, $tail, 0, $PerFileMaxBytes)
                    $bytes = $tail
                }

                $entry = $archive.CreateEntry($f.Name, [System.IO.Compression.CompressionLevel]::Optimal)
                $estream = $entry.Open()
                try {
                    $estream.Write($bytes, 0, $bytes.Length)
                } finally { $estream.Close() }
                $bundled++
            } catch {
                Write-Host "  ZIP: skipped '$($f.Name)' — $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  ZIP creation hard-failed: $_" -ForegroundColor Yellow
        return $null
    } finally {
        if ($archive) { $archive.Dispose() }
        if ($fs)      { $fs.Dispose() }
    }

    if ($bundled -eq 0) {
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }
        return $null
    }
    Write-Host "  ZIP: bundled $bundled file(s) → $zipPath" -ForegroundColor Gray
    return $zipPath
}

Function Build-BiitImeAndDebugZip {
    <#
    Bundles all IntuneManagementExtension logs + per-app install state
    registry dumps + the AAD-CloudAP/Operational + AppXDeployment-Server
    /Operational EVTX exports (if those channels exist on this build)
    into a single ZIP at C:\Windows\Temp\ime-and-debug-{serial}.zip.

    Why: option [6]'s prior shape only captured the NEWEST 1 IME log
    (slot 3 of the 5-file cap). On 2026-05-20 the PaceAirFreight MZ038GGC
    investigation showed that the Sidecar timeout's root cause —
    "Timed out waiting for all policy providers to provide a list of
    policies" — needed the FULL set of IME logs (Win32 app install
    state, Sidecar handoff timing) AND the registry hive that names
    which specific Win32 app the Intune Management Extension was
    waiting on. A single newest-log was not enough.

    Contents:
      - C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\*.log
        (all logs; per-file tail-trim at 5 MB so a bloated IME log
        doesn't dominate)
      - ime-app-state.reg     — HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\*
        per-Win32-app install attempt + content download state
      - enrollment-state.reg  — HKLM:\SOFTWARE\Microsoft\Enrollments\*
        per-category ESP state (DevicePreparation, DeviceSetup,
        AccountSetup) + FirstSync per-CSP status
      - aad-cloudap.evtx      — Microsoft-Windows-AAD-CloudAP/Operational
        if the channel exists on this Windows build (Sidecar / Cloud
        AP plugin activity)
      - appx-deployment.evtx  — Microsoft-Windows-AppXDeploymentServer
        /Operational if the channel exists (UWP / Sidecar app install)
      - summary.txt           — Get-AppxPackage state for the Sidecar-
        adjacent UWP packages (CloudExperienceHost, OOBE, AAD Broker
        Plugin) + a manifest of what got bundled

    Per-file FileShare.ReadWrite reads (the IME log writer is held open
    by the IntuneManagementExtension service while the agent is alive).
    Returns the ZIP file path on success, $null if nothing was found
    to bundle. Skip-if-missing semantics for every input — the script
    must keep running even if the IME directory doesn't exist yet
    (Pace's PAF-WKS038 case where IME never made it past the policy-
    provider wait).
    #>
    param(
        [string]$Serial,
        [int]$PerFileMaxBytes = 5242880   # 5 MB per file inside the ZIP
    )

    $tempDir = 'C:\Windows\Temp'
    if (-not (Test-Path $tempDir)) { return $null }

    $zipPath = Join-Path $tempDir "ime-and-debug-$Serial.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }

    # Working staging dir for non-IME inputs (reg exports, evtx exports,
    # summary). Cleared/recreated each run.
    $stageDir = Join-Path $tempDir "ime-and-debug-stage-$Serial"
    if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force -ErrorAction SilentlyContinue }
    try { New-Item -ItemType Directory -Path $stageDir -Force -ErrorAction Stop | Out-Null }
    catch {
        Write-Host "  ime-and-debug: could not create stage dir: $_" -ForegroundColor Yellow
        return $null
    }

    # --- 1. Collect IME logs --------------------------------------------------
    $imeDir = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
    $imeLogs = @()
    if (Test-Path $imeDir) {
        $imeLogs = Get-ChildItem -Path $imeDir -Filter '*.log' -ErrorAction SilentlyContinue |
                   Sort-Object LastWriteTime -Descending
    } else {
        Write-Host "  ime-and-debug: IME log dir not present ($imeDir) -- IME may not have started yet." -ForegroundColor Yellow
    }

    # --- 2. Registry dumps ---------------------------------------------------
    # `reg.exe export` writes a portable .reg text file; we add a .reg
    # extension explicitly so the entry inside the ZIP has the right name.
    $imeRegPath = Join-Path $stageDir "ime-app-state.reg"
    try {
        & reg.exe export 'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension' $imeRegPath /y 2>&1 | Out-Null
        if (-not (Test-Path $imeRegPath)) {
            # IntuneManagementExtension key absent -- record that explicitly
            "Key HKLM\SOFTWARE\Microsoft\IntuneManagementExtension not present at $(Get-Date -Format o)" |
                Set-Content -Path $imeRegPath -Encoding UTF8
        }
    } catch {
        "reg export failed: $_" | Set-Content -Path $imeRegPath -Encoding UTF8
    }

    $enrollRegPath = Join-Path $stageDir "enrollment-state.reg"
    try {
        & reg.exe export 'HKLM\SOFTWARE\Microsoft\Enrollments' $enrollRegPath /y 2>&1 | Out-Null
        if (-not (Test-Path $enrollRegPath)) {
            "Key HKLM\SOFTWARE\Microsoft\Enrollments not present at $(Get-Date -Format o)" |
                Set-Content -Path $enrollRegPath -Encoding UTF8
        }
    } catch {
        "reg export failed: $_" | Set-Content -Path $enrollRegPath -Encoding UTF8
    }

    # --- 3. EVTX channel exports (try-soft) ----------------------------------
    # `wevtutil epl` exports the full binary EVTX file (much richer than
    # `Get-WinEvent | Export-Clixml`). Channels that don't exist on this
    # Windows build return non-zero exit; skip silently.
    #
    # Pre-check channel existence with `wevtutil gl` before `epl` to avoid
    # the "exit 15007" (channel-not-found) noise in the transcript. On
    # Win11 26100, Microsoft-Windows-AAD-CloudAP/Operational doesn't exist
    # so the pre-check filters it out before we attempt the export.
    $evtxTargets = @(
        @{ Channel='Microsoft-Windows-AAD-CloudAP/Operational';        File='aad-cloudap.evtx' },
        @{ Channel='Microsoft-Windows-AppXDeploymentServer/Operational'; File='appx-deployment.evtx' },
        @{ Channel='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug'; File='dm-debug.evtx' }
    )
    foreach ($t in $evtxTargets) {
        $outPath = Join-Path $stageDir $t.File
        # Pre-check: `wevtutil gl <channel>` returns exit 0 + config dump on
        # known channels, exit non-zero on unknown ones. Redirect stderr so
        # the "channel does not exist" message doesn't appear in the
        # transcript when we're intentionally probing.
        $glCheck = & "$env:windir\System32\wevtutil.exe" gl $t.Channel 2>$null
        $glOk = ($LASTEXITCODE -eq 0)
        if (-not $glOk) {
            # Channel doesn't exist on this Windows SKU/build. No-op silently.
            continue
        }
        try {
            $proc = Start-Process -FilePath "$env:windir\System32\wevtutil.exe" `
                -ArgumentList @('epl', $t.Channel, $outPath, '/ow:true') `
                -NoNewWindow -PassThru -Wait -ErrorAction Stop
            if ($proc.ExitCode -ne 0 -or -not (Test-Path $outPath)) {
                Write-Host "  ime-and-debug: channel $($t.Channel) not exported (exit $($proc.ExitCode))." -ForegroundColor Gray
                if (Test-Path $outPath) { Remove-Item $outPath -Force -ErrorAction SilentlyContinue }
            }
        } catch {
            Write-Host "  ime-and-debug: wevtutil epl failed for $($t.Channel): $_" -ForegroundColor Gray
        }
    }

    # --- 4. Summary.txt -------------------------------------------------------
    $summaryPath = Join-Path $stageDir "summary.txt"
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("ime-and-debug bundle for $Serial")
    [void]$sb.AppendLine("Generated: $((Get-Date).ToUniversalTime().ToString('o'))")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=== IME logs found ===")
    if ($imeLogs) {
        foreach ($l in $imeLogs) {
            $size = [Math]::Round($l.Length / 1KB, 1)
            [void]$sb.AppendLine(("  {0,-50} {1,8} KB  {2}" -f $l.Name, $size, $l.LastWriteTime.ToString('s')))
        }
    } else {
        [void]$sb.AppendLine("  (none)")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=== Get-AppxPackage (Sidecar / OOBE / CloudExperience adjacent) ===")
    $pkgPatterns = @(
        'Microsoft.AAD.BrokerPlugin',
        '*CloudExperience*',
        'Microsoft.Windows.CloudExperienceHost',
        'Microsoft.AccountsControl',
        '*OOBE*',
        '*Sidecar*'
    )
    foreach ($pat in $pkgPatterns) {
        try {
            $pkgs = Get-AppxPackage -Name $pat -AllUsers -ErrorAction SilentlyContinue
            if ($pkgs) {
                foreach ($p in $pkgs) {
                    [void]$sb.AppendLine(("  {0,-50} v={1,-15} Inst={2}" -f $p.Name, $p.Version, $p.InstallLocation))
                }
            }
        } catch { }
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=== IntuneManagementExtension service state ===")
    try {
        $imeSvc = Get-Service -Name 'IntuneManagementExtension' -ErrorAction SilentlyContinue
        if ($imeSvc) {
            [void]$sb.AppendLine("  IntuneManagementExtension Status=$($imeSvc.Status) StartType=$($imeSvc.StartType)")
        } else {
            [void]$sb.AppendLine("  Service IntuneManagementExtension not present yet.")
        }
    } catch {
        [void]$sb.AppendLine("  Get-Service failed: $_")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("=== IME process state ===")
    try {
        $imeProcs = Get-Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.ProcessName -in @('IntuneManagementExtension','AgentExecutor','ClientHealthEval','Microsoft.Management.Services.IntuneWindowsAgent') }
        if ($imeProcs) {
            foreach ($p in $imeProcs) {
                [void]$sb.AppendLine(("  PID={0} {1,-45} Start={2} WS={3} MB" -f $p.Id, $p.ProcessName, $p.StartTime, [int]($p.WorkingSet64/1MB)))
            }
        } else {
            [void]$sb.AppendLine("  No IME-related processes running.")
        }
    } catch {
        [void]$sb.AppendLine("  Get-Process failed: $_")
    }
    try {
        [System.IO.File]::WriteAllText($summaryPath, $sb.ToString())
    } catch {
        Write-Host "  ime-and-debug: failed to write summary.txt: $_" -ForegroundColor Yellow
    }

    # --- 5. Assemble the ZIP --------------------------------------------------
    # Use System.IO.Compression directly so we can feed FileShare.ReadWrite
    # reads (mirrors Build-BiitTempLogsZip — the IME log writer is held
    # open by the IntuneManagementExtension service).
    try {
        Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    } catch { }

    $fs = $null
    $archive = $null
    $bundled = 0
    try {
        $fs = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $archive = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)

        function _AddBytes {
            param([string]$EntryName, [byte[]]$Bytes)
            $entry = $archive.CreateEntry($EntryName, [System.IO.Compression.CompressionLevel]::Optimal)
            $es = $entry.Open()
            try { $es.Write($Bytes, 0, $Bytes.Length) } finally { $es.Close() }
        }

        # 5a. IME logs (FileShare.ReadWrite read + tail-trim)
        foreach ($f in $imeLogs) {
            try {
                $rs = [System.IO.File]::Open(
                    $f.FullName,
                    [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read,
                    [System.IO.FileShare]::ReadWrite
                )
                try {
                    $len = $rs.Length
                    $buf = New-Object byte[] $len
                    $offset = 0
                    while ($offset -lt $len) {
                        $read = $rs.Read($buf, $offset, $len - $offset)
                        if ($read -le 0) { break }
                        $offset += $read
                    }
                } finally { $rs.Dispose() }

                if ($buf.Length -gt $PerFileMaxBytes) {
                    $tail = New-Object byte[] $PerFileMaxBytes
                    [System.Array]::Copy($buf, $buf.Length - $PerFileMaxBytes, $tail, 0, $PerFileMaxBytes)
                    $buf = $tail
                }
                _AddBytes -EntryName ("ime-logs/" + $f.Name) -Bytes $buf
                $bundled++
            } catch {
                Write-Host "  ime-and-debug: skipped '$($f.Name)' — $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }

        # 5b. Staged files (reg exports + evtx + summary)
        $staged = Get-ChildItem -Path $stageDir -File -ErrorAction SilentlyContinue
        foreach ($s in $staged) {
            try {
                $b = [System.IO.File]::ReadAllBytes($s.FullName)
                if ($b.Length -gt $PerFileMaxBytes) {
                    $tail = New-Object byte[] $PerFileMaxBytes
                    [System.Array]::Copy($b, $b.Length - $PerFileMaxBytes, $tail, 0, $PerFileMaxBytes)
                    $b = $tail
                }
                _AddBytes -EntryName $s.Name -Bytes $b
                $bundled++
            } catch {
                Write-Host "  ime-and-debug: skipped stage file '$($s.Name)' — $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  ime-and-debug: ZIP creation hard-failed: $_" -ForegroundColor Yellow
        return $null
    } finally {
        if ($archive) { $archive.Dispose() }
        if ($fs)      { $fs.Dispose() }
        # Clean up staging dir but leave the ZIP
        if (Test-Path $stageDir) { Remove-Item $stageDir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    if ($bundled -eq 0) {
        if (Test-Path $zipPath) { Remove-Item $zipPath -Force -ErrorAction SilentlyContinue }
        Write-Host "  ime-and-debug: no inputs available -- not producing a ZIP." -ForegroundColor Gray
        return $null
    }
    Write-Host "  ime-and-debug: bundled $bundled file(s) -> $zipPath" -ForegroundColor Gray
    return $zipPath
}

Function Invoke-BiitDiagnosticsCapture {
    <#
    Captures Autopilot + Intune-side diagnostic logs into base64-encoded
    blobs ready to POST. Returns an array of @{filename; contentBase64}
    hashtables (or $null on hard failure).

    Sources (5-file backend cap):
      1. MdmDiagnosticsTool.exe -area Autopilot;DeviceProvisioning -cab ...
         Microsoft's canonical Autopilot diag tool — bundles the relevant
         registry hives + log files + ETL traces into a single CAB.
      2. oobe-context-{serial}.txt (script-built) — dsregcmd /status,
         enrollment registry tree, AutopilotPolicy registry, recent Event
         Log entries from 6 Autopilot/AAD/MDM channels, network reachability,
         time sync, ipconfig. Designed to make 0x801c03f3-class AAD-join
         failures self-diagnosable from a single file.
      3. ime-and-debug-{serial}.zip — ALL IME logs (was: newest 1, too
         narrow per PaceAirFreight MZ038GGC 2026-05-20) + per-app install
         state registry dumps (HKLM\IntuneManagementExtension +
         HKLM\Enrollments) + Microsoft-Windows-AAD-CloudAP/Operational EVTX
         + AppXDeploymentServer/Operational EVTX + summary.txt with
         Get-AppxPackage state for Sidecar-adjacent UWP packages. Answers
         the load-bearing question "which provider was the ESP waiting
         on when the 30-min timer expired?"
      4. oobe-temp-logs-{serial}.zip — bundle of every PowerShell/Win32-
         deploy script log in C:\Windows\Temp. Up to 25 files matching
         PS*, EnrollmentScript-*, Install-*, Detection-*, PSAppDeployToolkit*,
         ImmyBot-*, msi*, setup*, *.cmd.log etc. Per-file tail-trim at
         5 MB. Resolves the original "newest 1 PS-*.log + newest 1
         EnrollmentScript-*.log" approach being too narrow — the 5-file
         backend cap is preserved by collapsing all script logs into one
         archive slot.
      5. mdm-diag-out-{serial}.zip -- DEFLATE-compressed bundle of the entire
         `MdmDiagnosticsTool -out` directory: MDMDiagReport.xml + area-specific
         XMLs + registry dumps. Sidesteps the LZX compression in the CAB so
         the BIIT backend / Linux-side tooling can parse on Linux to find the
         specific CSP that hung during ESP DeviceSetup. The same data is in
         the CAB but LZX cabs can't be cracked off-Windows.

    Each file is capped at $MaxBytes (default 10 MB) before encoding;
    files larger than the cap are tail-truncated to the last $MaxBytes
    bytes so we keep the most recent activity, with a warning surfaced
    to the operator.
    #>
    param(
        [int]$MaxBytes = 10485760,         # 10 MB / file
        [int]$MaxFilesPerRequest = 5       # backend cap; mirrored client-side
    )

    $serial = $null
    try { $serial = (Get-CimInstance -Class Win32_BIOS -ErrorAction Stop).SerialNumber.Trim() } catch { $serial = "unknown" }
    $cabPath = "C:\Windows\Temp\autopilot-diag-$serial.cab"

    Write-Host "`nCapturing diagnostics — this can take 30-60 seconds…" -ForegroundColor Gray

    # 1) MdmDiagnosticsTool — produces the CAB. Always attempt; the tool
    # writes a non-zero exit code if the device has never started enrollment,
    # but the CAB usually still contains useful registry exports.
    # Expanded -area list (2026-05-20 Pace investigation): added DeviceEnrollment
    # and TPM so the CAB carries the full MDM enrollment session state +
    # TPM context. Output stays under 5 MB even with the broader scope.
    try {
        if (Test-Path $cabPath) { Remove-Item $cabPath -Force -ErrorAction SilentlyContinue }
        $proc = Start-Process -FilePath "$env:windir\System32\MdmDiagnosticsTool.exe" `
            -ArgumentList @('-area','Autopilot;DeviceProvisioning;DeviceEnrollment;TPM','-cab',$cabPath) `
            -NoNewWindow -PassThru -Wait -ErrorAction Stop
        if ($proc.ExitCode -ne 0) {
            Write-Host "  MdmDiagnosticsTool exit code $($proc.ExitCode) — continuing with whatever it produced." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  MdmDiagnosticsTool failed: $_" -ForegroundColor Yellow
        # Continue — we still have IME + script logs + the script-built context.
    }

    # 1b) MdmDiagnosticsTool -out: also produce UNCOMPRESSED output in a
    # temp directory and bundle the whole thing as a zip. The -cab path uses
    # LZX compression which most non-Windows extractors can't decode (caught
    # analysing the Pace MZ038GGC 2026-05-20 diag -- `cabextract` and Python
    # `cabarchive` both choked on LZX). The -out flag produces MDMDiagReport.xml
    # + area-specific XMLs + a registry dump uncompressed, but the file layout
    # depends on the -area combination passed; bundling the entire output dir
    # as a zip means we don't have to guess at the file name (the prior version
    # of this code looked specifically for `MDMDiagReport.xml` and silently
    # produced nothing when -area-with-out didn't lay it down at the expected
    # path -- Pace MZ038GGC attempt-6 surfaced that). With the zip approach,
    # whatever MdmDiagnosticsTool produces lands in our 5th upload slot.
    $mdmOutDir = "C:\Windows\Temp\biit-mdm-out-$serial"
    $mdmOutZipPath = $null
    try {
        if (Test-Path $mdmOutDir) { Remove-Item $mdmOutDir -Recurse -Force -ErrorAction SilentlyContinue }
        New-Item -ItemType Directory -Path $mdmOutDir -Force -ErrorAction Stop | Out-Null
        # Note: no -area flag -- the bare `-out path` form collects the
        # default scope including MDMDiagReport.xml reliably. The -cab call
        # above already covers Autopilot + DeviceProvisioning + DeviceEnrollment
        # + TPM, so we're not losing coverage by dropping the explicit areas
        # here.
        $proc2 = Start-Process -FilePath "$env:windir\System32\MdmDiagnosticsTool.exe" `
            -ArgumentList @('-out',$mdmOutDir) `
            -NoNewWindow -PassThru -Wait -ErrorAction Stop
        if ($proc2.ExitCode -ne 0) {
            Write-Host "  MdmDiagnosticsTool -out exit code $($proc2.ExitCode) -- bundling whatever was produced." -ForegroundColor Yellow
        }
        # Diagnostic: list what was actually produced so future debugging is
        # easier when the contents change shape across Windows builds.
        $produced = Get-ChildItem -Path $mdmOutDir -Recurse -File -ErrorAction SilentlyContinue
        if ($produced) {
            Write-Host "  MdmDiagnosticsTool -out produced $($produced.Count) file(s) -- bundling as zip." -ForegroundColor Gray
            $mdmOutZipPath = "C:\Windows\Temp\mdm-diag-out-$serial.zip"
            if (Test-Path $mdmOutZipPath) { Remove-Item $mdmOutZipPath -Force -ErrorAction SilentlyContinue }
            Compress-Archive -Path "$mdmOutDir\*" -DestinationPath $mdmOutZipPath -Force -ErrorAction Stop
        } else {
            Write-Host "  MdmDiagnosticsTool -out produced no files at $mdmOutDir -- skipping bundle." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  MdmDiagnosticsTool -out (uncompressed XML bundle) failed: $_" -ForegroundColor Yellow
    }

    $candidates = @()
    if (Test-Path $cabPath) { $candidates += (Get-Item $cabPath) }

    # 2) Script-built OOBE context — dsregcmd, registry, event logs, network.
    Write-Host "  Building oobe-context.txt (dsregcmd + registry + event logs)…" -ForegroundColor Gray
    $contextPath = Build-BiitOobeContextFile -Serial $serial
    if ($contextPath -and (Test-Path $contextPath)) {
        $candidates += (Get-Item $contextPath)
    }

    # 3) ime-and-debug-{serial}.zip -- ALL IME logs + per-app install
    # state registry + AAD-CloudAP / AppXDeploymentServer / DM-Debug EVTX
    # + Get-AppxPackage summary for Sidecar-adjacent UWP. Replaces the
    # prior "newest 1 IME log" approach which was too narrow to identify
    # which specific Win32 app provider was hanging the ESP DevicePreparation
    # policy-provider-installation wait. PaceAirFreight MZ038GGC
    # 2026-05-20: the 30-min Sidecar timeout corresponded to
    # "waitForPolicyProviderInstallationToComplete" timing out; naming
    # the stuck provider needs the full IME log set + the
    # IntuneManagementExtension registry hive that tracks per-app
    # install attempts.
    Write-Host "  Bundling IME logs + Win32-app install registry + AAD-CloudAP/AppXDeployment EVTX..." -ForegroundColor Gray
    $imeAndDebugZipPath = Build-BiitImeAndDebugZip -Serial $serial
    if ($imeAndDebugZipPath -and (Test-Path $imeAndDebugZipPath)) {
        $candidates += (Get-Item $imeAndDebugZipPath)
    }

    # 4) Bundle every PowerShell / Win32-deploy log in C:\Windows\Temp into
    # a single ZIP so the 5-file cap doesn't force us to pick one pattern
    # over another. Operator quote 2026-05-06 PM:
    # "Many of our Win32 apps start with PS. so would it be worth grabbing
    #  those?" — yes, and Detection-*, Install-*, PSAppDeployToolkit*,
    # ImmyBot-*, msi*, setup* etc. all land in the same dir.
    Write-Host "  Bundling C:\Windows\Temp script logs into ZIP…" -ForegroundColor Gray
    $tempLogsZipPath = Build-BiitTempLogsZip -Serial $serial
    if ($tempLogsZipPath -and (Test-Path $tempLogsZipPath)) {
        $candidates += (Get-Item $tempLogsZipPath)
    }

    # 5) mdm-diag-out-{serial}.zip -- uncompressed MdmDiagnosticsTool -out
    # bundle. Contains MDMDiagReport.xml + area-specific XMLs + registry
    # dumps. Plain DEFLATE zip (not LZX) so backend can parse on Linux
    # without needing a CAB extractor.
    if ($mdmOutZipPath -and (Test-Path $mdmOutZipPath)) {
        Write-Host "  Including uncompressed mdm-diag-out zip..." -ForegroundColor Gray
        $candidates += (Get-Item $mdmOutZipPath)
    }

    if (-not $candidates -or $candidates.Count -eq 0) {
        Write-Host "  No diagnostic files found to upload." -ForegroundColor Red
        return $null
    }

    # Cap the file count so the backend's per-request limit is never exceeded.
    # Order matters — earlier entries are higher-priority (CAB + oobe-context
    # are the two we never want to drop).
    if ($candidates.Count -gt $MaxFilesPerRequest) {
        Write-Host "  Captured $($candidates.Count) files; trimming to the $MaxFilesPerRequest highest-priority for upload." -ForegroundColor Yellow
        $candidates = $candidates | Select-Object -First $MaxFilesPerRequest
    }

    # Read with FileShare.ReadWrite — the script's own EnrollmentScript-*.log
    # is held open by Start-Transcript at the top of this script. The default
    # [System.IO.File]::ReadAllBytes() uses FileShare.Read which collides with
    # Start-Transcript's writer and 502s every option [6] upload of the active
    # transcript ("file is in use by another process"). FileShare.ReadWrite
    # cooperates; same fix applies to any IME / Provisioning log that the OS
    # may still be appending to during OOBE.
    function _Read-FileShared {
        param([string]$Path)
        $fs = $null
        try {
            $fs = [System.IO.File]::Open(
                $Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite
            )
            $len = $fs.Length
            $buf = New-Object byte[] $len
            $offset = 0
            while ($offset -lt $len) {
                $read = $fs.Read($buf, $offset, $len - $offset)
                if ($read -le 0) { break }
                $offset += $read
            }
            return $buf
        } finally {
            if ($fs) { $fs.Dispose() }
        }
    }

    # PRP-63 — emit BOTH a base64 payload (legacy /diagnostics-by-code path
    # for paths 2/3 + the legacy code-driven base64 fallback) AND a path
    # manifest for the presigned-PUT path used by option [6] sub-path 1.
    # The presigned path streams files directly to S3 via Invoke-WebRequest
    # -InFile, bypassing API Gateway's 10 MB request cap. When a candidate
    # exceeds $MaxBytes, the trimmed tail is written to a sibling temp file
    # so both paths see the SAME bytes — Paths[i].LocalPath always reflects
    # what would have been base64'd in Files[i].contentBase64.
    # IntuneManagementExtension.log is held open with FileShare.Read by the
    # IME service (rejecting FileShare.None re-opens). `_Read-FileShared`
    # cooperates by opening with FileShare.ReadWrite — the legacy base64
    # path was already fine because it reads bytes here and never re-opens
    # the file. The presigned-PUT path uses `Invoke-WebRequest -InFile`,
    # which re-opens with default sharing and CRASHES with "process cannot
    # access the file because it is being used by another process".
    #
    # Fix: ALWAYS write a temp copy of the bytes to $env:TEMP, regardless
    # of trimming. The `Paths[i].localPath` always points at our temp copy
    # — the original file stays exclusively owned by IME. Caps disk usage
    # at ~$MaxBytes per file; cleanup happens via $env:TEMP rotation.
    $payload = @()
    $paths   = @()
    foreach ($f in $candidates) {
        try {
            $bytes = _Read-FileShared -Path $f.FullName
            if ($bytes.Length -gt $MaxBytes) {
                Write-Host "  '$($f.Name)' is $([Math]::Round($bytes.Length / 1MB, 2)) MB — trimming to last $([Math]::Round($MaxBytes / 1MB, 2)) MB." -ForegroundColor Yellow
                $tail = New-Object byte[] $MaxBytes
                [System.Array]::Copy($bytes, $bytes.Length - $MaxBytes, $tail, 0, $MaxBytes)
                $bytes = $tail
            }
            # Always stage a temp copy so Invoke-WebRequest -InFile doesn't
            # collide with whatever process holds the original open. Suffixed
            # `.upload` so it's obvious in C:\Windows\Temp what's transient.
            $localPath = Join-Path $env:TEMP ("oobe-diag-upload-" + $f.Name + ".upload")
            [System.IO.File]::WriteAllBytes($localPath, $bytes)
            $payload += @{
                filename      = $f.Name
                contentBase64 = [System.Convert]::ToBase64String($bytes)
            }
            $paths += @{
                filename    = $f.Name
                localPath   = $localPath
                sizeBytes   = [int64]$bytes.Length
                contentType = switch -Regex ($f.Name) {
                    '\.cab$'   { 'application/vnd.ms-cab-compressed'; break }
                    '\.zip$'   { 'application/zip'; break }
                    '\.evtx$'  { 'application/octet-stream'; break }
                    '\.etl$'   { 'application/octet-stream'; break }
                    '\.json$'  { 'application/json'; break }
                    '\.xml$'   { 'application/xml'; break }
                    default    { 'text/plain' }
                }
            }
            Write-Host "  + $($f.Name) ($([Math]::Round($bytes.Length / 1KB, 1)) KB)"
        } catch {
            Write-Host "  Skipping '$($f.Name)' — read error: $_" -ForegroundColor Yellow
        }
    }

    if ($payload.Count -eq 0) {
        Write-Host "  All capture targets failed to read." -ForegroundColor Red
        return $null
    }

    Write-Host "  Local CAB preserved at: $cabPath" -ForegroundColor Gray
    return @{
        Files  = $payload
        Paths  = $paths
        CabPath = $cabPath
        Serial = $serial
    }
}


Function Submit-BiitDiagnosticsPresigned {
    <#
    PRP-63 — Submit a captured diagnostics bundle via the presigned-PUT
    flow. Three steps:

      1. POST manifest to /diagnostics-by-code/presign — returns presigned
         PUT URLs + a session nonce.
      2. PUT each file directly to S3 via Invoke-WebRequest -InFile.
         Bypasses API Gateway's 10 MB body cap entirely.
      3. POST attachment list to /diagnostics-by-code/finalize — Lambda
         head_objects each upload + stamps the deployment-row sentinel
         + emits the same audit/activity event the legacy path produces.

    Returns @{Success=[bool]; Count=[int]; Error=[string]}.
    #>
    param(
        [Parameter(Mandatory)] [string] $PortalApiBase,
        [Parameter(Mandatory)] [string] $Code,
        [Parameter(Mandatory)] [object[]] $PathManifest
    )

    # Step 1 — presign
    $presignBody = @{
        code  = $Code
        files = @($PathManifest | ForEach-Object {
            @{
                filename    = $_.filename
                size        = [int64]$_.sizeBytes
                contentType = $_.contentType
            }
        })
    } | ConvertTo-Json -Compress -Depth 6

    Write-Host "  Step 1/3: requesting presigned upload URLs…" -ForegroundColor Gray
    try {
        $presignResp = Invoke-RestMethod -Method POST `
            -Uri "$PortalApiBase/immy/autopilot/diagnostics-by-code/presign" `
            -ContentType "application/json" `
            -Body $presignBody `
            -TimeoutSec 30 -DisableKeepAlive
    } catch {
        return @{ Success = $false; Count = 0; Error = "presign failed: $_" }
    }

    $sessionId    = $presignResp.sessionId
    $deploymentId = $presignResp.deploymentId
    $uploads      = @($presignResp.uploads)
    if (-not $sessionId -or -not $deploymentId -or $uploads.Count -ne $PathManifest.Count) {
        return @{ Success = $false; Count = 0; Error = "presign returned an unexpected shape" }
    }

    # Step 2 — direct PUT each file to S3
    Write-Host "  Step 2/3: streaming $($uploads.Count) file(s) to S3…" -ForegroundColor Gray
    $attachments = @()
    for ($i = 0; $i -lt $uploads.Count; $i++) {
        $upload = $uploads[$i]
        $manifest = $PathManifest | Where-Object { $_.filename -eq $upload.filename } | Select-Object -First 1
        if (-not $manifest) {
            return @{ Success = $false; Count = 0; Error = "presign returned filename $($upload.filename) not in manifest" }
        }

        # Convert PSCustomObject .headers to a string-keyed hashtable so
        # Invoke-WebRequest doesn't choke on dynamic property access. The
        # presign payload signs Content-Type into the URL, so we MUST send
        # the exact value back. Pull Content-Type out of $putHeaders and
        # pass it via -ContentType; passing it in both -Headers and
        # -ContentType produces a "header already set" warning on PS 5.1.
        $putHeaders = @{}
        $putContentType = 'application/octet-stream'
        $upload.headers.PSObject.Properties | ForEach-Object {
            if ($_.Name -ieq 'Content-Type') {
                $putContentType = [string]$_.Value
            } else {
                $putHeaders[$_.Name] = [string]$_.Value
            }
        }

        try {
            Invoke-WebRequest -Method Put `
                -Uri $upload.url `
                -InFile $manifest.localPath `
                -Headers $putHeaders `
                -ContentType $putContentType `
                -UseBasicParsing -TimeoutSec 300 -DisableKeepAlive | Out-Null
        } catch {
            return @{ Success = $false; Count = 0; Error = "S3 PUT failed for $($upload.filename): $_" }
        }

        $attachments += @{
            filename = $upload.filename
            s3Key    = $upload.key
            size     = [int64]$manifest.sizeBytes
        }
        Write-Host "    + $($upload.filename) uploaded" -ForegroundColor Gray
    }

    # Step 3 — finalize
    $finalizeBody = @{
        sessionId    = $sessionId
        deploymentId = $deploymentId
        attachments  = @($attachments)
    } | ConvertTo-Json -Compress -Depth 6

    Write-Host "  Step 3/3: finalizing…" -ForegroundColor Gray
    try {
        $finalResp = Invoke-RestMethod -Method POST `
            -Uri "$PortalApiBase/immy/autopilot/diagnostics-by-code/finalize" `
            -ContentType "application/json" `
            -Body $finalizeBody `
            -TimeoutSec 60 -DisableKeepAlive
    } catch {
        return @{ Success = $false; Count = 0; Error = "finalize failed: $_" }
    }

    return @{
        Success = $true
        Count   = [int]($finalResp.count)
        Error   = $null
    }
}


Function Invoke-BiitDiagnosticsUpload {
    <#
    Option [6] — capture + upload diagnostic logs to BIIT MSP Portal.
    Three sub-paths covering the post-failure (canonical) and bundle-with-intake
    (Path 1 / Path 2) cases. PRP-57 Phase C.

    Path (a) — code-driven post-failure: tech gets a 6-digit code from the
    wizard's "Generate upload code" button. Calls /diagnostics-by-code (UNAUTH
    at API GW; code is the auth). The canonical and most common path.

    Path (b) — bundle into a Path 2 intake: same OOBE session that just
    uploaded via option [5] path 2 wants to add diagnostics. Re-call
    /intake-by-code with the same (multi-use) or a fresh code, plus the
    diagnostics body field.

    Path (c) — bundle into a Path 1 intake: BIIT-tenant MSAL flow + diagnostics
    body. Calls /intake-from-script.

    If the OOBE device is offline (no portal connectivity), the local CAB
    at C:\Windows\Temp\autopilot-diag-{serial}.cab survives; the tech can
    grab it via USB and upload via the portal drag-drop later.
    #>
    $PortalApiBase = "https://2xo4m98krh.execute-api.us-east-2.amazonaws.com/prod"
    $BiitTenantId                = "fdec8e68-1a98-4a07-96ca-61d6960dd020"
    $BiitAutopilotIntakeClientId = "9446f70b-ad62-4bcb-aa07-7bc58fecc2f9"
    $BiitAutopilotIntakeScope    = "api://d0e751e8-fac8-429c-98a5-53939e92f535/Autopilot.Intake"

    Write-Host "`n--- BIIT MSP Portal Diagnostics Upload ---" -ForegroundColor Cyan
    Write-Host "[1] Use a 6-digit upload code from the portal wizard (recommended)"
    Write-Host "[2] Bundle with a fresh Path 2 intake (6-digit code)"
    Write-Host "[3] Bundle with a Path 1 intake (BIIT sign-in)"
    Write-Host "[4] Capture only — leave the CAB on disk, skip upload"
    Write-Host "[5] Cancel"
    $sub = Read-Host "`nSelect an option"
    if ($sub -eq "5" -or [string]::IsNullOrWhiteSpace($sub)) {
        Write-Host "Cancelled." -ForegroundColor Yellow
        return
    }
    if ($sub -notin @("1","2","3","4")) {
        Write-Host "Invalid selection." -ForegroundColor Red
        return
    }

    # Path 1 uses the PRP-63 presigned-PUT route (50 MB / file). Paths 2 + 3
    # bundle into intake routes that still go through API GW's 10 MB body
    # cap, so they call the capture function with the legacy 10 MB tail-trim
    # below by passing -MaxBytes explicitly.
    $captureMaxBytes = if ($sub -eq "1") { 52428800 } else { 10485760 }
    $captured = Invoke-BiitDiagnosticsCapture -MaxBytes $captureMaxBytes
    if (-not $captured) { return }
    $files  = $captured.Files
    $paths  = $captured.Paths
    $serial = $captured.Serial
    $cab    = $captured.CabPath

    if ($sub -eq "4") {
        Write-Host "`nDiagnostic CAB available at: $cab" -ForegroundColor Green
        Write-Host "Copy it via USB and use the portal's drag-drop on the failure recovery wizard."
        return
    }

    # Paths 2 + 3 need a hardware hash + model + device type for the intake row.
    $hardwareHash = $null
    $model        = $null
    $deviceType   = "Laptop"
    if ($sub -in @("2","3")) {
        try {
            $devDetail = Get-CimInstance -Namespace root/cimv2/mdm/dmmap `
                -Class MDM_DevDetail_Ext01 `
                -Filter "InstanceID='Ext' AND ParentID='./DevDetail'" `
                -ErrorAction Stop
            $hardwareHash = $devDetail.DeviceHardwareData
        } catch {
            Write-Host "Hash capture failed via WMI: $_" -ForegroundColor Red
            Write-Host "Falling back to path [1] — please mint an upload code from the portal wizard." -ForegroundColor Yellow
            $sub = "1"
        }
        if ($sub -in @("2","3")) {
            $cs = Get-CimInstance -Class Win32_ComputerSystem
            $model = $cs.Model.Trim()
            $deviceType = switch ($cs.PCSystemType) {
                1 { "Desktop" }
                2 { "Laptop" }
                3 { "Workstation" }
                default { "Laptop" }
            }
        }
    }

    if ($sub -eq "1") {
        # Path (a) — canonical, code-driven. PRP-63 — uses the presigned-PUT
        # flow (presign → direct S3 PUT → finalize) to bypass API Gateway's
        # 10 MB request body cap. Real OOBE captures routinely exceed that
        # via a 12 MB IntuneManagementExtension.log alone.
        $code = Read-Host "`nEnter the 6-digit upload code from the portal wizard"
        $code = $code.Trim()
        if ($code -notmatch '^\d{6}$') {
            Write-Host "Code must be 6 digits." -ForegroundColor Red
            return
        }

        Write-Host "`nUploading $($paths.Count) file(s) via presigned S3 PUT…" -ForegroundColor Gray
        $result = Submit-BiitDiagnosticsPresigned -PortalApiBase $PortalApiBase -Code $code -PathManifest $paths
        if ($result.Success) {
            Write-Host "`nUploaded." -ForegroundColor Green
            Write-Host "  Files attached: $($result.Count)"
        } else {
            Write-Host "Upload failed: $($result.Error)" -ForegroundColor Red
            Write-Host "Local CAB preserved at: $cab" -ForegroundColor Yellow
            Write-Host "(Codes have 5 redemptions — generate a fresh one if this code is exhausted.)" -ForegroundColor Yellow
        }
        return
    }

    if ($sub -eq "2") {
        # Path (b) — bundle into Path 2 intake.
        $code = Read-Host "`nEnter the 6-digit intake code the BIIT tech gave you"
        $code = $code.Trim()
        if ($code -notmatch '^\d{6}$') {
            Write-Host "Code must be 6 digits." -ForegroundColor Red
            return
        }
        $redeemerName = $null
        $maybeName = Read-Host "`nYour name (required for multi-use codes; leave blank for single-use)"
        $maybeName = ($maybeName -as [string]).Trim()
        if ($maybeName) { $redeemerName = $maybeName }

        $body = @{
            code         = $code
            hardwareHash = $hardwareHash
            serialNumber = $serial
            model        = $model
            deviceType   = $deviceType
            diagnostics  = $files
        }
        if ($redeemerName) { $body.redeemedByName = $redeemerName }
        $bodyJson = $body | ConvertTo-Json -Compress -Depth 6

        try {
            Write-Host "`nUploading to portal (60s timeout)…" -ForegroundColor Gray
            $resp = Invoke-RestMethod -Method POST `
                -Uri "$PortalApiBase/immy/autopilot/intake-by-code" `
                -ContentType "application/json" `
                -Body $bodyJson `
                -TimeoutSec 60 -DisableKeepAlive
            Write-Host "`nUploaded." -ForegroundColor Green
            Write-Host "  Intake ID:           $($resp.intakeId)"
            Write-Host "  Diagnostics attached: $($resp.diagnosticsAttached)"
        } catch {
            Write-Host "Upload failed: $_" -ForegroundColor Red
            Write-Host "Local CAB preserved at: $cab" -ForegroundColor Yellow
        }
        return
    }

    if ($sub -eq "3") {
        # Path (c) — bundle into Path 1 intake. Uses the cached BIIT token
        # from option [5] if still valid; otherwise prompts for MSAL.
        $token = $null
        if ($script:BiitIntakeToken -and $script:BiitIntakeTokenExpiresAt -and `
            $script:BiitIntakeTokenExpiresAt -gt (Get-Date).AddMinutes(2)) {
            $token = $script:BiitIntakeToken
        }
        if (-not $token) {
            if (-not (Get-Module -ListAvailable -Name MSAL.PS)) {
                Write-Host "MSAL.PS not installed — run option [5] path [1] once first to bootstrap it, or use path [1] (upload code) instead." -ForegroundColor Red
                return
            }
            Import-Module MSAL.PS -ErrorAction Stop
            try {
                $msalToken = Get-MsalToken -ClientId $BiitAutopilotIntakeClientId `
                                           -TenantId $BiitTenantId `
                                           -Scopes  $BiitAutopilotIntakeScope `
                                           -Interactive -ErrorAction Stop
                $token = $msalToken.AccessToken
                $script:BiitIntakeToken          = $token
                $script:BiitIntakeTokenExpiresAt = $msalToken.ExpiresOn.LocalDateTime
            } catch {
                Write-Host "Could not acquire BIIT token: $_" -ForegroundColor Red
                return
            }
        }

        # Pick a tenant from the portal's tenant list.
        Write-Host "`nFetching BIIT tenant list…" -ForegroundColor Gray
        try {
            $tenantsResp = Invoke-RestMethod -Method GET `
                -Uri "$PortalApiBase/immy/autopilot/intake-from-script/tenants" `
                -Headers @{ Authorization = "Bearer $token" } `
                -TimeoutSec 30 -DisableKeepAlive
        } catch {
            Write-Host "Could not fetch tenant list: $_" -ForegroundColor Red
            return
        }
        $tenants = @($tenantsResp.tenants)
        if ($tenants.Count -eq 0) {
            Write-Host "No tenants returned from portal." -ForegroundColor Red
            return
        }
        Write-Host ""
        for ($i = 0; $i -lt $tenants.Count; $i++) {
            Write-Host ("  [{0,2}] {1} ({2})" -f ($i+1), $tenants[$i].displayName, $tenants[$i].clientIdentifier)
        }
        $choice = Read-Host "`nSelect tenant (number)"
        $idx = ($choice -as [int]) - 1
        if ($idx -lt 0 -or $idx -ge $tenants.Count) {
            Write-Host "Invalid selection." -ForegroundColor Red
            return
        }
        $clientIdentifier = $tenants[$idx].clientIdentifier

        $body = @{
            clientIdentifier = $clientIdentifier
            hardwareHash     = $hardwareHash
            serialNumber     = $serial
            model            = $model
            deviceType       = $deviceType
            diagnostics      = $files
        } | ConvertTo-Json -Compress -Depth 6

        try {
            Write-Host "`nUploading to portal (60s timeout)…" -ForegroundColor Gray
            $resp = Invoke-RestMethod -Method POST `
                -Uri "$PortalApiBase/immy/autopilot/intake-from-script" `
                -Headers @{ Authorization = "Bearer $token" } `
                -ContentType "application/json" `
                -Body $body `
                -TimeoutSec 60 -DisableKeepAlive
            Write-Host "`nUploaded." -ForegroundColor Green
            Write-Host "  Intake ID:            $($resp.intakeId)"
            Write-Host "  Diagnostics attached:  $($resp.diagnosticsAttached)"
        } catch {
            Write-Host "Upload failed: $_" -ForegroundColor Red
            Write-Host "Local CAB preserved at: $cab" -ForegroundColor Yellow
        }
        return
    }
}
#EndRegion - BIIT MSP Portal diagnostic upload

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
[5] Upload this device to the BIIT MSP Portal | Sends hash + serial to the Portal's Autopilot intake queue for a tech to finish
[6] Capture and upload diagnostics | Bundle Autopilot/IME/EnrollmentScript logs and ship them to the portal for a tech to triage

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
            3 { try{
                    # $AutoPilotDiagnostics  = Get-InstalledScript -Name Get-AutopilotDiagnosticsCommunity -ErrorAction Ignore
                    # if(!($AutoPilotDiagnostics)){
                    #     Install-Script -Name Get-AutopilotDiagnosticsCommunity -Force
                    # }
                    # # Get NuGet
                    # $provider = Get-PackageProvider NuGet -ErrorAction Ignore
                    # if (-not $provider) {
                    #     Write-Host "Installing provider NuGet"
                    #     Install-PackageProvider -Name NuGet -Force
                    # }
                    #Run Diagnostics
                    Get-AutopilotDiagnostics -Online
                }catch{
                    Write-Host "An error occurred:"
                    Write-Host $_
                }
            }
            4 { UpdateWindows }
            5 { Invoke-BiitPortalUpload }
            6 { Invoke-BiitDiagnosticsUpload }
            0 { Stop-Transcript;exit }
        }
    }  while($userAction -notmatch "[1234560]")
} until($userAction -eq "0")
#EndRegion - Menu
