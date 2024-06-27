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
    try{
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

        #Region Get and assign variables
        Write-Host("

        Pleaes provide the needed data to upload the device info to the clients Intune portal. If you get an error about incorrect sign in info YOU  info wrong.") -ForegroundColor Yellow

        #Connect to Graph then AzureAD
        Write-Host "Please sign in to Azure AD and Graph to begin the device upload process" -ForegroundColor Yellow
        $aadId = Connect-AzureAD
        Write-Host "Connected to Azure tenant. Domain: $($aadId.tenantdomain) | Tenant ID: $($aadId.TenantId.Guid)"
        #Connect to MgGraph
        Write-Host "Connecting to MgGraph now (Microsoft Graph Command Line Tools)"
        Write-Host "NOTE: If you have to consent to anything with the MgGraph connection you will need a global admin. Talk to the infra team for help <3"
        $MgGraph = Connect-MgGraph -TenantID $($aadId.TenantId.Guid) -Scope DeviceManagementServiceConfig.ReadWrite.All
        #Write-Host "Attempting to connect to MSGraph now."
        # $graph = Connect-MSGraph

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
        }


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
        $QueryGroup = Get-AzureADGroup -All:$true | Where-Object{$_.displayName -like "*$GroupName*"}
        while($null -eq $QueryGroup){
            $QueryGroup = Get-AzureADGroup -All:$true | Select-Object DisplayName,Description,ObjectID
            if($QueryGroup.DisplayName -notcontains "Enroll_AutoPilot_v1"){
                $QueryGroup += New-Object psobject -Property @{
                    DisplayName = "Enroll_AutoPilot_v1"
                    Description = "This group is for all devices that have been deployed using this Autopilot profile 'Enroll_AutoPilot_v1' as well as any 'Generic Installers'. Devices deployed through BIIT's script are placed in this group."
                    ObjectID = $null
                }
                Write-Host "The AutoPilot profile 'Enroll_AutoPilot_v1' may not exist because the group Intune_Devices_AutopilotDeployed does not yet exist" -ForegroundColor Red
                Write-Host "Please talk to infrastructure about ensuring the autopilot profile exists in Intune for this client" -ForegroundColor Red
            }
            $QueryGroup = $QueryGroup | Select-Object DisplayName,Description,ObjectId | Sort-Object DisplayName | Out-GridView -PassThru -Title "Please select which group you would like to put the device in"
            if(($null -eq $QueryGroup.ObjectID) -and ($null -ne $QueryGroup)){
                New-AzureADGroup -DisplayName $QueryGroup.DisplayName -MailEnabled $false -SecurityEnabled $true -MailNickName "NotSet" -Description $QueryGroup.Description
            }
        }

        #To save time start checking for windows updates
        $SilentWindowsUpdateBlock = {Import-Module -Name PSWindowsUpdate -Force
        Get-WindowsUpdate -AcceptAll -Install -IgnoreReboot -silent}
        Write-Host "
        While things are running windows updates will be installed silently in the background" -foregroundcolor Magenta
        $JobStart = Start-Job -ScriptBlock $SilentWindowsUpdateBlock

        #Get Serial Number
        $session = New-CimSession
        $serial = (Get-CimInstance -CimSession $session -Class Win32_BIOS).SerialNumber

        #Kick off device upload process
        if(($null -eq $UPN) -or ($UPN -eq "")){
            Get-WindowsAutoPilotInfo -Online $false -AddToGroup $GroupName -Assign -AssignedComputerName $ComputerName
        }else{
            Get-WindowsAutoPilotInfo -Online $false -AddToGroup $GroupName -Assign -AssignedUser $UPN -AssignedComputerName $ComputerName
        }
        Write-Host "        
        Veryifying '$serial' is added to the group '$GroupName'"
        while($(Get-AzureADGroupMember -ObjectId $QueryGroup.ObjectID -All $true | Select-Object DisplayName).DisplayName -notcontains $serial){
            Write-Host "
    Group '$GroupName' does not contain '$serial'" -ForegroundColor Yellow
            Write-Host "
    The script will attempt to add the device to the noted group and will wait for 5 seconds after attempting to add it" -ForegroundColor Yellow
            Write-Host "    NOTE: The script will be stuck in this loop until it sees the device added to the needed group. If it is stuck either add it to the noted group manually or restart the script" -ForegroundColor Yellow
            $DeviceQuery = Get-AzureADDevice -SearchString $serial
            foreach($Device in $DeviceQuery){
                Add-AzureADGroupMember -ObjectId $QueryGroup.ObjectID -RefObjectId $Device.ObjectID
                
            }
            Start-Sleep -Seconds 5
        }
        Write-Host "
        
        '$serial' is added to the group '$GroupName' moving on with the script. We'll now wait on the autopilot profile to be asigned" -ForegroundColor Green

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
                #Connect to AzureAD if it's not connected already if we end up doing the user query
                Try{
                    $AzureADConnectionTest = Get-AzureADDomain -Name $($aadId.tenantdomain)
                    if($AzureADConnectionTest.Name -ne $($aadId.tenantdomain)){
                        # Write-Host "Looks like you're already connected to Azure AD" -foregroundcolor green
                    }Else{
                        $AzureADConnection = Connect-AzureAD -AccountId $Username| Out-Null
                        $AzureADConnectionTest = Get-AzureADDomain -Name $($aadId.tenantdomain)
                    }

                }
                Catch{
                    while($AzureADConnectionTest.Name -ne $($aadId.tenantdomain)){
                        Write-Host "Connecting to Azure AD now" -foregroundcolor yellow
                        $AzureADConnection = Connect-AzureAD -AccountId $Username | Out-Null
                        $AzureADConnectionTest = Get-AzureADDomain -Name $($aadId.tenantdomain)
                    }
                }
                #Ensure device is in group
                $DeviceObjectID = $(Get-AzureADDevice -SearchString $serial).ObjectID
                $GroupMembershipCheck = $(Get-AzureADGroupMember -ObjectId $QueryGroup.ObjectId -All $true)
                if(!($GroupMembershipCheck -contains $DeviceObjectID)){
                    Write-host "The Azure AD Group $($QueryGroup.DisplayName) did not contain the device $serial | Attemptiong to add it now. If it fails this will loop forever. To fix this login to the 365 and add the device to the group manually" -ForegroundColor Yellow
                    Add-AzureADGroupMember -ObjectId $QueryGroup.ObjectId -RefObjectId $DeviceObjectID 
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
        Could not find the assigned user $QueryDisplayName ($UPN) assigned to device $serial. Trying to apply these paramaters again and will query after a 5 second wait timer."
            }
        }Else{
                Write-Host "
        It does look like the Display Name (addressableUserName) and userPrincipalName (Users username to login) assigned fine. It is $QueryDisplayName and $userPrincipalName resptively" -ForegroundColor Green
            }

        While($displayName -eq ""){
            #Connect to AzureAD if it's not connected already if we end up doing the user query
            Try{
                $AzureADConnectionTest = Get-AzureADDomain -Name $($aadId.tenantdomain)
                if($AzureADConnectionTest.Name -ne $($aadId.tenantdomain)){
                    # Write-Host "Looks like you're already connected to Azure AD" -foregroundcolor green
                }Else{
                    $AzureADConnection = Connect-AzureAD -AccountId $Username| Out-Null
                    $AzureADConnectionTest = Get-AzureADDomain -Name $($aadId.tenantdomain)
                }

            }
            Catch{
                while($AzureADConnectionTest.Name -ne $($aadId.tenantdomain)){
                    Write-Host "Connecting to Azure AD now" -foregroundcolor yellow
                    $AzureADConnection = Connect-AzureAD -AccountId $Username | Out-Null
                    $AzureADConnectionTest = Get-AzureADDomain -Name $($aadId.tenantdomain)
                }
            }
            #Ensure device is in group
            $DeviceObjectID = $(Get-AzureADDevice -SearchString $serial).ObjectID
            $GroupMembershipCheck = $(Get-AzureADGroupMember -ObjectId $QueryGroup.ObjectId -All $true)
            if(!($GroupMembershipCheck -contains $DeviceObjectID)){
                Write-host "The Azure AD Group $($QueryGroup.DisplayName) did not contain the device $serial | Attempting to add it now. If it fails this will loop forever. To fix this login to the 365 and add the device to the group manually" -ForegroundColor Yellow
                Add-AzureADGroupMember -ObjectId $QueryGroup.ObjectId -RefObjectId $DeviceObjectID 
            }
            $DeviceObjectID = $null
            $GroupMembershipCheck = $null

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
        Write-Host "
    Updates will now be installed if there are some remaining.
        If you are in a rush and need updates to not install simply hit Ctrl + c to end the script."
        $StopJob = Get-Job | Stop-Job
        UpdateWindows -InstallUpdates "Yes"
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
                # $graph = Connect-MSGraphApp -Tenant $TenantId -AppId $AppId -AppSecret $AppSecret
                # Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
                Write-Host "Hit need to conenct to MSGraph but this is currently commented out"
            }
            else {
                # $graph = Connect-MSGraph
                # Write-Host "Connected to Intune tenant $($graph.TenantId)"
                Write-Host "Hit need to conenct to MSGraph but this is currently commented out"
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
            0 { Stop-Transcript;exit }
        }
    }  while($userAction -notmatch "[12340]")
} until($userAction -eq "0")
#EndRegion - Menu
