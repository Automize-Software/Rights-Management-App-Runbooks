param(
    [Parameter(Mandatory = $true)]
    [string] $domainID, 
  
    [Parameter(Mandatory = $true)]
    [string] $snowCredentialsName, 
  
    [Parameter(Mandatory = $true)]
    [string] $instance
)


# Load data and setup connections

#ServiceNow Connection
$snowCredentials = Get-AutomationPSCredential -Name $snowCredentialsName
$ServiceNowAuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $snowCredentials.UserName, $snowCredentials.GetNetworkCredential().Password)))
$ServiceNowHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$ServiceNowHeaders.Add('Authorization', ('Basic {0}' -f $ServiceNowAuthInfo))
$ServiceNowHeaders.Add('Accept', 'application/json')
$ServiceNowHeaders.Add('Content-Type', 'application/json; charset=utf-8')

#Get Domain data
try {
    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'GET' -Uri "https://$($instance).service-now.com/api/now/table/x_autps_active_dir_domain/$($domainID)?sysparm_display_value=true&sysparm_limit=1" 
} catch {
    throw "Unable to connect to ServiceNow instance and retrieve domain information. Make sure the provided user credential has read access to the domain record."
}

$sysdomain = $response.result.sys_domain.display_value
$domainName = $response.result.name
$domainControllerIP = $response.result.domain_controller_ip
$ADcredentialsName = $response.result.automation_credentials.display_value
$AADcredentialsName = $response.result.azureadcredentials.display_value

#$TenantID = $domainName + ".onmicrosoft.com"
$TenantID = $response.result.tenant_azure_active_directory
Write-Output $TenantID
function SNComplete {
    param (
        $sys_id
    )
    try {
        $SnowInput = @{
            'status' = 4
        }
        $json = $SnowInput | ConvertTo-Json
        $body = [System.Text.Encoding]::UTF8.GetBytes($json)
        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri "https://$($instance).service-now.com/api/now/table/x_autps_active_dir_command_queue/$($sys_id)" -Body $body
        $output = $response.RawContent
        Write-Verbose "ServiceNow output: $output"
    }
    catch {
        Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
    }
}

function SNWIP {
    param (
        $sys_id
    )
    try {
        $ServiceNowURI = "https://$instance.service-now.com/api/now/table/x_autps_active_dir_command_queue/$sys_id"
        $SnowInput = @{
            'status' = 2
        }
        $json = $SnowInput | ConvertTo-Json
        $body = [System.Text.Encoding]::UTF8.GetBytes($json)
        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri "https://$($instance).service-now.com/api/now/table/x_autps_active_dir_command_queue/$($sys_id)" -Body $body
        $output = $response.RawContent
        Write-Verbose "ServiceNow output: $output"
    }
    catch {
        Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
    }
}

function SNFail {
    param (
        $sys_id
    )
    try {
        $ServiceNowURI = "https://$instance.service-now.com/api/now/table/x_autps_active_dir_command_queue/$sys_id"
        $SnowInput = @{
            'status'    = 3
            'exception' = $($_.Exception.Message)
        }
        $json = $SnowInput | ConvertTo-Json
        $body = [System.Text.Encoding]::UTF8.GetBytes($json)
        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri "https://$($instance).service-now.com/api/now/table/x_autps_active_dir_command_queue/$($sys_id)" -Body $body
        $output = $response.RawContent
        Write-Verbose "ServiceNow output: $output"
    }
    catch {
        Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
    }
}

#Write-Verbose "Runbook started - $($metadata.startTime)" -Verbose
 
if (Get-Module -ListAvailable -Name "ActiveDirectory") {
    Write-Verbose "Found ActiveDirectory module"
}
else {
    try {
        Write-Verbose "Did not find Active Directory module. Trying to install the RSAT-AD-PowerShell Windows Feature"
        Install-WindowsFeature RSAT-AD-PowerShell
    }
    catch {
        Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
        throw "Could not find ActiveDirectory module. Please install this module"
    }
}
if (Get-Module -ListAvailable -Name "ExchangeOnlineManagement") {
    Write-Verbose "Found Exchange Online Management module"
}
else {
    try {
        Write-Warning "Exchange Online Management module was not found. Trying to install it."
        Install-Module "ExchangeOnlineManagement" -Force
    }
    catch {
        throw "Did not find Exchange Online Management module. Please make sure the Exchange Online Management module is installed"
    }
}
Import-Module "ExchangeOnlineManagement"

if (Get-Module -ListAvailable -Name "AzureAD") {
    Write-Verbose "Found Exchange Azure Active Directory module"
}
else {
    try {
        Write-Warning "Azure Active Directory module was not found. Trying to install it."
        Install-Module "AzureAD" -Force
    }
    catch {
        throw "Did not find Azure Active Directory module. Please make sure the AzureAD module is installed."
    }
}
Import-Module "AzureAD"

# Setup connections

if($null -eq $ADcredentialsName) {
    Write-Warning "Active Directory Credentials not provided. No AD connection will be available"
} else {
	$ADcredentials = Get-AutomationPSCredential -Name $ADcredentialsName
}

if($null -eq $AADcredentialsName) {
    Write-Warning "Azure Active Directory Credentials not provided. No Azure AD or Exchange Online connection will be available"
} else {
	$AADcredentials = Get-AutomationPSCredential -Name $AADcredentialsName
    try {
        Connect-ExchangeOnline -Credential $AADcredentials
        Connect-AzureAD -TenantId $TenantID -Credential $AADcredentials
    } 
    catch {
        throw "Could not connect to Exchange Online / Azure AD"
    }
}


# Do an initial AD import

if($null -ne $ADcredentialsName) {
    try {
        $updateURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
        Write-Verbose $updateURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $updateURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
        $domain = Get-ADDomain -Server $domainControllerIP -Credential $ADcredentials
        $forest = Get-ADForest -Server $domainControllerIP -Credential $ADcredentials
        $pam = Get-ADOptionalFeature -Server $domainControllerIP -Credential $ADcredentials -filter { name -like "Privileged*" }
        $pamEnabled = $false
    
        if (($pam.PSobject.Properties.name -match "EnabledScopes")) {
            Write-Verbose "Found EnabledScopes in response"
            $EnabledScopes = [PSCustomObject]$pam.PSobject.Properties['EnabledScopes']
            if ($EnabledScopes.Value.count -eq 0) {
                $pamEnabled = $false
            }
            else {
                $pamEnabled = $true
            }
        } 
      
        $domainInput = @{
            'domain_mode' = ($domain.DomainMode).ToString()
            'name'        = $domain.Name
            'forest_mode' = ($forest.ForestMode).ToString()
            'forest_name' = $forest.Name
            'pam_enabled' = $pamEnabled
            'sync_state'  = "ready"
        }
      
        $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID"
      
        $json = $domainInput | ConvertTo-Json
        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
        Write-Verbose "ServiceNow input: $body"
        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
        $output = $response.RawContent
        Write-Verbose "ServiceNow output: $output"
    }
    catch {
        Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
        #throw
    }
}


if($null -ne $AADcredentialsName) {
    try {
        $updateURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
        Write-Verbose $updateURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $updateURI -Headers $ServiceNowHeaders | ConvertTo-Json
      
    }
    catch {
        Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
        #throw
    }
}


$TimeNow = Get-Date
$TimeEnd = $TimeNow.addMinutes(60)

while ($TimeNow -le $TimeEnd) { 
    $TimeNow = Get-Date
    $ServiceNowURI = "https://$instance.service-now.com/api/now/table/x_autps_active_dir_command_queue?sysparm_query=domain%3D$domainID%5Estatus%3D1%5EORDERBYsys_created_on&sysparm_limit=1"
    Write-Verbose "ServiceNow URI: $ServiceNowURI"
    $jobQueue = Invoke-RestMethod -Method "GET" -Uri $ServiceNowURI -Headers $ServiceNowHeaders 
    if ($jobQueue.result) {
        $jobQueueItem = $jobQueue.result[0]
        Write-Verbose "Processing command queue item with sys_id $($jobQueueItem.sys_id)"
        SNWIP $jobQueueItem.sys_id
        try {
            $JSONObject = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($jobQueueItem.input))
            Write-Output $JSONObject
            $ParameterObject = $JSONObject | ConvertFrom-Json
            Write-Verbose "Executing action $($ParameterObject.action)"
            if ($ParameterObject.action -eq "Create-User") {
                try {
          
                    if ($null -ne $ParameterObject.givenname -and $null -ne $ParameterObject.surname -and $ParameterObject.givenname -ne '' -and $ParameterObject.surname -ne '') {
                        $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname + " (" + $ParameterObject.username + ")"
                    }
                    elseif ($null -ne $ParameterObject.surname -and $ParameterObject.surname -ne '') {
                        $displayname = $ParameterObject.surname + " (" + $ParameterObject.username + ")"
                    }
                    elseif ($null -ne $ParameterObject.givenname -and $ParameterObject.givenname -ne '') {
                        $displayname = $ParameterObject.givenname + " (" + $ParameterObject.username + ")"
                    }
                    else {
                        $displayname = $ParameterObject.username
                    }
          
                    $samAccountName = $ParameterObject.username
                    $userPrincipalName = $samtAccountName + "@" + $domainName
                    $userPassword = ConvertTo-SecureString $ParameterObject.password -AsPlainText -Force
          
                    $createUser = New-ADUser -SamAccountName $samAccountName `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials  `
                        -Name $displayname `
                        -Givenname $ParameterObject.givenname `
                        -Surname $ParameterObject.surname `
                        -Title $ParameterObject.title `
                        -Office $ParameterObject.office `
                        -PostalCode $ParameterObject.postalcode `
                        -City $ParameterObject.city `
                        -Country $ParameterObject.country `
                        -Company $ParameterObject.company `
                        -EmailAddress $ParameterObject.emailAddress `
                        -OfficePhone $ParameterObject.officePhone `
                        -MobilePhone $ParameterObject.mobilePhone `
                        -Department $ParameterObject.department `
                        -EmployeeID $ParameterObject.employeeid `
                        -EmployeeNumber $ParameterObject.employeenumber `
                        -Description $ParameterObject.description `
                        -AccountPassword $userPassword `
                        -Path $ParameterObject.path `
                        -Enabled:$true `
                        -ChangePasswordAtLogon:$false `
                        -PassThru:$true
      
                    $user = Get-ADUser -Identity $ParameterObject.username `
                        -Properties GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
                    $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $userInput = @{
                        'GivenName'             = $user.GivenName
                        'Surname'               = $user.Surname
                        'UserPrincipalName'     = $user.UserPrincipalName
                        'Enabled'               = $user.Enabled
                        'SamAccountName'        = $user.SamAccountName
                        'DistinguishedName'     = $user.DistinguishedName
                        'Name'                  = $user.Name
                        'ObjectClass'           = $user.ObjectClass
                        'ObjectGuid'            = $user.ObjectGuid
                        'AccountExpirationDate' = $user.AccountExpirationDate
                        'AccountLockoutTime'    = $user.AccountLockoutTime
                        'CannotChangePassword'  = $user.CannotChangePassword
                        'City'                  = $user.City
                        'Company'               = $user.Company
                        'Country'               = $user.Country
                        'Department'            = $user.Department
                        'Description'           = $user.Description
                        'EmailAddress'          = $user.EmailAddress
                        'EmployeeID'            = $user.EmployeeID
                        'EmployeeNumber'        = $user.EmployeeNumber
                        'LockedOut'             = $user.LockedOut
                        'MobilePhone'           = $user.MobilePhone
                        'Office'                = $user.Office
                        'OfficePhone'           = $user.OfficePhone
                        'PasswordExpired'       = $user.PasswordExpired
                        'PasswordNeverExpires'  = $user.PasswordNeverExpires 
                        'PostalCode'            = $user.PostalCode
                        'Title'                 = $user.Title
                        'sysid'                 = $ParameterObject.usersysid
                    }
                    $json = $userInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    SNFail $jobQueueItem.sys_id
                    Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                    try {
                        $usersysid = $ParameterObject.usersysid
                        $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
                        $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
        
                        Write-Verbose "ServiceNow URL $ServiceNowURI"
            
                        $userInput = @{
                            'sysid'      = $ParameterObject.usersysid
                            'Sync State' = "Failed"
                        }
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI2 -Body $body
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    }
                    catch {
                        Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                    }
                }
            }
            #
            #
            # Set Exchange Online Folder Permission
            if ($ParameterObject.action -eq "Set-ExchangeOnline-Folder-Permission") {
              try{
                $mailboxName = $ParameterObject.mailboxName #Eg. emi@automize.dk
                $permissionRoleToSet = $ParameterObject.permissionRoleToSet #Eg. "Reviewer"
                $folderType = $ParameterObject.folderType #Eg. 'Calendar'
                $userToGrant = $ParameterObject.userToGrant #Eg. "default"
        
                if ($userToGrant -ne 'default') {
                    try {
                        Get-AzureADUser -ObjectId $userToGrant -ErrorAction Stop > $null
                    }
                    catch {
                        $errorMessage = $error[0].exception.message
                        throw "Could not verify user. Message: $errorMessage"
                    }
                }

        
                try {
                    $mailBox = Get-EXOMailbox -Identity $mailboxName -ErrorAction Stop
                    $upn = $mailBox.UserPrincipalName
                    $nameForFolderType = (Get-EXOMailboxFolderStatistics -Identity $upn | Where-Object { $_.FolderType -eq $folderType }).Name
                    $identity = $upn + ":\" + $nameForFolderType
                    $permisson = Get-MailboxFolderPermission -Identity $identity -user $userToGrant -ErrorAction SilentlyContinue
                    if ($permisson.AccessRights -eq $permissionRoleToSet) {
                        Write-Output "Folder permission already set for $identity."
                    }
                    else {
                        Set-MailboxFolderPermission -identity $identity -User $userToGrant -AccessRights $permissionRoleToSet > $null
                        Write-Output "Folder permission set successfully for $userToGrant on $identity."
                    }
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    $errorMessage = $error[0].exception.message
                    throw "Could not set / verify folder permission. Message: $errorMessage"
                }
                
              } catch {
                SNFail $jobQueueItem.sys_id
                Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
              }
                
            }


            #
            #
            #Create azure ad user
            if ($ParameterObject.action -eq "Create-AzureAD-User") {
                try {
                   
          
                    if ($null -ne $ParameterObject.usertypeset -and $ParameterObject.usertypeset -ne ''){
                        Write-Output "usertypetest $($ParameterObject.usertypetest)"
                        if($null -ne $ParameterObject.givenname -and $null -ne $ParameterObject.surname -and $ParameterObject.givenname -ne '' -and $ParameterObject.surname -ne '') {
                       Write-Output "usertypetest $($ParameterObject.name)"
                        $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname + " (" + $ParameterObject.usertypeset + ")"
                    }
                        elseif ($null -ne $ParameterObject.surname -and $ParameterObject.surname -ne '') {
                        $displayname = $ParameterObject.surname + " (" + $ParameterObject.usertypeset + ")"
                    }
                        elseif($null -ne $ParameterObject.givenname -and $ParameterObject.givenname -ne '') {
                        $displayname = $ParameterObject.givenname + " (" + $ParameterObject.usertypeset + ")"
                    } 
                    elseif($null -ne $ParameterObject.name){
                        $displayname = $ParameterObject.name + " (" + $ParameterObject.usertypeset + ")"
                    }
                    
                    }
                     elseif ($null -ne $ParameterObject.name){
                         Write-Output "usertypetest $($ParameterObject.name)"
                        $displayname = $ParameterObject.name
                    }
                    else {
                         if($null -ne $ParameterObject.givenname -and $null -ne $ParameterObject.surname -and $ParameterObject.givenname -ne '' -and $ParameterObject.surname -ne '') {
                        $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname 
                    }
                    elseif ($null -ne $ParameterObject.surname -and $ParameterObject.surname -ne '') {
                        $displayname = $ParameterObject.surname
                    }
                    elseif($null -ne $ParameterObject.givenname -and $ParameterObject.givenname -ne '') {
                        $displayname = $ParameterObject.givenname 
                    }
                    }

                    Write-Output $displayname
                    
                    if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        throw "Could not find AzureAD module. Please install this module"
                    }
                    $userName = $ParameterObject.username
                    Write-Output "username $userName"
                    $AADdomainprinc = (Get-AzureADDomain | Where-Object { $_.isDefault }).name
                    Write-Output "$AADdomainprinc"
                    $princname = $userName -replace '\s', ''
                    $userprinname = $princname + "@" + $AADdomainprinc
		
                    Write-Output $userprinname
                    $user = Get-AzureADUser -Filter "userPrincipalName eq '$userprinname'"
		
                    if ($user) {
                        throw "Cannot create user. The user '$userName' already exists"
                    }
                    else {
                        $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
                        $PasswordProfile.Password = $ParameterObject.password
        
                        $user = New-AzureADUser `
                            -DisplayName $displayname `
                            -AgeGroup $ParameterObject.agegroup `
                            -City $ParameterObject.city `
                            -CompanyName $ParameterObject.company `
                            -Country $ParameterObject.country `
                            -Department $ParameterObject.department `
                            -GivenName $ParameterObject.givenname `
                            -JobTitle $ParameterObject.title `
                            -Mobile $ParameterObject.mobile `
                            -PhysicalDeliveryOfficeName $ParameterObject.physicaldelofficename `
                            -PostalCode $ParameterObject.postalcode `
                            -PreferredLanguage $ParameterObject.preferredlang `
                            -StreetAddress $ParameterObject.streetaddress `
                            -Surname $ParameterObject.surname `
                            -TelephoneNumber $ParameterObject.telephonenumber `
                            -UsageLocation $ParameterObject.usagelocation `
                            -UserState $ParameterObject.userstate `
                            -UserType $ParameterObject.usertype `
                            -userPrincipalName $userprinname `
                            -PasswordProfile $PasswordProfile `
                            -AccountEnabled $true `
                            -mailNickname $princname
                        $user = Get-AzureADUser -Filter "userPrincipalName eq '$userprinname'"
                        Write-Output "Azure user id" $user.ObjectId "and manager" $ParameterObject.manager
                        $user = Get-AzureADUser -Filter "userPrincipalName eq '$userprinname'"
                        Write-Output "Azure user id" $user.ObjectId "and manager" $ParameterObject.manager
                        if (-not ([string]::IsNullOrEmpty($ParameterObject.manager))) {
                            Set-AzureADUserManager -ObjectId $user.ObjectId -RefObjectId $ParameterObject.manager
                        }
		

                        $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser"
                        $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                        Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                        $userInput = @{
                            'ObjectGuid'                 = $user.ObjectId
                            'AccountEnabled'             = $user.AccountEnabled
                            'AgeGroup'                   = $user.AgreGroup
                            'City'                       = $user.City
                            'Company'                    = $user.CompanyName
                            'Country'                    = $user.country
                            'Department'                 = $user.Department
                            'DisplayName'                = $user.DisplayName
                            'GivenName'                  = $user.GivenName
                            'Title'                      = $user.JobTitle
                            'MailNickName'               = $user.MailNickName
                            'Mobile'                     = $user.Mobile
                            'PhysicalDeliveryOfficeName' = $user.PhysicalDeliveryOfficeName
                            'PostalCode'                 = $user.PostalCode
                            'PreferredLanguage'          = $user.PreferredLanguage
                            'StreetAddress'              = $user.StreetAddress
                            'Surname'                    = $user.Surname
                            'TelephoneNumber'            = $user.TelephoneNumber
                            'UsageLocation'              = $user.UsageLocation
                            'UserPrincipalName'          = $user.UserPrincipalName
                            'UserState'                  = $user.UserState
                            'UserType'                   = $user.UserType
                            'Name'                       = $user.DisplayName
                            'sysid'                      = $ParameterObject.usersysid
                        }
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                        SNComplete $jobQueueItem.sys_id
                    }
                }
                catch {
                    SNFail $jobQueueItem.sys_id
                    Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
		
                    try {
                        $usersysid = $ParameterObject.usersysid
                        $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser"
                        $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
        
                        Write-Verbose "ServiceNow URL $ServiceNowURI"
            
                        $userInput = @{
                            'sysid'      = $ParameterObject.usersysid
                            'Sync State' = "Failed"
                        }
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI2 -Body $body
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    } 
                    catch {
                        Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                    }
                }
            }

            #
            #
	 
            if ($ParameterObject.action -eq "Update-User") {
                try {
                    $user = Get-ADUser -Identity $ParameterObject.user `
                        -Properties GivenName, Surname, Description, title, office, postalcode, city, country, company, emailaddress, officephone, mobilephone, department, employeeid, employeenumber `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
            
                    $ParameterObject.PSObject.Properties | ForEach-Object {
                        $parmName = $_.Name
                        $parmValue = $_.Value
                        if ($parmName -ne "usersysid" -and $parmName -ne "action" -and $parmName -ne "user") {   
                            if ($parmValue -eq "") {
                                $user.$parmName = $null
                            }
                            elseif ($parmValue -eq "false") {
                                $user.$parmName = $false
                            }
                            elseif ($parmValue -eq "true") {
                                $user.$parmName = $true
                            }
                            else {
                                $user.$parmName = $parmValue
                            }
                        }
                    } 
      
                    Set-ADUser -Instance $user `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
          
                    $user = Get-ADUser -Identity $ParameterObject.user `
                        -Properties GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $userInput = @{
                        'GivenName'             = $user.GivenName
                        'Surname'               = $user.Surname
                        'UserPrincipalName'     = $user.UserPrincipalName
                        'Enabled'               = $user.Enabled
                        'SamAccountName'        = $user.SamAccountName
                        'DistinguishedName'     = $user.DistinguishedName
                        'Name'                  = $user.Name
                        'ObjectClass'           = $user.ObjectClass
                        'ObjectGuid'            = $user.ObjectGuid
                        'AccountExpirationDate' = $user.AccountExpirationDate
                        'AccountLockoutTime'    = $user.AccountLockoutTime
                        'CannotChangePassword'  = $user.CannotChangePassword
                        'City'                  = $user.City
                        'Company'               = $user.Company
                        'Country'               = $user.Country
                        'Department'            = $user.Department
                        'Description'           = $user.Description
                        'EmailAddress'          = $user.EmailAddress
                        'EmployeeID'            = $user.EmployeeID
                        'EmployeeNumber'        = $user.EmployeeNumber
                        'lastLogon'             = $user.lastLogon
                        'LockedOut'             = $user.LockedOut
                        'MobilePhone'           = $user.MobilePhone
                        'Office'                = $user.Office
                        'OfficePhone'           = $user.OfficePhone
                        'PasswordExpired'       = $user.PasswordExpired
                        'PasswordNeverExpires'  = $user.PasswordNeverExpires
                        'PostalCode'            = $user.PostalCode
                        'Title'                 = $user.Title
                        'sysid'                 = $ParameterObject.usersysid
                    }
                    $json = $userInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    SNFail $jobQueueItem.sys_id
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    $usersysid = $ParameterObject.usersysid
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $userInput = @{
                        'sysid'      = $ParameterObject.usersysid
                        'Sync State' = "Failed"
                    }
                    $json = $userInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
          
                } 
            }

            #
            #
            #Azure ad update user
            if ($ParameterObject.action -eq "Update-AzureAD-User") {
                try {
                    if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        throw "Could not find AzureAD module. Please install this module"
                    }
                    $DisplayName = $ParameterObject.displayname
                    $user = Get-AzureADUser -ObjectId $ParameterObject.user 
                    $ParameterObject.PSObject.Properties | ForEach-Object {
                        $parmName = $_.Name
                        $parmValue = $_.Value
                        if ($parmName -ne "usersysid" -and $parmName -ne "action" -and $parmName -ne "user") {   
                            if ([string]::IsNullOrWhiteSpace($parmValue)) {
                                $user.$parmName = " "
                            }
                            elseif ($parmValue -eq "") {
                                $user.$parmName = $null
                            }
                            elseif ($parmValue -eq "false") {
                                $user.$parmName = $false
                            }
                            elseif ($parmValue -eq "true") {
                                $user.$parmName = $true
                            }
                            else {
                                $user.$parmName = $parmValue
                            }
                        }
                    } 
                    Set-AzureADUser -ObjectId $ParameterObject.user -DisplayName $ParameterObject.displayname -GivenName $ParameterObject.givenname -Surname $ParameterObject.surname -Department $ParameterObject.department -UserPrincipalName $ParameterObject.userprincipalname -AccountEnabled $ParameterObject.enabled -mailNickname $ParameterObject.emailaddress -JobTitle $ParameterObject.jobtitle `
                        -City $ParameterObject.city -PostalCode $ParameterObject.postalcode -Country $ParameterObject.country -PhysicalDeliveryOfficeName $ParameterObject.physicaldeliveryofficename -CompanyName $ParameterObject.companyname -TelephoneNumber $ParameterObject.telephonenumber -Mobile $ParameterObject.mobile -PreferredLanguage $ParameterObject.preferredlanguage -StreetAddress $ParameterObject.streetaddress
          
                    $user = Get-AzureADUser -ObjectId $ParameterObject.user | select $properties 
           
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $userInput = @{
                        'GivenName'             = $user.firstname
                        'Surname'               = $user.lastname
                        'UserPrincipalName'     = $user.UserPrincipalName
                        'enabled'               = $user.AccountEnabled
                        'Name'                  = $user.DisplayName
                        'ObjectClass'           = $user.ObjectClass
                        'ObjectGuid'            = $user.ObjectId
                        'AccountExpirationDate' = $user.AccountExpirationDate
                        'AccountLockoutTime'    = $user.AccountLockoutTime
                        'CannotChangePassword'  = $user.CannotChangePassword
                        'City'                  = $user.City
                        'Company'               = $user.Company
                        'Country'               = $user.Country
                        'Department'            = $user.Department
                        'Description'           = $user.Description
                        'EmailAddress'          = $user.MailNickName
                        'EmployeeID'            = $user.EmployeeID
                        'EmployeeNumber'        = $user.EmployeeNumber
                        'lastLogon'             = $user.lastLogon
                        'LockedOut'             = $user.LockedOut
                        'MobilePhone'           = $user.MobilePhone
                        'Office'                = $user.Office
                        'OfficePhone'           = $user.OfficePhone
                        'PasswordExpired'       = $user.PasswordExpired
                        'PasswordNeverExpires'  = $user.PasswordNeverExpires
                        'postalcode'            = $user.PostalCode
                        'title'                 = $user.JobTitle
                        'sysid'                 = $ParameterObject.usersysid
                    }
                    $json = $userInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    SNFail $jobQueueItem.sys_id
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    $usersysid = $ParameterObject.usersysid
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $userInput = @{
                        'sysid'      = $ParameterObject.usersysid
                        'Sync State' = "Failed"
                    }
                    $json = $userInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
          
                } 
            }
            #
            #
            #
      
            if ($ParameterObject.action -eq "Remove-User") {
                try {
                    $user = Remove-ADUser -Identity $ParameterObject.user `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Confirm:$false
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
      
                    SNFail $jobQueueItem.sys_id
                } 
            }
      
            if ($ParameterObject.action -eq "Set-User-Password") {
                try {
                    $user = Set-ADAccountPassword -Identity $ParameterObject.user `
                        -Reset `
                        -NewPassword (ConvertTo-SecureString -AsPlainText $ParameterObject.password -Force) `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Confirm:$false
                    Write-Output "User password has been set"  
                    if ($ParameterObject.mustChange -eq $true) {
                        Set-ADUser -Identity $ParameterObject.user `
                            -ChangePasswordAtLogon $true `
                            -Server $domainControllerIP `
                            -Credential $ADcredentials `
                            -Confirm:$false
                        Write-Output "User must change password at next login"
                    }
          
                    if ($ParameterObject.unlock -eq $true) {
                        Unlock-ADAccount -Identity $ParameterObject.user `
                            -Server $domainControllerIP `
                            -Credential $ADcredentials `
                            -Confirm:$false
                        Write-Output "User has been unlocked"
                    }
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                } 
            }
            ## Azure ad remove user
            #
            #

            if ($ParameterObject.action -eq "Remove-AzureAD-User") {
                try {
                    $identity = $ParameterObject.user
                    Write-Output $identity
                    $user = Get-AzureADUser -ObjectId $identity
                    if (!$user) {
                        throw "Cannot find user. The user does not exist"
                    }
                    else {
                        Write-Verbose "Removing user"
                        Remove-AzureADUser -ObjectId $identity
                        Write-Verbose "User removed"
                        SNComplete $jobQueueItem.sys_id
                    } 
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
      
                    SNFail $jobQueueItem.sys_id
                } 
            }
	  
     
            #
            #
            #
            #set azure ad user password
            if ($ParameterObject.action -eq "Set-AzureAD-User-Password") {
                try {
                    $identity = $ParameterObject.user
					#################added###########################
                    $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
                    $PasswordProfile.Password = $ParameterObject.password
                    $user = Set-AzureADUserPassword -ObjectId $identity -Password (ConvertTo-SecureString $ParameterObject.password -AsPlainText -Force) 
                   Write-Output "User password has been set"  
                    if ($ParameterObject.mustChange -eq $true) {
                        Set-AzureADUser -ObjectId $ParameterObject.user `
                            -ForceChangePasswordNextLogin $true
                        Write-Output "User must change password at next login"
                    }
          
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                } 
            }
            #
            #
            #
            #
            if ($ParameterObject.action -eq "Unlock-User") {
                try {
                    Unlock-ADAccount -Identity $ParameterObject.user `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Confirm:$false
                    Write-Output "User has been unlocked"
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                } 
            }
      
            if ($ParameterObject.action -eq "Enable-User") {
                try {
                    Enable-ADAccount -Identity $ParameterObject.user `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Confirm:$false
                    Write-Output "User has been enabled"
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                } 
            }
      
            #
            #
            # Enable azure AD account
            if ($ParameterObject.action -eq "Enable-AzureADUser") {
                try {
                    $user = Get-AzureADUser -ObjectId $ParameterObject.user 
                    Set-AzureADUser -ObjectId $ParameterObject.user --AccountEnabled $true
         
                    Write-Output "User has been enabled"
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                } 
            }
            #
            #
            #
            if ($ParameterObject.action -eq "Disable-User") {
                try {
                    Disable-ADAccount -Identity $ParameterObject.user `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Confirm:$false
                    Write-Output "User has been disabled"
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                } 
            }
      
            #
            #
            # Disable azure AD account
            if ($ParameterObject.action -eq "Disable-AzureADUser") {
                try {
                    $user = Get-AzureADUser -ObjectId $ParameterObject.user 
                    Set-AzureADUser -ObjectId $ParameterObject.user --AccountEnabled $false
         
                    Write-Output "User has been disabled"
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                } 
            }
            #
            #
            #

            if ($ParameterObject.action -eq "Import-Users") {
                try {
                    $users = Get-ADUser -Filter * `
                        -Properties GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, accountExpires, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
           
                    foreach ($user in $users) {
                        $userInput = @{
                            'Domain'                = $domainID
                            'GivenName'             = $user.GivenName
                            'Surname'               = $user.Surname
                            'UserPrincipalName'     = $user.UserPrincipalName
                            'Enabled'               = $user.Enabled
                            'SamAccountName'        = $user.SamAccountName
                            'DistinguishedName'     = $user.DistinguishedName
                            'Name'                  = $user.Name
                            'ObjectClass'           = $user.ObjectClass
                            'ObjectGuid'            = $user.ObjectGuid
                            'AccountExpirationDate' = $user.AccountExpirationDate
                            'accountExpires'        = $user.accountExpires
                            'AccountLockoutTime'    = $user.AccountLockoutTime
                            'CannotChangePassword'  = $user.CannotChangePassword
                            'City'                  = $user.City
                            'Company'               = $user.Company
                            'Country'               = $user.Country
                            'Department'            = $user.Department
                            'Description'           = $user.Description
                            'EmailAddress'          = $user.EmailAddress
                            'EmployeeID'            = $user.EmployeeID
                            'EmployeeNumber'        = $user.EmployeeNumber
                            'lastLogon'             = $user.lastLogon
                            'LockedOut'             = $user.LockedOut
                            'MobilePhone'           = $user.MobilePhone
                            'Office'                = $user.Office
                            'OfficePhone'           = $user.OfficePhone
                            'PasswordExpired'       = $user.PasswordExpired
                            'PasswordNeverExpires'  = $user.PasswordNeverExpires
                            'PostalCode'            = $user.PostalCode
                            'Title'                 = $user.Title
                        }
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }
            #Import azure AD Users
            #Import azure AD Users
            if ($ParameterObject.action -eq "Import-AzureAD-Users") {
                try {
                    if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        Install-Module -Name "AzureAD"
                        throw "Could not find AzureAD module. Please install this module"
                    }
	$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                    $properties = @(
                        'ObjectId',
                        'Name',
                        'DisplayName',
                        'givenname',
                        'surname',
                        'userprincipalname',
                        'Mail',
                        'MailNickName',
                        'jobtitle',
                        'department',
                        'telephoneNumber',
                        'PhysicalDeliveryOfficeName',
                        'mobile',
                        'streetAddress',
                        'city',
                        'postalcode',
                        'state',
                        'country',
                        'AccountEnabled'
                    )
                    $users = Get-AzureADUser -all $true | select $properties 
      
                    $ServiceNowURI = "https://$instance.service-now.com//api/x_autps_active_dir/domain/$domainID/aduser"
                    $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
           
                    foreach ($user in $users) {
                        $UserExtProperties = Get-AzureADUserExtension -ObjectId $user.ObjectId
                        $employeeId = $UserExtProperties["employeeId"]
                        $userInput = @{
                            'ObjectGuid'        = $user.ObjectId
                            'Domain'            = $domainID
                            'GivenName'         = $user.givenname
                            'Surname'           = $user.surname
                            'UserPrincipalName' = $user.UserPrincipalName
                            'Enabled'           = $user.AccountEnabled
                            'Name'              = $user.DisplayName
                            'ObjectClass'       = $user.ObjectType
                            'City'              = $user.City
                            'Company'           = $user.CompanyName
                            'Country'           = $user.Country
                            'Email'				= $user.Mail
                            'Department'        = $user.Department
                            'Description'       = $user.Description
                            'MailNickName'      = $user.MailNickName
                            'Mobile'            = $user.mobile
                            'OfficePhone'       = $user.telephoneNumber
                            'PostalCode'        = $user.postalcode
                            'Title'             = $user.JobTitle
                            'EmployeeID'        = $employeeId
                        }
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
            
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                    $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity/cleanup"
                    $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI2
                    SNComplete $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/ready"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    throw
                }
            }
            #
            #
            #

            if ($ParameterObject.action -eq "Create-Group") {
                try {
                    $createGroup = New-ADGroup -Name $ParameterObject.name `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials  `
                        -Description $ParameterObject.description `
                        -GroupScope $ParameterObject.groupScope `
                        -GroupCategory $ParameterObject.groupCategory `
                        -PassThru:$true
          	
                    $group = Get-ADGroup -Identity $createGroup.ObjectGUID `
                        -Properties Description `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'Enabled'           = $group.Enabled
                        'SamAccountName'    = $group.SamAccountName
                        'DistinguishedName' = $group.DistinguishedName
                        'Name'              = $group.Name
                        'ObjectClass'       = $group.ObjectClass
                        'ObjectGuid'        = $group.ObjectGuid
                        'Description'       = $group.Description
                        'GroupScope'        = $group.GroupScope
                        'GroupCategory'     = $group.GroupCategory
                        'sysid'             = $ParameterObject.groupsysid
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                    $groupsysid = $ParameterObject.groupsysid
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'sysid'      = $ParameterObject.groupsysid
                        'Sync State' = "Failed"
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                } 
            }
            ###
            #
            #
            #Create azure ad group
            if ($ParameterObject.action -eq "Create-AzureAD-Group") {
                try {
                    if ($ParameterObject.securityenabled -eq $null) {
                        $ParameterObject.securityenabled = $false
                    }
                    elseif ($ParameterObject.securityenabled -eq "0") {
                        $ParameterObject.securityenabled = $false
                    }
                    else {
                        $ParameterObject.securityenabled = $true
                    }
                    if ($ParameterObject.mailenabled -eq $null) {
                        $ParameterObject.mailenabled = $false
                    }
                    elseif ($ParameterObject.mailenabled -eq "0") {
                        $ParameterObject.mailenabled = $false
                    }
                    else {
                        $ParameterObject.mailenabled = $true
                    }
                    $createGroup = New-AzureADGroup -DisplayName $ParameterObject.name -MailEnabled $ParameterObject.MailEnabled -MailNickName $ParameterObject.mailnickname -SecurityEnabled $ParameterObject.securityenabled
                    $group = Get-AzureADGroup -ObjectId $createGroup.ObjectId 
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'Description'     = $group.Description
                        'DisplayName'     = $group.DisplayName
                        'MailEnabled'     = $group.MailEnabled
                        'MailNickName'    = $group.MailNickName
                        'SecurityEnabled' = $group.SecurityEnabled
                        'Mail'            = $group.Mail
                        'ObjectType'      = $group.ObjectType
                        'sysid'           = $ParameterObject.groupsysid
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                    $groupsysid = $ParameterObject.groupsysid
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'sysid'      = $ParameterObject.groupsysid
                        'Sync State' = "Failed"
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                } 
            }
            #
            #
            #
      
            if ($ParameterObject.action -eq "Update-Group") {
                try {
                    $group = Get-ADGroup -Identity $ParameterObject.group `
                        -Properties Description `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
            
                    $ParameterObject.PSObject.Properties | ForEach-Object {
                        $parmName = $_.Name
                        $parmValue = $_.Value
                        if ($parmName -ne "groupsysid" -and $parmName -ne "action" -and $parmName -ne "group" -and $parmName -ne "name") {   
                            if ($parmValue -eq "") {
                                $group.$parmName = $null
                            }
                            elseif ($parmValue -eq "false") {
                                $group.$parmName = $false
                            }
                            elseif ($parmValue -eq "true") {
                                $user.$parmName = $true
                            }
                            else {
                                $group.$parmName = $parmValue
                            }
                        }
                    } 
      
                    Set-ADGroup -Instance $group `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
          
                    $group = Get-ADGroup -Identity $ParameterObject.group `
                        -Properties Description `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'Enabled'           = $group.Enabled
                        'SamAccountName'    = $group.SamAccountName
                        'DistinguishedName' = $group.DistinguishedName
                        'Name'              = $group.Name
                        'ObjectClass'       = $group.ObjectClass
                        'ObjectGuid'        = $group.ObjectGuid
                        'Description'       = $group.Description
                        'GroupScope'        = $group.GroupScope
                        'GroupCategory'     = $group.GroupCategory
                        'sysid'             = $ParameterObject.groupsysid
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                    if ($response.result.sync_policy -gt 0) {
                        $groupMembers = Get-ADGroupMember -Server $domainControllerIP -Credential $ADcredentials -Identity $group.ObjectGuid
                        $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/groupmember"
                        foreach ($member in $groupMembers) {
                            if ($null -ne $member.ObjectClass) {
                                $memberInput = @{
                                    'Domain'            = $domainID
                                    'GroupGUID'         = $group.ObjectGuid
                                    'SamAccountName'    = $member.SamAccountName
                                    'DistinguishedName' = $member.DistinguishedName
                                    'ObjectClass'       = $member.ObjectClass
                                    'ObjectGuid'        = $member.ObjectGuid
                                    'Name'              = $member.Name
                                }
                                $gmjson = $memberInput | ConvertTo-Json
                                $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                                Write-Verbose "ServiceNow groupmember input: $gmbody"
                                $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                                $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
                            }
                        }
                    }
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'sysid'      = $ParameterObject.groupsysid
                        'Sync State' = "Failed"
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                } 
            }
            #
            #
            #
            #Update azure AD Group
            if ($ParameterObject.action -eq "Update-AzureAD-Group") {
                try {
                    $group = Get-AzureADGroup -ObjectId $ParameterObject.group 
                    if ($ParameterObject.securityenabled -eq $null) {
                        $ParameterObject.securityenabled = $false
                    }
                    elseif ($ParameterObject.securityenabled -eq "0") {
                        $ParameterObject.securityenabled = $false
                    }
                    else {
                        $ParameterObject.securityenabled = $true
                    }
                    if ($ParameterObject.mailenabled -eq $null) {
                        $ParameterObject.mailenabled = $false
                    }
                    elseif ($ParameterObject.mailenabled -eq "0") {
                        $ParameterObject.mailenabled = $false
                    }
                    else {
                        $ParameterObject.mailenabled = $true
                    }
                    $ParameterObject.PSObject.Properties | ForEach-Object {
                        $parmName = $_.Name
                        $parmValue = $_.Value
                        if ($parmName -ne "groupsysid" -and $parmName -ne "action" -and $parmName -ne "group" -and $parmName -ne "name") {   
                            if ([string]::IsNullOrWhiteSpace($parmValue)) {
                                $group.$parmName = " "
                            }
                            elseif ($parmValue -eq "") {
                                $group.$parmName = $null
                            }
                            elseif ($parmValue -eq "0") {
                                $group.$parmName = $false
                            }
                            elseif ($parmValue -eq "1") {
                                $group.$parmName = $true
                            }
                            else {
                                $group.$parmName = $parmValue
                            }
                        }
                    } 
      
                    Set-AzureADGroup -ObjectId $ParameterObject.group -Description $ParameterObject.description -DisplayName $ParameterObject.name -MailNickName $ParameterObject.mailnickname 
                    $group = Get-AzureADGroup -ObjectId $ParameterObject.group 
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'ObjectGuid'      = $group.ObjectId
                        'Description'     = $group.Description 
                        'Name'            = $group.DisplayName
                        'MailEnabled'     = $group.MailEnabled
                        'MailNickName'    = $group.MailNickName
                        'SecurityEnabled' = $group.SecurityEnabled
                        'sysid'           = $ParameterObject.groupsysid
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                    if ($response.result.sync_policy -gt 0) {
                        $groupMembers = Get-AzureADGroupMember -ObjectId $group.ObjectId
                        Write-Output "Group members of update group $groupMembers"
                        $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroupmember"
                        foreach ($member in $groupMembers) {
                            if ($null -ne $member.ObjectType) {
                                $memberInput = @{
                                    'Domain'      = $domainID
                                    'GroupGUID'   = $group.ObjectId
                                    'Name'        = $member.DisplayName
                                    'ObjectClass' = $member.ObjectType
                                    'ObjectId'    = $member.ObjectId
                                }
                                $gmjson = $memberInput | ConvertTo-Json
                                $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                                Write-Verbose "ServiceNow groupmember input: $gmbody"
                                $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                                $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
                            }
                        }
                    }
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'sysid'      = $ParameterObject.groupsysid
                        'Sync State' = "Failed"
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                } 
            }
            #
            #
            #
            #
      
            if ($ParameterObject.action -eq "Remove-Group") {
                try {
                    $group = Remove-ADGroup -Identity $ParameterObject.group `
                        -Properties Description `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Confirm:$false
                    SNComplete $jobQueueItem.sys_id
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                } 
            }
            #
            #
            #
            #Remove AZure AD Group
            if ($ParameterObject.action -eq "Remove-AzureAD-Group") {
                try {
                    $group = Get-AzureADGroup -ObjectId $ParameterObject.group 
                    if (!$group) {
                        throw "Cannot find group. The group does not exist"
                    }
                    else {
                        Write-Verbose "Removing group"
                        Remove-AzureADGroup -ObjectId $ParameterObject.group 
                        Write-Verbose "Group removed"
                        SNComplete $jobQueueItem.sys_id
                    } 
                }
                catch { 
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                } 
            }
            #
            #
            #Import AzureAD group
            #
            #
            if ($ParameterObject.action -eq "Import-AzureAD-Groups") {
        
                try {
                    if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        Install-Module -Name "AzureAD"
                        throw "Could not find AzureAD module. Please install this module"
                    }
		$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                    $groups = Get-AzureADGroup -all $true 
      
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
		  
           
                    foreach ($group in $groups) {
			 
                        $groupInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $group.DisplayName
                            'ObjectGuid'      = $group.ObjectId
                            'Description'     = $group.Description
                            'MailEnabled'     = $group.MailEnabled
                            'MailNickName'    = $group.MailNickName
                            'SecurityEnabled' = $group.SecurityEnabled
                        }
                        $json = $groupInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "Servicenow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        if ($response.result.sync_policy -gt 0) {
                            $groupMembers = Get-AzureADGroupMember -ObjectId $group.objectId
                            $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroupmember"
                            foreach ($member in $groupMembers) {
                                if ($null -ne $member.ObjectClass) {
                                    $memberInput = @{
                                        'Domain'      = $domainID 
                                        'GroupGUID'   = $group.ObjectGuid    
                                        'Name'        = $member.DisplayName
                                        'Description' = $member.Description
                                        'ObjectGuid'  = $member.ObjectId
                                    }
                                    $gmjson = $memberInput | ConvertTo-Json
                                    $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                                    Write-Verbose "ServiceNow groupmember input: $gmbody"
                                    $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
                                }
                            }
                        }
                    }
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                    SNComplete $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/ready"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }

            #
            #
            #
            if ($ParameterObject.action -eq "Import-Groups") {
                try {
                    $groups = Get-ADGroup -Filter * `
                        -Properties Description `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
           
                    foreach ($group in $groups) {
                        $groupInput = @{
                            'Domain'            = $domainID
                            'GroupScope'        = $group.GroupScope
                            'GroupCategory'     = $group.GroupCategory
                            'SamAccountName'    = $group.SamAccountName
                            'DistinguishedName' = $group.DistinguishedName
                            'ObjectClass'       = $group.ObjectClass
                            'ObjectGuid'        = $group.ObjectGuid
                            'Name'              = $group.Name
                            'Description'       = $group.Description
                        }
                        $json = $groupInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "Servicenow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        if ($response.result.sync_policy -gt 0) {
                            $groupMembers = Get-ADGroupMember -Server $domainControllerIP -Credential $ADcredentials -Identity $group.ObjectGuid
                            $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/groupmember"
                            foreach ($member in $groupMembers) {
                                if ($null -ne $member.ObjectClass) {
                                    $memberInput = @{
                                        'Domain'            = $domainID
                                        'GroupGUID'         = $group.ObjectGuid
                                        'SamAccountName'    = $member.SamAccountName
                                        'DistinguishedName' = $member.DistinguishedName
                                        'ObjectClass'       = $member.ObjectClass
                                        'ObjectGuid'        = $member.ObjectGuid
                                        'Name'              = $member.Name
                                    }
                                    $gmjson = $memberInput | ConvertTo-Json
                                    $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                                    Write-Verbose "ServiceNow groupmember input: $gmbody"
                                    $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
                                }
                            }
                        }
                    }
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }
      
            if ($ParameterObject.action -eq "Create-Group-Member") {
                try {
                    $group = Get-ADGroup -Identity $ParameterObject.group `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
          	
                    if (!$group) {
                        throw "The group was not found"
                    }
          
                    $user = Get-ADUser -Identity $ParameterObject.user `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
          	
                    if (!$user) {
                        throw "The user was not found"
                    }
          
                    if ($null -ne $ParameterObject.ttl) {
                        $groupMember = Add-ADGroupMember `
                            -Identity $group.ObjectGuid `
                            -MemberTimeToLive $ParameterObject.ttl `
                            -Members $user.ObjectGuid `
                            -Server $domainControllerIP `
                            -Credential $ADcredentials `
                            -PassThru:$true
                    }
                    else {
                        $groupMember = Add-ADGroupMember `
                            -Identity $group.ObjectGuid `
                            -Members $user.ObjectGuid `
                            -Server $domainControllerIP `
                            -Credential $ADcredentials `
                            -PassThru:$true
                    }
          
                    Write-Output $groupMember | ConvertTo-Json
          
                    $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/groupmember"
                    $memberInput = @{
                        'Domain'            = $domainID
                        'GroupGUID'         = $group.ObjectGuid
                        'SamAccountName'    = $user.SamAccountName
                        'DistinguishedName' = $user.DistinguishedName
                        'ObjectClass'       = $user.ObjectClass
                        'ObjectGuid'        = $user.ObjectGuid
                        'Name'              = $user.Name
                    }
                    $gmjson = $memberInput | ConvertTo-Json
                    $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow groupmember input: $gmbody"
                    $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/groupmember"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'sysid'      = $ParameterObject.membersysid
                        'Sync State' = "Failed"
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                }
            }
            #
            #
            #
            #Create Azure AD group member
            if ($ParameterObject.action -eq "Create-AzureADGroup-Member") {
                try {
                    $group = Get-AzureADGroup -ObjectId $ParameterObject.group 
                    if (!$group) {
                        throw "The group was not found"
                    }
          
                    $user = Get-AzureADUser -ObjectId $ParameterObject.usermember
          
                    if (!$user) {
                        throw "The user was not found"
                    }
          
          
                    $groupMember = Add-AzureADGroupMember `
                        -ObjectId $ParameterObject.group `
                        -RefObjectId $ParameterObject.usermember
        
                    $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroupmember"
                    $memberInput = @{
                        'Domain'      = $domainID
                        'GroupGUID'   = $group.ObjectId
                        'ObjectId'    = $user.ObjectId
                        'ObjectClass' = $user.ObjectType
                        'Name'        = $user.DisplayName
                    }
                    $gmjson = $memberInput | ConvertTo-Json
                    $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    #Write-Output "ServiceNow groupmember input: $gmbody"
                    $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroupmember"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'sysid'      = $ParameterObject.membersysid
                        'Sync State' = "Failed"
                    }
                    $json = $groupInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                }
            }
            #
            #
            #
      
            if ($ParameterObject.action -eq "Remove-Group-Member") {
                try {
                    $group = Get-ADGroup -Identity $ParameterObject.group `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
          	
                    if (!$group) {
                        throw "The group was not found"
                    }
           
                    $user = Get-ADUser -Identity $ParameterObject.user `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
          	
                    if (!$user) {
                        throw "The user was not found"
                    }
          
                    $groupMember = Remove-ADGroupMember `
                        -Identity $group.ObjectGuid `
                        -Members $user.ObjectGuid `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Confirm:$false `
                        -PassThru:$true
          
                    <#
           No call back - Record is already deleted in ServiceNow
           
          $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/groupmember"
          $memberInput = @{
            'Domain' = $domainID
            'GroupGUID' = $group.ObjectGuid
            'SamAccountName' = $user.SamAccountName
            'DistinguishedName' = $user.DistinguishedName
            'ObjectClass' = $user.ObjectClass
            'ObjectGuid' = $user.ObjectGuid
            'Name' = $user.Name
          }
          $gmjson = $memberInput | ConvertTo-Json
          $gmbody = [regex]::Replace($gmjson,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
          Write-Verbose "ServiceNow groupmember input: $gmbody"
          $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'DELETE' -Uri $ServiceNowGroupMemberURI -Body $gmbody
          $output = $response.RawContent
          Write-Verbose "ServiceNow response: $output"
          #>
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }
            #
            #
            # Remove Azure AD Group Member
            if ($ParameterObject.action -eq "Remove-AzureADGroup-Member") {
                try {
                    $group = Get-AzureADGroup -ObjectId $ParameterObject.group
		  
                    if (!$group) {
                        throw "The group was not found"
                    }
           
                    $user = Get-AzureADUser -ObjectId $ParameterObject.user
          
                    if (!$user) {
                        throw "The user was not found"
                    }
          
                    $groupMember = Remove-AzureADGroupMember -ObjectId $group.ObjectId -MemberId $user.ObjectId
          
          
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }
            #
            #
            #

        }
        catch {
            Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
            SNFail $jobQueueItem.sys_id
        }
    }
    else {
        Write-Verbose "Nothing in the command queue. Sleeping for 60 seconds"
        Start-Sleep -Seconds 60
    }
}
if($null -ne $AADcredentialsName) {
    try {
        Disconnect-ExchangeOnline -Confirm:$false
    }
    catch {
        $errorMessage = $error[0].exception.message
        throw "Could not disconnect from Exchange Online. Message: $errorMessage"
    }
    try {
        Disconnect-AzureAD -Confirm:$false
    }
    catch {
        $errorMessage = $error[0].exception.message
        throw "Could not disconnect from Exchange Online. Message: $errorMessage"
    }
}
