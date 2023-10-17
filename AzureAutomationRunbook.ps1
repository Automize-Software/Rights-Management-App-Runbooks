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
#$AADcredentialsName = $response.result.azureadcredentials.display_value
$ConnectApplicationID = $response.result.applicationid
$Thumbprintconnection = $response.result.thumbprint
$certname = $response.result.certificate.display_value
$secret = $response.result.clientsecret


#$TenantID = $domainName + ".onmicrosoft.com"
$TenantID = $response.result.tenant_azure_active_directory

 
$AllCultures = [System.Globalization.CultureInfo]::
GetCultures(
[System.Globalization.CultureTypes]:: 
SpecificCultures) # !AllCultures

# $AllCultures | ft -AutoSize
# $AllCultures.Count

##### build table of data
$objs = @();
$AllCultures | % {
$dn = $_.DisplayName.Split(“(|)”);
$RegionInfo = New-Object System.Globalization.RegionInfo $PsItem.name;
$objs += [pscustomobject]@{
Name = $RegionInfo.Name;
EnglishName = $RegionInfo.EnglishName;
TwoLetterISORegionName = $RegionInfo.TwoLetterISORegionName;
GeoId = $RegionInfo.GeoId;
ISOCurrencySymbol = $RegionInfo.ISOCurrencySymbol;
CurrencySymbol = $RegionInfo.CurrencySymbol;
IsMetric = $RegionInfo.IsMetric;
LCID = $PsItem.LCID;
Lang = $dn[0].Trim();
Country = $dn[1].Trim();
}
};

# check which country or countries support a particular language
$countries = $objs | select -Unique -prop TwoLetterISORegionName,EnglishName | sort TwoLetterISORegionName
 

 # $coun = $pscustomobject.FindIndex({param($item) $item.Name -eq 'Denmark'})    
 # Write-Output $coun 
                    
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

if (Get-Module -ListAvailable -Name "Microsoft.Graph") {
    Write-Verbose "Found Exchange Azure Active Directory module"
}
else {
    try {
        Write-Warning "Microsoft.Graph module was not found. Trying to install it."
        Install-Module "Microsoft.Graph" -Force
    }
    catch {
        throw "Did not find Microsoft.Graph module. Please make sure the AzureAD module is installed."
    }
} 
Import-Module "AzureAD"


# Setup connections

if($null -eq $ADcredentialsName) {
    Write-Warning "Active Directory Credentials not provided. No AD connection will be available"
} else {
	$ADcredentials = Get-AutomationPSCredential -Name $ADcredentialsName
}

if($null -eq $ConnectApplicationID -or $null -eq $Thumbprintconnection ) {
    Write-Warning "Azure Active Directory Credentials not provided. No Azure AD or Exchange Online connection will be available"
} else {
	#$AADcredentials = Get-AutomationPSCredential -Name $AADcredentialsName
    try {
       
        if ($null -ne $Thumbprintconnection -and $Thumbprintconnection -ne '' ){
        
       
       Select-MgProfile –Name “beta” 
       Connect-MgGraph -ClientID $ConnectApplicationID -TenantId $TenantID -CertificateThumbprint $Thumbprintconnection
       Get-MgContext
       $Organization = (Get-MgDomain | Where-Object { $_.isDefault }).Id
       
       Connect-ExchangeOnline -AppId $ConnectApplicationID -CertificateThumbprint $Thumbprintconnection -Organization $Organization
        }
        elseif($null -ne $secret -and $secret -ne '' ){
             $SecuredPassword = $secret


            $SecuredPasswordPassword = ConvertTo-SecureString -String $SecuredPassword -AsPlainText -Force

            $MsalToken = Get-MsalToken -TenantId $TenantId -ClientId $ConnectApplicationID -ClientSecret ($secret | ConvertTo-SecureString -AsPlainText -Force)
            Connect-MgGraph -AccessToken $MsalToken.AccessToken
            #Connect-ExchangeOnline -AccessToken $MsalToken.AccessToken
        }
   
      <#  Connect-AzureAD -TenantId $TenantID -Credential $AADcredentials
        Write-Output "Connect with service principal"
        # Create the self signed cert
$currentDate = Get-Date
$endDate = $currentDate.AddYears(4)
$notAfter = $endDate.AddYears(4)
$pwd = "vQ7qJxqgXAxEKdVAWHQF"
$thumb = (New-SelfSignedCertificate -CertStoreLocation cert:\CurrentUser\my -DnsName automize.cer.CertificateLoginRightsManagementApp -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter $notAfter).Thumbprint
Write-Output $thumb
$pwd = ConvertTo-SecureString -String $pwd -Force -AsPlainText
Export-PfxCertificate -cert "cert:\CurrentUser\my\$thumb" -FilePath c:\temp\examplecert.pfx -Password $pwd
# Load the certificate
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate("C:\temp\examplecert.pfx", $pwd)
$keyValue = [System.Convert]::ToBase64String($cert.GetRawCertData())
# Create the Azure Active Directory Application
$application = New-AzureADApplication -DisplayName "CertificateLoginRightsManagementApp" -IdentifierUris "https://CertificateLoginRightsManagementApp.automizedev.onmicrosoft.com"
New-AzureADApplicationKeyCredential -ObjectId $application.ObjectId -CustomKeyIdentifier "CertificateLogin" -StartDate $currentDate -EndDate $endDate -Type AsymmetricX509Cert -Usage Verify -Value $keyValue
# Create the Service Principal and connect it to the Application
$sp=New-AzureADServicePrincipal -AppId $application.AppId
# Give the Service Principal Reader access to the current tenant (Get-AzureADDirectoryRole)
Add-AzureADDirectoryRoleMember -ObjectId (Get-AzureADDirectoryRole | where-object {$_.DisplayName -eq "Directory Readers"}).Objectid -RefObjectId $sp.ObjectId 


# Get Tenant Detail
$tenant=Get-AzureADTenantDetail#>
# Now you can login to Azure PowerShell with your Service Principal and Certificate#>
#Connect-AzureAD -TenantId $TenantID -ApplicationId $ConnectApplicationID -CertificateThumbprint $thumb
#Connect-MgGraph -TenantId $TenantID -AppId $ConnectApplicationID -CertificateThumbprint $Thumbprintconnection -Scopes "User.ReadWrite.All","Group.ReadWrite.All","UserAuthenticationMethod.ReadWrite.All"  
    

#Connect

#Get-MgOrganization | Select-Object DisplayName, City, State, VerifiedDomains 

   
    } 
    catch {
         Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
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


if($null -ne $ConnectApplicationID -and $null -ne $Thumbprintconnection) {
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
                        $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname #+ " (" + $ParameterObject.username + ")"
                    }
                    elseif ($null -ne $ParameterObject.surname -and $ParameterObject.surname -ne '') {
                        $displayname = $ParameterObject.surname #+ " (" + $ParameterObject.username + ")"
                    }
                    elseif ($null -ne $ParameterObject.givenname -and $ParameterObject.givenname -ne '') {
                        $displayname = $ParameterObject.givenname #+ " (" + $ParameterObject.username + ")"
                    }
                    else {
                        $displayname = $ParameterObject.username
                    }


                    $manager = Get-ADUser -Filter 'ObjectGUID -eq "$ParameterObject.manager"'  
                    $samAccountName = $ParameterObject.username
                    $userPrincipalName = $samtAccountName + "@" + $domainName
                    $userPassword = ConvertTo-SecureString $ParameterObject.password -AsPlainText -Force
                    #if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.path)){
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
                        -Company $ParameterObject.company `
                        -EmailAddress $ParameterObject.emailAddress `
                        -OfficePhone $ParameterObject.officePhone `
                        -MobilePhone $ParameterObject.mobilePhone `
                        -Manager $manager `
                        -Department $ParameterObject.department `
                        -EmployeeID $ParameterObject.employeeid `
                        -EmployeeNumber $ParameterObject.employeenumber `
                        -Description $ParameterObject.description `
                        -AccountPassword $userPassword `
                        -Enabled:$true `
                        -ChangePasswordAtLogon:$false `
                        -PassThru:$true



                        
          <#}else{
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
                        -Enabled:$true `
                        -ChangePasswordAtLogon:$false `
                        -PassThru:$true
          }#>
                    $user = Get-ADUser -Identity $ParameterObject.username `
                        -Properties GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials


                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.country)){
                                    $coun = $countries | Where-Object {$_.EnglishName -eq $ParameterObject.country}
                                    $cou = $coun.TwoLetterISORegionName
                                    $user.country = $cou
                                   
                                    Set-ADUser -Instance $user

                                }
      
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
                    
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                    $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
                   # $response3 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI3 -Body $body

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
                       # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                       # $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/adidentitylink"
                       

        
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
                       # $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI2 -Body $body
                       #  $response3 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI3 -Body $body

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
                        Get-MgUser -UserId $userToGrant -ErrorAction Stop > $null
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
                        Set-Mailbox $mailBox -LitigationHoldEnabled $true -LitigationHoldDuration 2555
                        Write-Output "Folder permission set successfully for $userToGrant on $identity."
                    }
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    $errorMessage = $error[0].exception.message
                     Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                    throw "Could not set / verify folder permission. Message: $errorMessage"
                }
                
              } catch {
                SNFail $jobQueueItem.sys_id
                Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                
              }
                
            }


            #Set authentication method 
            if ($ParameterObject.action -eq "Set-Mobile-Authentication-Method") {
                try{
                    $userid = $ParameterObject.useridforauth
                    $mobilephone = $ParameterObject.mobile
                    $user = Get-MgUser -UserId $userid
                   if(-Not [string]::IsNullOrWhiteSpace($mobilephone)){
                                    
                                 New-MgUserAuthenticationPhoneMethod -UserId $user.Id -PhoneType Mobile -PhoneNumber $mobilephone
                                 }
                                  
                SNComplete $jobQueueItem.sys_id
                }catch{
                    $errorMessage = $error[0].exception.message
                     Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                     SNFail $jobQueueItem.sys_id
               
                
                }
            }


            #Create guest user account
            if ($ParameterObject.action -eq "Create-Guest-User"){
                try{
                    Import-Module Microsoft.Graph.Identity.SignIns

                    $params = @{
	                InvitedUserEmailAddress = $ParameterObject.email
	                InviteRedirectUrl = $ParameterObject.url
	                InvitedUserDisplayName = $ParameterObject.username
	                SendInvitationMessage = $true
	                CustomizedMessageBody = $ParameterObject.message
                        }

                    New-MgInvitation -BodyParameter $params
                    SNComplete $jobQueueItem.sys_id
                    
                }catch{

                    $errorMessage = $error[0].exception.message
                     Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                     SNFail $jobQueueItem.sys_id
                }
            }
           



            #
            #
            #Create azure ad user
            if ($ParameterObject.action -eq "Create-AzureAD-User") {
                
                try {

                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.mobile)){
                        $telephone = $ParameterObject.mobile
                    }
                   
         <# if ((-Not [string]::IsNullOrWhiteSpace($ParameterObject.usertypeset)) -and $ParameterObject.usertypeset -ne 'personal account'){
                       
                        if($ParameterObject.usertypeset -eq "admin"){
                            $usertypeset = "Admin"
                        }
                        elseif($ParameterObject.usertypeset -eq "svc"){
                            $usertypeset = "SVC"
                        }#>
                       if ((-Not [string]::IsNullOrWhiteSpace($ParameterObject.displayname))){
                           $displayname = $ParameterObject.displayname
                       }else{
                        if((-Not [string]::IsNullOrWhiteSpace($ParameterObject.givenname))-and (-Not [string]::IsNullOrWhiteSpace($ParameterObject.surname))) {
                       
                        $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname 
                    }
                        elseif (-Not [string]::IsNullOrWhiteSpace($ParameterObject.surname)) {
                        $displayname = $ParameterObject.surname 
                    }
                        elseif(-Not [string]::IsNullOrWhiteSpace($ParameterObject.givenname)) {
                        $displayname = $ParameterObject.givenname 
                    } 
                    elseif(-Not [string]::IsNullOrWhiteSpace($ParameterObject.name)){
                        $displayname = $ParameterObject.name 
                    
                    }
                     elseif (-Not [string]::IsNullOrWhiteSpace($ParameterObject.username)){#$null -ne $ParameterObject.name -or $ParameterObject.name  -ne ' '){
                         
                        $displayname = $ParameterObject.username
                        
                    }
                       }
                    
                    
                   <# if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        throw "Could not find AzureAD module. Please install this module"
                    }#>


                    <#if (-Not [string]::IsNullOrWhiteSpace($ParameterObject.username)){
                         if ($null -ne $ParameterObject.usertypeset -and $ParameterObject.usertypeset -ne '' -and $ParameterObject.usertypeset -ne ' ' -and $ParameterObject.usertypeset -ne 'personal account'){
                            $userName = $ParameterObject.username+"-"+$ParameterObject.usertypeset
                         }else{
                             $userName = $ParameterObject.username
                         }
                    }
                    else{
                        $string = $usernameoption2 -replace '\s',''
                        $userName = $string
                    }#>
                   
                    $userName = $ParameterObject.username
                    Write-Output "username $userName"
                    $AADdomainprinc = (Get-MgDomain | Where-Object { $_.isDefault }).Id
                    Write-Output "domain name $AADdomainprinc"
                    $princname = $userName -replace '\s', ''
                    $userprinname = $princname + "@" + $AADdomainprinc
		
                    Write-Output $userprinname
                    $user = Get-MgUser -Filter "userPrincipalName eq '$userprinname'"
		
                    if ($user) {
                        throw "Cannot create user. The user '$userName' already exists"
                    }
                    else {
                        $PasswordProfile = @{Password = $ParameterObject.password}
                       #$PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
                       #$PasswordProfile.Password = $ParameterObject.password
                       
                       if (-Not [string]::IsNullOrWhiteSpace($telephone)){
                       $user = New-MgUser -DisplayName $displayname `
                                -PasswordProfile $PasswordProfile `
                                -AccountEnabled `
                                -MailNickName $princname `
                                -UserPrincipalName $userprinname `
                                -City $ParameterObject.city `
                                -CompanyName $ParameterObject.company `
                                -Country $ParameterObject.country `
                                -Department $ParameterObject.department `
                                -JobTitle $ParameterObject.title `
                                -MobilePhone $telephone `
                                -PostalCode $ParameterObject.postalcode `
                                -StreetAddress $ParameterObject.streetaddress 
                       }else{
                            $user = New-MgUser -DisplayName $displayname `
                                -PasswordProfile $PasswordProfile `
                                -AccountEnabled `
                                -MailNickName $princname `
                                -UserPrincipalName $userprinname `
                                -City $ParameterObject.city `
                                -CompanyName $ParameterObject.company `
                                -Country $ParameterObject.country `
                                -Department $ParameterObject.department `
                                -JobTitle $ParameterObject.title `
                                -PostalCode $ParameterObject.postalcode `
                                -StreetAddress $ParameterObject.streetaddress 
                       }

                        if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.givenname)){
                             Update-MgUser -UserId $user.Id -GivenName $ParameterObject.givenname
                        }
                         if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.surname)){
                             Update-MgUser -UserId $user.Id -Surname $ParameterObject.surname
                        }
                               
                              if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.manager)){
                                    $manager = Get-MgUser -UserId $ParameterObject.manager
                                    $mgmanager = $manager.Id
                                    $NewManager = @{
                                        "@odata.id"="https://graph.microsoft.com/beta/users/$mgmanager"
                                    }

                                    Set-MgUserManagerByRef -UserId $user.Id -BodyParameter $NewManager
                                    
                                    }  
                              if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.employeehiredate)){
                                    $hiredate = [DateTime]$ParameterObject.employeehiredate
                                   
                                     Update-MgUser -UserId $user.Id -EmployeeHireDate $hiredate
                                   
                                }  
                                
                               if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.country)){
                                    $coun = $countries | Where-Object {$_.EnglishName -eq $ParameterObject.country}
                                    $cou = $coun.TwoLetterISORegionName
                                   
                                    Update-MgUser -UserId $user.Id -UsageLocation $cou

                                }
                                if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.preferredlang)){
                                   Update-MgUser -UserId $user.Id -PreferredLanguage $ParameterObject.preferredlang

                                }

                                
                   if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.mfa)){
                                    
                                 New-MgUserAuthenticationPhoneMethod -UserId $user.Id -PhoneType Mobile -PhoneNumber $ParameterObject.mfa
                                 }
                                <# if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.mobile)){
                                    
                                 New-MgUserAuthenticationPhoneMethod -UserId $user.Id -PhoneType Mobile -PhoneNumber $ParameterObject.mobile
                                 }#>
                            
                        $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser"
                       # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                       # $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identitylink"

                        Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                        $userInput = @{
                            'ObjectGuid'                 = $user.Id
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
                            'Mobile'                     = $user.MobilePhone
                            'PostalCode'                 = $user.PostalCode
                            'PreferredLanguage'          = $user.PreferredLanguage
                            'StreetAddress'              = $user.StreetAddress
                            'Surname'                    = $user.Surname
                            'UsageLocation'              = $user.UsageLocation
                            'UserPrincipalName'          = $user.UserPrincipalName
                            'UserType'                   = $user.UserType
                            'Name'                       = $user.DisplayName
                            'sysid'                      = $ParameterObject.usersysid
                        }
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                      #  $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
                      #   $response3 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI3 -Body $body

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
                      #  $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                      #  $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identitylink"

        
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
                       # $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI2 -Body $body
                       #  $response3 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI3 -Body $body

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
                        -Properties GivenName, Surname, Description, DisplayName, title, office, postalcode, city, country, company, emailaddress, officephone, mobilephone, department, employeeid, employeenumber, manager `
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
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.manager)){
                                    $manager = Get-ADUser -Identity $ParameterObject.manager
                                    $user.manager = $manager
                                    
          }
          if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.country)){
                                    $coun = $countries | Where-Object {$_.EnglishName -eq $ParameterObject.country}
                                    $cou = $coun.TwoLetterISORegionName
                                    $user.country = $cou
                                   

                                }
      
                    Set-ADUser -Instance $user `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
          
                    $user = Get-ADUser -Identity $ParameterObject.user `
                        -Properties GivenName, Surname, UserPrincipalName, DisplayName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
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
                        'Name'                  = $user.DisplayName
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
                    <#if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        throw "Could not find AzureAD module. Please install this module"
                    }#>
                    $DisplayName = $ParameterObject.displayname
                    $user = Get-MgUser -UserId $ParameterObject.user 
                    $ParameterObject.PSObject.Properties | ForEach-Object {
                        $parmName = $_.Name
                        $parmValue = $_.Value
                        if ($parmName -ne "usersysid" -and $parmName -ne "action" -and $parmName -ne "user" -and $parmName -ne "manager") {   
                            if ($parmValue -eq "false") {
                                $user.$parmName = $false
                            }
                            elseif ($parmValue -eq "true") {
                                $user.$parmName = $true
                            }
                            
                        }
                       
                    }
                    $cou = " "
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.country)){
                                    $coun = $countries | Where-Object {$_.EnglishName -eq $ParameterObject.country}
                                    $cou = $coun.TwoLetterISORegionName

                                }
                    Update-MgUser -UserId $ParameterObject.user -DisplayName $ParameterObject.displayname -GivenName $ParameterObject.givenname -Surname $ParameterObject.surname -Department $ParameterObject.department -JobTitle $ParameterObject.jobtitle `
                        -City $ParameterObject.city -PostalCode $ParameterObject.postalcode -Country $cou -CompanyName $ParameterObject.companyname -MobilePhone $ParameterObject.mobilephone -StreetAddress $ParameterObject.streetaddress
          if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.manager)){
                                    $manager = Get-MgUser -UserId $ParameterObject.manager
                                    $mgmanager = $manager.Id
                                    $NewManager = @{
                                        "@odata.id"="https://graph.microsoft.com/beta/users/$mgmanager"
                                    }
                                     Set-MgUserManagerByRef -UserId $ParameterObject.user -BodyParameter $NewManager
          }
           if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.mfa)){
               $params = @{
	                phoneNumber = $ParameterObject.mfa
	                phoneType = "mobile"
                }

               Update-MgUserAuthenticationPhoneMethod -UserId $userId -PhoneAuthenticationMethodId "3179e48a-750b-4051-897c-87b9720928f7" -BodyParameter $params

           }
                    $user = Get-MgUser -UserId $ParameterObject.user #| select $properties 
           
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $userInput = @{
                        'GivenName'             = $user.firstname
                        'Surname'               = $user.lastname
                        'UserPrincipalName'     = $user.UserPrincipalName
                        'enabled'               = $user.AccountEnabled
                        'Name'                  = $user.DisplayName
                        'ObjectGuid'            = $user.Id
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
                  
                    $user = Get-MgUser -UserId $identity
                    if (!$user) {
                        throw "Cannot find user. The user does not exist"
                    }
                    else {
                        Write-Verbose "Removing user"
                        Remove-MgUser -UserId $identity
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
                    $userId = $ParameterObject.user
					#################added###########################
                   # $method = Get-MgUserAuthenticationPasswordMethod -UserId $identity
                    if ($ParameterObject.mustChange -eq $true) {
                    $params = @{
	                        passwordProfile = @{
		                    forceChangePasswordNextSignIn = $true
		                    password = $ParameterObject.password
	                        }
}                   

                    Update-MgUser -UserId $userId -BodyParameter $params
                
                        Write-Output "User must change password at next login"
                    }
                    if ($ParameterObject.mustChange -eq $false) {
                        $params = @{
	                        passwordProfile = @{
		                    forceChangePasswordNextSignIn = $false
		                    password = $ParameterObject.password
	                    }
}

Update-MgUser -UserId $userId -BodyParameter $params
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
                    $user = Get-MgUser -UserId $ParameterObject.user 
                    Update-MgUser -UsertId $ParameterObject.user -AccountEnabled 
         
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
                    $params = @{  
                        AccountEnabled = "false"  
                         }  

                    Update-MgUser -UserId $ParameterObject.user -BodyParameter $params  
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

            if ($ParameterObject.action -eq "Initial-Import-Users") {
                try {
                    $users = Get-ADUser -Filter * `
                        -Properties GivenName, SamAccountName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, DIsplayName, ObjectClass, ObjectGuid, AccountExpirationDate, accountExpires, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                  #  $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/adidentitylink"
           
                    foreach ($user in $users) {
                         $userInput = @{
                            'Domain'                = $domainID
                            'GivenName'             = $user.GivenName
                            'Surname'               = $user.Surname
                            'UserPrincipalName'     = $user.UserPrincipalName
                            'username'              = $user.SamAccountName
                            'Enabled'               = $user.Enabled
                            'SamAccountName'        = $user.SamAccountName
                            'DistinguishedName'     = $user.DistinguishedName
                            'Name'                  = $user.DisplayName
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
                            'Path'                  = $user.DistinguishedName
                        }
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                      #  $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
                      #  $response3 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI3 -Body $body
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity/cleanup"
                   # $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI2
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }


            if ($ParameterObject.action -eq "Import-Users") {
                try {
                   
                    $users = Get-ADUser -Filter * -Properties whenCreated, description | Where-Object {$_.whenCreated -ge ((Get-Date).AddDays(-1)).Date -or $_.LastDirSyncTime -gt (Get-Date).AddDays(-1)} |select GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, DisplayName, ObjectClass, ObjectGuid, AccountExpirationDate, accountExpires, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title 
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                  #  $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/adidentitylink"
           
                    foreach ($user in $users) {
                        $userInput = @{
                            'Domain'                = $domainID
                            'GivenName'             = $user.GivenName
                            'Surname'               = $user.Surname
                            'UserPrincipalName'     = $user.UserPrincipalName
                            'Enabled'               = $user.Enabled
                            'username'              = $user.SamAccountName
                            'SamAccountName'        = $user.SamAccountName
                            'DistinguishedName'     = $user.DistinguishedName
                            'Name'                  = $user.DisplayName
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
                            'Path'                  = $user.DistinguishedName
                        }
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                      #  $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
                      #  $response3 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI3 -Body $body
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity/cleanup"
                   # $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI2
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }
            #
            #Import azure AD Users
            if ($ParameterObject.action -eq "Initial-Import-AzureAD-Users") {
                try {
                    <#if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        Install-Module -Name "AzureAD"
                        throw "Could not find AzureAD module. Please install this module"
                    }#>
	$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                    $properties = @(
                        'Id',
                        'Name',
                        'DisplayName',
                        'givenname',
                        'surname',
                        'userprincipalname',
                        'Mail',
                        'MailNickname',
                        'JobTitle',
                        'Department',
                        'Mobile',
                        'StreetAddress',
                        'City',
                        'PostalCode',
                        'state',
                        'Country',
                        'EmployeeId',
                        'UserType',
                        'AccountEnabled'
                    )
                    $users = Get-MgUser -All | select $properties 
                   
                    $ServiceNowURI = "https://$instance.service-now.com//api/x_autps_active_dir/domain/$domainID/aduser"
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                   # $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identitylink"
                    
                   
                    foreach ($user in $users) {
                      
                        $UserExtProperties = Get-MgUserExtension -UserId $user.Id
                        Import-Module Microsoft.Graph.DeviceManagement.Enrolment
                        $objectid = $user.Id
                       
                        $responserole = Get-MgRoleManagementDirectoryRoleAssignment -CountVariable $true -Filter "principalId eq '$objectid'" 
                        $roleadmin = "User"
                       
                         if($responserole.roleDefinitionId -eq '62e90394-69f5-4237-9190-012177145e10'){
                             $roleadmin = "Admin"
                         }
                         
                         $mfasms =  Get-MgUserAuthenticationPhoneMethod -UserId $user.UserPrincipalName | Select-Object @{ N='UserPrincipalName'; E={ $user.UserPrincipalName }}, ID, PhoneNumber, PhoneType
                        $userprincname = $user.UserPrincipalName
                        #$employeeId = $UserExtProperties["employeeId"]
                        $userInput = @{
                            'ObjectGuid'        = $user.Id
                            'Domain'            = $domainID
                            'GivenName'         = $user.givenname
                            'Surname'           = $user.surname
                            'UserPrincipalName' = $user.UserPrincipalName
                            'Username'          = $userprincname.Substring(0, $userprincname.IndexOf('@'))
                            'Enabled'           = $user.AccountEnabled
                            'Name'              = $user.DisplayName
                            'City'              = $user.City
                            'Company'           = $user.CompanyName
                            'Country'           = $user.Country
                            'Email'				= $user.Mail
                            'Department'        = $user.Department
                            'Description'       = $user.Description
                            'MailNickName'      = $user.MailNickname
                            'Mobile'            = $user.Mobile
                            'PostalCode'        = $user.PostalCode
                            'Title'             = $user.JobTitle
                            'UserType'          =$user.UserType
                            'EmployeeID'        = $user.EmployeeId
                            'role'              = $roleadmin
                            'mfasms'            = $mfasms.PhoneNumber
                        }

                        
                         
                        $json = $userInput | ConvertTo-Json
                       
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                      #  $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
                      #  $response3 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI3 -Body $body
            
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity/cleanup"
                   # $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI2
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

             if ($ParameterObject.action -eq "Import-AzureAD-Users") {
                try {
                    <#if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        Install-Module -Name "AzureAD"
                        throw "Could not find AzureAD module. Please install this module"
                    }#>
	$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                    $properties = @(
                        'Id',
                        'Name',
                        'DisplayName',
                        'givenname',
                        'surname',
                        'userprincipalname',
                        'Mail',
                        'MailNickname',
                        'JobTitle',
                        'Department',
                        'Mobile',
                        'StreetAddress',
                        'City',
                        'PostalCode',
                        'state',
                        'Country',
                        'EmployeeId',
                        'UserType',
                        'AccountEnabled'
                    )

                    $dte = Get-Date

                    $papapa = $dte.AddDays(-1)
                    $users = Get-MgUser -All | Where-Object {$_.CreatedDateTime -ge $papapa -or $_.whenChanged -ge ((Get-Date).AddDays(-1)).Date} | select $properties 
                   
                   Write-Output "$papapa"
                    $ServiceNowURI = "https://$instance.service-now.com//api/x_autps_active_dir/domain/$domainID/aduser"
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                   # $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identitylink"
                    
                   
                    foreach ($user in $users) {
                        Write-Output $user
                        $UserExtProperties = Get-MgUserExtension -UserId $user.Id
                        Import-Module Microsoft.Graph.DeviceManagement.Enrolment
                        $objectid = $user.Id
                       
                        $responserole = Get-MgRoleManagementDirectoryRoleAssignment -CountVariable $true -Filter "principalId eq '$objectid'" 
                        $roleadmin = "User"
                       
                         if($responserole.roleDefinitionId -eq '62e90394-69f5-4237-9190-012177145e10'){
                             $roleadmin = "Admin"
                         }
                         
                         $mfasms =  Get-MgUserAuthenticationPhoneMethod -UserId $user.UserPrincipalName | Select-Object @{ N='UserPrincipalName'; E={ $user.UserPrincipalName }}, ID, PhoneNumber, PhoneType
                        $userprincname = $user.UserPrincipalName
                        #$employeeId = $UserExtProperties["employeeId"]
                        $userInput = @{
                            'ObjectGuid'        = $user.Id
                            'Domain'            = $domainID
                            'GivenName'         = $user.givenname
                            'Surname'           = $user.surname
                            'UserPrincipalName' = $user.UserPrincipalName
                            'Username'          = $userprincname.Substring(0, $userprincname.IndexOf('@'))
                            'Enabled'           = $user.AccountEnabled
                            'Name'              = $user.DisplayName
                            'City'              = $user.City
                            'Company'           = $user.CompanyName
                            'Country'           = $user.Country
                            'Email'				= $user.Mail
                            'Department'        = $user.Department
                            'Description'       = $user.Description
                            'MailNickName'      = $user.MailNickname
                            'Mobile'            = $user.Mobile
                            'PostalCode'        = $user.PostalCode
                            'Title'             = $user.JobTitle
                            'UserType'          =$user.UserType
                            'EmployeeID'        = $user.EmployeeId
                            'role'              = $roleadmin
                            'mfasms'            = $mfasms.PhoneNumber
                        }

                        
                         
                        $json = $userInput | ConvertTo-Json
                       
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                      #  $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
                      #  $response3 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI3 -Body $body
            
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity/cleanup"
                   # $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI2
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
                       if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.mailnickname)){
                           $mailnickname = $ParameterObject.mailnickname
                       }else{
                           $mailnickname = (New-Guid).Guid.Substring(0,10)
                       }
                   if ( $ParameterObject.isassignabletorole -eq 'true'){
                       $createGroup = New-MgGroup -DisplayName $ParameterObject.name  -MailNickName $mailnickname -Description $ParameterObject.description -MailEnabled:$false -SecurityEnabled -IsAssignableToRole
                   }else{
                       $createGroup = New-MgGroup -DisplayName $ParameterObject.name  -MailNickName $mailnickname -Description $ParameterObject.description -MailEnabled:$false -SecurityEnabled
                   }
                    
                    $group = Get-MgGroup -GroupId $createGroup.Id 
                   
                     
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'Description'     = $group.Description
                        'IsAssignableToRole' = $group.IsAssignableToRole
                        'ObjectGuid'      = $group.Id
                        'DisplayName'     = $group.DisplayName
                        'MailEnabled'     = $group.MailEnabled
                        'MailNickName'    = $group.MailNickName
                        'SecurityEnabled' = $group.SecurityEnabled
                        'Mail'            = $group.Mail
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


                    Write-Output "Group scope category "
                    Write-Output $group.GroupScope 
                    Write-Output $group.GroupCategory
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
                    $group = Get-MgGroup -GroupId $ParameterObject.group 
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
      
                    Update-MgGroup -GroupId $ParameterObject.group -Description $ParameterObject.description -DisplayName $ParameterObject.displayname -MailNickName $ParameterObject.mailnickname 
                    $group = Get-MgGroup -GroupId $ParameterObject.group 
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'ObjectGuid'      = $group.Id
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
                        $groupMembers = Get-MgGroupMember -GroupId $group.Id
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
                    $group = Get-MgGroup -GroupId $ParameterObject.group 
                    if (!$group) {
                        throw "Cannot find group. The group does not exist"
                    }
                    else {
                        Write-Verbose "Removing group"
                        Remove-MgGroup -GroupId $ParameterObject.group 
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
            if ($ParameterObject.action -eq "Initial-Import-AzureAD-Groups") {
        
                try {
                    <#if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        Install-Module -Name "AzureAD"
                        throw "Could not find AzureAD module. Please install this module"
                    }#>
		$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                    $groups = Get-MgGroup -All  
      
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
		  
           
                    foreach ($group in $groups) {
			 
                        $groupInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $group.DisplayName
                            'ObjectGuid'      = $group.Id
                            'Description'     = $group.Description
                            'MailEnabled'     = $group.MailEnabled
                            'MailNickName'    = $group.mailNickname
                            'SecurityEnabled' = $group.SecurityEnabled
                            'IsAssignableToRole' =$group.IsAssignableToRole
                        }
                        $json = $groupInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "Servicenow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        if ($response.result.sync_policy -gt 0) {
                            $groupMembers = Get-MgGroupMember -GroupId $group.Id
                            $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroupmember"
                            foreach ($member in $groupMembers) {
                                if ($null -ne $member.ObjectClass) {
                                    $memberInput = @{
                                        'Domain'      = $domainID 
                                        'GroupGUID'   = $group.Id    
                                        'Name'        = $member.DisplayName
                                        'Description' = $member.Description
                                        'ObjectGuid'  = $member.Id
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
             if ($ParameterObject.action -eq "Import-AzureAD-Groups") {
        
                try {
                    <#if (Get-Module -ListAvailable -Name "AzureAD") {
                        Write-Verbose "Found AzureAD module"
                    }
                    else {
                        Install-Module -Name "AzureAD"
                        throw "Could not find AzureAD module. Please install this module"
                    }#>
		$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                    $groups = Get-MgGroup -All | Where-Object {$_.CreatedDateTime -ge ((Get-Date).AddDays(-1)).Date -or $_.whenChanged -ge ((Get-Date).AddDays(-1)).Date} 
      
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
		  
           
                    foreach ($group in $groups) {
			 
                        $groupInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $group.DisplayName
                            'ObjectGuid'      = $group.Id
                            'Description'     = $group.Description
                            'MailEnabled'     = $group.MailEnabled
                            'MailNickName'    = $group.mailNickname
                            'SecurityEnabled' = $group.SecurityEnabled
                            'IsAssignableToRole' =$group.IsAssignableToRole
                        }
                        $json = $groupInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "Servicenow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        if ($response.result.sync_policy -gt 0) {
                            $groupMembers = Get-MgGroupMember -GroupId $group.Id
                            $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroupmember"
                            foreach ($member in $groupMembers) {
                                if ($null -ne $member.ObjectClass) {
                                    $memberInput = @{
                                        'Domain'      = $domainID 
                                        'GroupGUID'   = $group.Id    
                                        'Name'        = $member.DisplayName
                                        'Description' = $member.Description
                                        'ObjectGuid'  = $member.Id
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


            if ($ParameterObject.action -eq "Initial-Import-Groups") {
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
      

       if ($ParameterObject.action -eq "Import-Groups") {
                try {
                    $groups = Get-ADGroup -Filter * `
                        -Properties whenCreated, description | Where-Object {$_.whenCreated -ge ((Get-Date).AddDays(-1)).Date -or $_.whenChanged -ge ((Get-Date).AddDays(-1)).Date} 
                        
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
      
      #import organizational unit
      if ($ParameterObject.action -eq "Import-Organizational-Units") {
        
                try {
                    
		$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
                    
                    $OUS = Get-ADOrganizationalUnit -Filter * #'Name -like "*"'
                    #$OUS = Get-ADObject -Filter { ObjectClass -eq 'organizationalunit' }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/ou"
		  
           
                    foreach ($OU in $OUS) {
                       
                        $OUInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $OU.Name
                            'Description'     = $OU.Description
                            'DistinguishedName'= $OU.DistinguishedName
                            'Id'              = $OU.ObjectGuid
                           
                        }
                        $json = $OUInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "Servicenow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        
                            #$OUMembers =  Get-ADUser -Filter * -SearchBase "$OU.DistinguishedName" 
                            
                            $OUMembers = Get-AdUser -Filter * -SearchBase $OU.DistinguishedName -SearchScope OneLevel -Properties * 
                           
                            $ServiceNowOUMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/oumember"
                            foreach ($member in $OUMembers) {
                                  
                                    $memberInput = @{
                                        'Domain'      = $domainID 
                                        'OrganizationalUnitId'      = $OU.ObjectGuid   
                                        'ObjectGuid'  = $member.ObjectGuid
                                    }
                                    $gmjson = $memberInput | ConvertTo-Json
                                    $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                                    Write-Verbose "ServiceNow OUmember input: $gmbody"
                                    $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowOUMemberURI -Body $gmbody
                                
                            }#>
                        
                    }
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
             if ($ParameterObject.action -eq "Update-Organizational-Unit"){
                try{
                    Set-ADOrganizationalUnit -Server $domainControllerIP `
                        -Credential $ADcredentials  `
                        -Identity $ParameterObject.identity `
                        -DisplayName $ParameterObject.name `
                        -City $ParameterObject.city `
                        -Country $ParameterObject.country `
                        -Description $ParameterObject.description 
                    

                    SNComplete $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/ou"
                    $OU = Get-ADOrganizationalUnit -Identity $ParameterObject.identity
                     $OUInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $OU.Name
                            'Description'     = $OU.Description
                            'DistinguishedName'= $OU.DistinguishedName
                            'Id'              = $OU.ObjectGuid
                            'sysid'           = $ParameterObject.sysid
                           
                        }
                    $json = $OUInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "Servicenow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        
                    
                }catch{

                    $errorMessage = $error[0].exception.message
                     Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                     SNFail $jobQueueItem.sys_id
                }
            }##
            #
            #
            if ($ParameterObject.action -eq "Create-Organizational-Unit"){
                try{
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.parent)){
                    $newOU =New-ADOrganizationalUnit  -Server $domainControllerIP `
                        -Credential $ADcredentials  `
                        -City $ParameterObject.city `
                        -Path $ParameterObject.parent `
                    -Country $ParameterObject.country `
                    -Description $ParameterObject.description `
                    -Name $ParameterObject.name 
                    } 
                    else {
                         $newOU =New-ADOrganizationalUnit  -Server $domainControllerIP `
                        -Credential $ADcredentials  `
                        -City $ParameterObject.city `
                    -Country $ParameterObject.country `
                    -Description $ParameterObject.description `
                    -Name $ParameterObject.name  
                    }
                    
                    $varname = $ParameterObject.name

                    $OU = Get-ADOrganizationalUnit  -Filter "Name -eq '$($varname)'"
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/ou"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $OUInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $OU.Name
                            'Description'     = $OU.Description
                            'DistinguishedName'= $OU.DistinguishedName
                            'Id'              = $OU.ObjectGuid
                            'sysid'           = $ParameterObject.sysid
                            'Sync State'      = "Ready"
                           
                        }
                    $json = $OUInput | ConvertTo-Json
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
                    $groupsysid = $ParameterObject.sysid
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/ou"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $OUInput = @{
                        'sysid'      = $ParameterObject.sysid
                        'Sync State' = "Failed"
                    }
                    $json = $OUInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                } 
            
            }##
            #
            #
             if ($ParameterObject.action -eq "Remove-Organizational-Unit") {
                try {
                    $identity = $ParameterObject.organizationalunit
                  
                    $OU = Get-ADOrganizationalUnit -Identity $ParameterObject.distinguishedname
                   
                    if (!$OU) {
                        throw "Cannot find organizational unit. The ou does not exist"
                    }
                    else {
                        Write-Verbose "Removing Organizational Unit"
                        Set-ADOrganizationalUnit  -Server $domainControllerIP `
                        -Credential $ADcredentials  `
                        -Identity $identity `
                        -ProtectedFromAccidentalDeletion $false
                       Remove-ADOrganizationalUnit -Server $domainControllerIP `
                        -Credential $ADcredentials  `
                        -Identity $identity -Confirm:$False
                        Write-Verbose "Organizational Unit removed"
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

             if ($ParameterObject.action -eq "Add-Userto-Organizational-Unit") {
               
                try {
                     Write-Verbose $ServiceNowURI
                    $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
                    
                    $OUSselected = Get-ADOrganizationalUnit -Filter 'DistinguishedName -like "$ParameterObject.ou"'

		             $OUS = Get-ADOrganizationalUnit -Filter * #'Name -like "*"'
                    #$OUS = Get-ADObject -Filter { ObjectClass -eq 'organizationalunit' }
                    $exist = $false;
                    
                    foreach ($OU in $OUS) {
                       
                    if( Get-AdUser -Filter 'DistinguishedName -eq "$ParameterObject.user"' -SearchBase $OU.DistinguishedName ){
                         Write-Host "$user exists in OU: $OU.DistinguishedName"
                         $exist = $true;
                    }
                    }
                    if($exist -eq $false){
                    Move-ADObject -Identity $ParameterObject.user -TargetPath $ParameterObject.ou
                    }
                    
                     SNComplete $jobQueueItem.sys_id
             
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }
             
            ##
            #
            #
            if ($ParameterObject.action -eq "Add-Groupto-Organizational-Unit") {
        
                try {
                    
		           
                     Write-Verbose $ServiceNowURI
                    $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
                    
                    $OUS = Get-ADOrganizationalUnit -Filter 'DistinguishedName -like "$ParameterObject.ou"'
                    $User = Get-AdGroup -Filter 'DistinguishedName -eq "$ParameterObject.group"'
                    Move-ADObject -Identity $ParameterObject.user -TargetPath $ParameterObject.ou
                    
                    
                     SNComplete $jobQueueItem.sys_id
                  
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }
            ##
            #
            #

      if ($ParameterObject.action -eq "Import-AzureAD-Organizational-Units") {
        
                try {
                    
                    
		$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
                    
                    $OUS = Get-MgDirectoryAdministrativeUnit -Property MembershipType,DisplayName,Description,Id
                    
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aadou"
		  
           
                    foreach ($OU in $OUS) {
                    $OUselected = $OU
                    $Properties = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $OUselected.Id | Select-Object -ExpandProperty AdditionalProperties 
                    $MembershipRule = $Properties['membershipRule']
                    $MembershipType = $Properties['membershipType']
                    if([string]::IsNullOrWhiteSpace($MembershipType)){
                        $MembershipType = "Assigned"
                    }
                    $MembershipRuleProcessingState = $Properties['membershipRuleProcessingState']
                    if([string]::IsNullOrWhiteSpace($MembershipRuleProcessingState)){
                        $MembershipRuleProcessingState = "Off"
                    }

                        $OUInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $OU.DisplayName
                            'Description'     = $OU.Description
                            'MembershipType'  = $MembershipType
                            'MembershipRule'  = $MembershipRule
                            'Id'              = $OU.Id
                            'MembershipRuleProcessingState' = $MembershipRuleProcessingState
                            
                        }
                        $json = $OUInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "Servicenow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        
                        
                            $OUMembers = Get-MgDirectoryAdministrativeUnitMember -AdministrativeUnitId $OU.Id #| select $properties
                            $ServiceNowOUMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adoumember"
                            foreach ($member in $OUMembers) {
                                  
                                    $memberInput = @{
                                        'Domain'      = $domainID 
                                        'OrganizationalUnitId'      = $OU.Id   
                                        'ObjectGuid'  = $member.Id
                                    }
                                    $gmjson = $memberInput | ConvertTo-Json
                                    $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                                    Write-Verbose "ServiceNow OUmember input: $gmbody"
                                    $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowOUMemberURI -Body $gmbody
                                
                            }
                        
                    }
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


            #####
           
            if ($ParameterObject.action -eq "Create-AzureAD-Organizational-Unit"){
                try{
                    if ($ParameterObject.membershiptype -eq "Assigned" -or [string]::IsNullOrWhiteSpace($ParameterObject.membershiptype)){
                        $params = @{
	                    DisplayName = $ParameterObject.displayname
	                    Description = $ParameterObject.description
	                    MembershipType = "Assigned"
                    }
                    }else{
                    $params = @{
	                    DisplayName = $ParameterObject.displayname
	                    Description = $ParameterObject.description
	                    MembershipType = $ParameterObject.membershiptype
	                    MembershipRule = $ParameterObject.membershiprule
	                    MembershipRuleProcessingState = $ParameterObject.membershipruleprocessingstate
                    }
                    }
                    $AdminUnitName = $ParameterObject.displayname
                    New-MgDirectoryAdministrativeUnit -BodyParameter $params
                    $ID = (Get-MgDirectoryAdministrativeUnit -Filter "displayname eq '$AdminUnitName'").Id
                    SNComplete $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aadou"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $OUInput = @{
                            'Domain'          = $domainID     
                            'Id'              = $ID
                            'sysid'           = $ParameterObject.sysid
                            'Sync State'      = "Ready"
                    }
                    $json = $OUInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                    SNComplete $jobQueueItem.sys_id

                }catch{

                    $errorMessage = $error[0].exception.message
                    
                     SNFail $jobQueueItem.sys_id
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aadou"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $OUInput = @{
                        'sysid'      = $ParameterObject.sysid
                        'Sync State' = "Failed"
                    }
                    $json = $OUInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    Write-Verbose "ServiceNow input: $body"
                    $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
          
                } 
            }
           



            if ($ParameterObject.action -eq "Update-AzureAD-Organizational-Unit") {
                try {
                   
                    $DisplayName = $ParameterObject.displayname
                    $OU = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $ParameterObject.organizationalunit 
                    
                    $params = @{
                        DisplayName = $ParameterObject.displayname
                        MembershipType = $ParameterObject.membrshiptype
	                    MembershipRule = $ParameterObject.membershiprule
	                    Description = $ParameterObject.description
                    }

                    Update-MgDirectoryAdministrativeUnit -AdministrativeUnitId $ParameterObject.organizationalunit -BodyParameter $params
                 
                    $Properties = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $OU.Id | Select-Object -ExpandProperty AdditionalProperties 
                    $MembershipRule = $Properties['membershipRule']
                    $MembershipType = $Properties['membershipType']
           
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aadou"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $OUInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $OU.DisplayName
                            'Description'     = $OU.Description
                            'MembershipType'  = $MembershipType
                            'MembershipRule'  = $MembershipRule
                            'Id'              = $OU.Id
                            'sysid'           = $ParameterObject.sysid
                    }
                    $json = $OUInput | ConvertTo-Json
                    $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
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
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aadou"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $OUInput = @{
                        'sysid'      = $ParameterObject.sysid
                        'Sync State' = "Failed"
                    }
                    $json = $OUInput | ConvertTo-Json
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

            if ($ParameterObject.action -eq "Remove-AzureAD-Organizational-Unit") {
                try {
                    $identity = $ParameterObject.organizationalunit
                  
                    $OU = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $identity
                    if (!$OU) {
                        throw "Cannot find organizational unit. The ou does not exist"
                    }
                    else {
                        Write-Verbose "Removing Organizational Unit"
                       Remove-MgDirectoryAdministrativeUnit -AdministrativeUnitId $identity
                        Write-Verbose "Organizational Unit removed"
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

            if ($ParameterObject.action -eq "Create-AzureAD-OUGroup-Member") {
                try {
                    $group = Get-MgGroup -GroupId $ParameterObject.group 
                    if (!$group) {
                        throw "The group was not found"
                    }
                    $OU = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $ParameterObject.ou
                    $params = @{
	                "@odata.id" = "https://graph.microsoft.com/beta/groups/$($ParameterObject.group)"
                        }
                    New-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $OU.Id -BodyParameter $params
          
                    $groupm = Get-MgGroupMember -GroupId $ParameterObject.group 
                    Write-Output "Group Id $groupm.Id"
                       
                    $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adoumember"
                    $memberInput = @{
                                        'Domain'      = $domainID 
                                        'OrganizationalUnitId'      = $OU.Id   
                                        'ObjectGuid'  = $groupm.Id
                                    }
                    $gmjson = $memberInput | ConvertTo-Json
                    $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                    $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adoumember"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'sysid'      = $ParameterObject.ousysid
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
            if ($ParameterObject.action -eq "Remove-AzureAD-OUGroup-Member") {
                try {
                    $group = Get-MgGroup -GroupId $ParameterObject.group
		  
                    if (!$group) {
                        throw "The group was not found"
                    }
                    Remove-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $ParameterObject.ou -DirectoryObjectId $ParameterObject.group
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }


            ###

             if ($ParameterObject.action -eq "Create-AzureAD-OUUser-Member") {
                try {
                    $user = Get-MgUser -UserId $ParameterObject.user 
                    if (!$user) {
                        throw "The user was not found"
                    }
                    $OU = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $ParameterObject.ou
                    $params = @{
	                "@odata.id" = "https://graph.microsoft.com/beta/users/$($ParameterObject.user)"
                        }
                    New-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $OU.Id -BodyParameter $params
          
                       
                    $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adoumember"
                    $memberInput = @{
                                        'Domain'      = $domainID 
                                        'OrganizationalUnitId'      = $OU.Id   
                                        'ObjectGuid'  = $user.Id
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
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adoumember"
      
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
          
                    $groupInput = @{
                        'sysid'      = $ParameterObject.ousysid
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
            #
            #
            if ($ParameterObject.action -eq "Remove-AzureAD-OUUser-Member") {
                try {
                    $user = Get-MgUser -UserId $ParameterObject.user
		  
                    if (!$user) {
                        throw "The user was not found"
                    }
                    Remove-MgDirectoryAdministrativeUnitMemberByRef -AdministrativeUnitId $ParameterObject.ou -DirectoryObjectId $ParameterObject.user
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }


            ###
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
                    $group = Get-MgGroup -GroupId $ParameterObject.group 
                    if (!$group) {
                        throw "The group was not found"
                    }
          
                    $user = Get-MgUser -UserId $ParameterObject.usermember
          
                    if (!$user) {
                        throw "The user was not found"
                    }
          
          
                    $groupMember = New-MgGroupMember `
                        -GroupId $ParameterObject.group `
                        -DirectoryObjectId $ParameterObject.usermember
                    $groupm = Get-MgGroupMember -GroupId $ParameterObject.group 
                       
                    $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroupmember"
                    $memberInput = @{
                        'Domain'      = $domainID
                        'GroupGUID'   = $group.Id
                        'ObjectId'    = $user.Id
                        'ObjectClass' = "User"
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
                    $group = Get-MgGroup -GroupId $ParameterObject.group
		  
                    if (!$group) {
                        throw "The group was not found"
                    }
           
                    $user = Get-MgUser -UserId $ParameterObject.user
          
                    if (!$user) {
                        throw "The user was not found"
                    }
          
                    $groupMember = Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $user.Id
          
          
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

            if ($ParameterObject.action -eq "Import-AzureAD-Roles"){
                try{
               $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
                 Write-Verbose $ServiceNowURI
                $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
                    
                    $DRS = Get-MgDirectoryRoleTemplate
                    $DirectoryRoles = Get-MgDirectoryRole
                   
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adrole"
		  
           
                    foreach ($DR in $DRS) {
                       
                        $DRInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $DR.DisplayName
                            'Description'     = $DR.Description 
                            'Id'              = $DR.Id
                            
                            
                        }
                        $json = $DRInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "Servicenow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                        
                        # Get all role assignments
                        
                       
                        foreach ($DirectoryRole in $DirectoryRoles) {
                         
                            $ServiceNowOUMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adrolemember"
                            if ($DR.DisplayName -eq $DirectoryRole.DisplayName){
                                $OUMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $DirectoryRole.Id
                            foreach ($member in $OUMembers) {
                                    
                                    $memberInput = @{
                                        'Domain'      = $domainID 
                                        'Role'      = $DR.Id   
                                        'Objectguid'  = $member.Id
                                        'Id' =          $DirectoryRole.Id
                                    }
                                    $gmjson = $memberInput | ConvertTo-Json
                                    $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                                    Write-Verbose "ServiceNow OUmember input: $gmbody"
                                    $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowOUMemberURI -Body $gmbody
                                
                            }
                            }
                    }
                    }
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
            if ($ParameterObject.action -eq "Create-AzureADRole"){
                try{
                    $params = @{
	                    Description = $ParameterObject.description
	                    DisplayName = $ParameterObject.name
	                    RolePermissions = @(
		                                @{
			                                AllowedResourceActions = @(
				                                $ParameterObject.rolepermissions
			                                )
		                                }
	                            )
	                    IsEnabled = $true
                    }
                    Write-Output $params
                    New-MgRoleManagementDirectoryRoleDefinition -BodyParameter $params
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

            if ($ParameterObject.action -eq "Assign-AzureADRole"){
                try{
                    Import-Module Microsoft.Graph.DeviceManagement.Enrolment
                    if ($ParameterObject.assignmentobject -eq "group"){
                        $group = Get-MgGroup -GroupId $ParameterObject.user
		                $appObjectId = $group.Id
                        if (!$group) {
                            throw "The group was not found"
                        }
                    }else{
           
                        $user = Get-MgUser -UserId $ParameterObject.user
                         $appObjectId = $user.Id
                        if (!$user) {
                            throw "The user was not found"
                        }

                    }
                    # Get the role Id
                    $role = $ParameterObject.role
                    $roleId = (Get-MgRoleManagementDirectoryRoleDefinition -Filter "DisplayName eq '$role'").Id
                    Write-Output "role id $roleId"
                    # Get the object ID of your Enterprise Application
                    

                    New-MgRoleManagementDirectoryRoleAssignment -PrincipalId $appObjectId -RoleDefinitionId $roleId -DirectoryScopeId "/"
                     SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }

             if ($ParameterObject.action -eq "Remove-AzureADRole"){
                try{
                     if ($ParameterObject.assignmentobject -eq "group"){
                        $group = Get-MgGroup -GroupId $ParameterObject.user
		                $appObjectId = $group.Id
                        if (!$group) {
                            throw "The group was not found"
                        }
                    }else{
           
                        $user = Get-MgUser -UserId $ParameterObject.user
                         $appObjectId = $user.Id
                        if (!$user) {
                            throw "The user was not found"
                        }

                    }
                    # Get the role Id
                    $role = $ParameterObject.role
                    #$roleId = (Get-MgDirectoryRole -Filter "DisplayName eq '$role'").Id
                    $roleId = $ParameterObject.assignmentid
                    Write-Output "role id $roleId"
                    # Get the object ID of your Enterprise Application
                    

                    Remove-MgDirectoryRoleMemberByRef -DirectoryRoleId $roleId -DirectoryObjectId $appObjectId
                     SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }


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
if($null -ne $ConnectApplicationID -and $null -ne $Thumbprintconnection) {
    try {
        Disconnect-ExchangeOnline -Confirm:$false
    }
    catch {
        $errorMessage = $error[0].exception.message
        throw "Could not disconnect from Exchange Online. Message: $errorMessage"
    }
    try {
       # Disconnect-AzureAD -Confirm:$false
       Disconnect-MgGraph
    }
    catch {
        $errorMessage = $error[0].exception.message
        throw "Could not disconnect from Exchange Online. Message: $errorMessage"
    }
}
