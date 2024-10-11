param(
    [Parameter(Mandatory = $true)]
    [string] $domainID, 
  
    [Parameter(Mandatory = $true)]
    [string] $snowCredentialsName, 
  
    [Parameter(Mandatory = $true)]
    [string] $instance,

     [Parameter(Mandatory = $true)]
    [string] $secret
)

$PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText
Install-Module Microsoft.Graph -AllowPrerelease -AllowClobber -Force
Install-Module Microsoft.Graph.Beta -AllowClobber -Force
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.Graph.Identity.DirectoryManagement

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

#$TenantID = $domainName + ".onmicrosoft.com"
$TenantID = $response.result.tenant_azure_active_directory


 
$AllCultures = [System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::SpecificCultures)
#[System.Globalization.CultureInfo]::GetCultures([System.Globalization.CultureTypes]::AllCultures)# !AllCultures

# $AllCultures | ft -AutoSize
# $AllCultures.Count

##### build table of data
$objs = @();
#$AllCultures | % {
    foreach ($culture in $AllCultures){
#$dn = $_.DisplayName.Split(“)”);
#$dn = $_.DisplayName -split '[()]'
$RegionInfo = New-Object System.Globalization.RegionInfo $culture.Name

$objs += [pscustomobject]@{
DisplayName = $RegionInfo.DisplayName;
Name = $RegionInfo.Name;
LCID = $culture.LCID ;
EnglishName = $RegionInfo.EnglishName;
TwoLetterISORegionName = $RegionInfo.TwoLetterISORegionName;
LanguageName = $culture.DisplayName
Language = $culture.Name
<#GeoId = $RegionInfo.GeoId;
ISOCurrencySymbol = $RegionInfo.ISOCurrencySymbol;
CurrencySymbol = $RegionInfo.CurrencySymbol;
IsMetric = $RegionInfo.IsMetric;
LCID = $PsItem.LCID;#>
#Lang = $dn[0].Trim();
#Country = $dn[1].Trim();
}
}

# check which country or countries support a particular language
$countries = $objs | select -Unique -prop TwoLetterISORegionName,EnglishName,Name,LCID,LanguageName,Language | sort TwoLetterISORegionName
#Write-Output "COUNTRIES"
# $countries

 # $coun = $pscustomobject.FindIndex({param($item) $item.Name -eq 'Denmark'})    #>

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
    Write-Output "Found Exchange Online Management module"
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
        
       
      # Select-MgProfile –Name “beta” 
       Connect-MgGraph -ClientID $ConnectApplicationID -TenantId $TenantID -CertificateThumbprint $Thumbprintconnection
       Get-MgContext
       $Organization = (Get-MgDomain | Where-Object { $_.isDefault }).Id
       $Organization
       Connect-ExchangeOnline -AppId $ConnectApplicationID -CertificateThumbprint $Thumbprintconnection -Organization $Organization
        }
        elseif($null -ne $secret -and $secret -ne '' ){
             $SecuredPassword = $secret


            $SecuredPasswordPassword = ConvertTo-SecureString -String $SecuredPassword -AsPlainText -Force

            $MsalToken = Get-MsalToken -TenantId $TenantId -ClientId $ConnectApplicationID -ClientSecret ($secret | ConvertTo-SecureString -AsPlainText -Force)
            Connect-MgGraph -AccessToken ($MsalToken.AccessToken| ConvertTo-SecureString -AsPlainText -Force)  
            $AToken = $MsalToken.AccessToken
            $Organization = (Get-MgDomain | Where-Object { $_.isDefault }).Id
       $Organization
            <#$AccessToken = $AToken
$Authorization = "Bearer {0} " -f $AccessToken
$Password = ConvertTo-SecureString -AsPlainText $Authorization -Force
$UserCredential = New-Object System.Management.Automation.PSCredential("<upn-value>", $Password)
Connect-ExchangeOnline -Credential $UserCredential -ShowProgress $true#>

<#$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/x-www-form-urlencoded")
$body = "client_id=" + $ConnectApplicationID + "&scope=https%3A%2F%2Foutlook.office365.com%2F.default&grant_type=client_credentials&client_secret=" + $secret

$url = "https://login.microsoftonline.com/" + $TenantId + "/oauth2/v2.0/token"
$response = Invoke-RestMethod $url -Method 'POST' -Headers $headers -Body $body
            Connect-ExchangeOnline -Organization 'automizedev.onmicrosoft.com' -AccessToken $response.access_token#>
            $secureSecret = ConvertTo-SecureString -String $secret -AsPlainText -Force
            $Scopes = New-Object System.Collections.Generic.List[string]
$Scope = "https://outlook.office365.com/.default"
$Scopes.Add($Scope)
           $MsalToken = Get-MsalToken -TenantId $tenantId -ClientId $ConnectApplicationID -ClientSecret $secureSecret -Scopes $Scopes
Connect-ExchangeOnline -Organization $Organization -AccessToken $MsalToken.AccessToken

<#$tokenRequestUrl = "https://login.microsoftonline.com/$TenantId/oauth2/token"

$body = @{
    "grant_type" = "client_credentials"
    "client_id" = $ConnectApplicationID
    "client_secret" = $secret
     "scope" = "https://outlook.office.com/.default"
    #"scope"="Exchange.Manage"
    #"resource" = "https://outlook.office.com" # Update with the specific resource URL if needed
}

$response = Invoke-RestMethod -Uri $tokenRequestUrl -Method Post -Body $body

$accessToken = $response.access_token
$accessToken

Connect-ExchangeOnline -AppId $ConnectApplicationID -AccessToken $accessToken -Organization "automizedev.onmicrosoft.com"#>
        #Connect-ExchangeOnline -Organization 'automizedev.onmicrosoft.com' -AccessToken ($MsalToken.AccessToken| ConvertTo-SecureString -AsPlainText -Force)  
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
                    Write-Output $ParameterObject.entitlement
                    if ($null -ne $ParameterObject.givenname -and $null -ne $ParameterObject.surname -and $ParameterObject.givenname -ne '' -and $ParameterObject.surname -ne '') {
                        $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname #+ " (" + $ParameterObject.username + ")"
                        $exists = [bool] (Get-ADUser -Filter "DisplayName -eq '$displayname'" -ErrorAction Ignore)
                        if ($exists){
                            $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname + " (" + $ParameterObject.username + ")"
                        }
                    }
                    elseif ($null -ne $ParameterObject.surname -and $ParameterObject.surname -ne '') {
                        $displayname = $ParameterObject.surname #+ " (" + $ParameterObject.username + ")"
                         $exists = [bool] (Get-ADUser -Filter "DisplayName -eq '$displayname'" -ErrorAction Ignore)
                        if ($exists){
                             $displayname = $ParameterObject.surname + " (" + $ParameterObject.username + ")"
                        }
                    }
                    elseif ($null -ne $ParameterObject.givenname -and $ParameterObject.givenname -ne '') {
                        $displayname = $ParameterObject.givenname #+ " (" + $ParameterObject.username + ")"
                         $exists = [bool] (Get-ADUser -Filter "DisplayName -eq '$displayname'" -ErrorAction Ignore)
                        if ($exists){
                            $displayname = $ParameterObject.givenname + " (" + $ParameterObject.username + ")"
                        }
                        
                    }
                    else {
                        $displayname = $ParameterObject.username
                    }


                    $manager = Get-ADUser -Filter 'ObjectGUID -eq "$ParameterObject.manager"'  
                    $samAccountName = $ParameterObject.username
                    if($null -ne $ParameterObject.domainname -and $ParameterObject.domainname -ne ''){
                        $userPrincipalName = $samAccountName + "@" + $ParameterObject.domainname
                    }else{
                    $userPrincipalName = $samAccountName + "@" + $domainName
                    }

                    

                    $userPassword = ConvertTo-SecureString $ParameterObject.password -AsPlainText -Force
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.path)){
                    $createUser = New-ADUser -SamAccountName $samAccountName `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Name $displayname `
                        -Givenname $ParameterObject.givenname `
                        -Surname $ParameterObject.surname `
                        -UserPrincipalName $userPrincipalName `
                        -Title $ParameterObject.title `
                        -Office $ParameterObject.office `
                        -PostalCode $ParameterObject.postalcode `
                        -City $ParameterObject.city `
                        -Company $ParameterObject.company `
                        -EmailAddress $ParameterObject.emailAddress `
                        -OfficePhone $ParameterObject.officePhone `
                        -MobilePhone $ParameterObject.mobilePhone `
                        -Manager $manager `
                        -Path $ParameterObject.path `
                        -Department $ParameterObject.department `
                        -EmployeeID $ParameterObject.employeeid `
                        -EmployeeNumber $ParameterObject.employeenumber `
                        -Description $ParameterObject.description `
                        -AccountPassword $userPassword `
                        -StreetAddress $ParameterObject.streetaddress `
                        -Enabled:$true `
                        -ChangePasswordAtLogon:$false `
                        -PassThru:$true
                        }   
                    else{
              $createUser = New-ADUser -SamAccountName $samAccountName `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Name $displayname `
                        -Givenname $ParameterObject.givenname `
                        -Surname $ParameterObject.surname `
                        -Title $ParameterObject.title `
                        -Office $ParameterObject.office `
                        -PostalCode $ParameterObject.postalcode `
                        -City $ParameterObject.city `
                        -UserPrincipalName $userPrincipalName `
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
                        -StreetAddress $ParameterObject.streetaddress `
                        -Enabled:$true `
                        -ChangePasswordAtLogon:$false `
                        -PassThru:$true
          }

                    $user = Get-ADUser -Identity $ParameterObject.username `
                        -Properties GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials

                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.country)){
                                    $coun = $countries | Where-Object {$_.EnglishName -eq $ParameterObject.country} | Select-Object -First 1
                                    $cou = $coun.TwoLetterISORegionName
                                    $user.country = $cou
                                    Write-Output "c="
                                    Write-Output $coun.TwoLetterISORegionName 
                                    Write-Output "co="
                                    Write-Output $coun.EnglishName 
                                    Write-Output "countrycode="
                                    Write-Output $coun.LCID 
                                   Set-ADUser -Identity $ParameterObject.username -Replace @{c=$coun.TwoLetterISORegionName;co=$coun.EnglishName;countrycode=$coun.LCID} -Server $domainControllerIP -Credential $ADcredentials 
                                    #Set-ADUser -Instance $user -Server $domainControllerIP -Credential $ADcredentials 

                                }
                                if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.preferredlanguage)){
                                   
                                    Set-ADObject -Identity $user.DistinguishedName -replace @{preferredLanguage=$ParameterObject.preferredlanguage} -Server $domainControllerIP -Credential $ADcredentials
                     }
                              
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.expirationdate)){
                        $user.AccountExpirationDate = $ParameterObject.expirationdate
                         Set-ADUser -Instance $user
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute1)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute1
                            if(-not($userea.extensionattribute1)){
                                Set-ADUser $userea -Add @{"extensionattribute1"=$ParameterObject.extensionattribute1} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute1"=$ParameterObject.extensionattribute1} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute2)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute2
                            if(-not($userea.extensionattribute2)){
                                
                                Set-ADUser $userea -Add @{"extensionattribute2"=$ParameterObject.extensionattribute2} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute2"=$ParameterObject.extensionattribute2} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute3)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute3
                            if(-not($userea.extensionattribute3)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute3"=$ParameterObject.extensionattribute3} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute3"=$ParameterObject.extensionattribute3} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute4)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute4
                            if(-not($userea.extensionattribute4)){
                                
                                Set-ADUser $userea -Add @{"extensionattribute4"=$ParameterObject.extensionattribute4} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute4"=$ParameterObject.extensionattribute4} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute5)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute5
                            if(-not($userea.extensionattribute5)){
                                
                                Set-ADUser $userea -Add @{"extensionattribute5"=$ParameterObject.extensionattribute5} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute5"=$ParameterObject.extensionattribute5} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute6)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute6
                            if(-not($userea.extensionattribute6)){
                              
                                Set-ADUser $userea -Add @{"extensionattribute6"=$ParameterObject.extensionattribute6} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute6"=$ParameterObject.extensionattribute6} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute7)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute7
                            if(-not($userea.extensionattribute7)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute7"=$ParameterObject.extensionattribute7} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute7"=$ParameterObject.extensionattribute7} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute8)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute8
                            if(-not($userea.extensionattribute8)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute8"=$ParameterObject.extensionattribute8} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute8"=$ParameterObject.extensionattribute8} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute9)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute9
                            if(-not($userea.extensionattribute9)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute9"=$ParameterObject.extensionattribute9} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute9"=$ParameterObject.extensionattribute9} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute10)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute10
                            if(-not($userea.extensionattribute10)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute10"=$ParameterObject.extensionattribute10} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute10"=$ParameterObject.extensionattribute10} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute11)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute11
                            if(-not($userea.extensionattribute11)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute11"=$ParameterObject.extensionattribute11} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute11"=$ParameterObject.extensionattribute11} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute12)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute12
                            if(-not($userea.extensionattribute12)){
                                
                                Set-ADUser $userea -Add @{"extensionattribute12"=$ParameterObject.extensionattribute12} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute12"=$ParameterObject.extensionattribute12} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute13)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute13
                            if(-not($userea.extensionattribute13)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute13"=$ParameterObject.extensionattribute13} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute13"=$ParameterObject.extensionattribute13} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute14)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute14
                            if(-not($userea.extensionattribute14)){
                              
                                Set-ADUser $userea -Add @{"extensionattribute14"=$ParameterObject.extensionattribute14} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute14"=$ParameterObject.extensionattribute14} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute15)){
                        $userea = Get-ADUser -Identity $ParameterObject.username -Properties extensionattribute15
                            if(-not($userea.extensionattribute15)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute15"=$ParameterObject.extensionattribute15} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute15"=$ParameterObject.extensionattribute15} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                   
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
                  #  $response2 = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI2 -Body $body
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
            if ($ParameterObject.action -eq "Hide-Mailbox") {
              try{
                #$mailboxName = $ParameterObject.mailboxName
                #$mailBox = Get-EXOMailbox -Identity $mailboxName -ErrorAction Stop
                $userId = $ParameterObject.user
                $params = @{
	                showInAddressList = $true
                }

                Update-MgBetaUser -UserId $userId -BodyParameter $params
                SNComplete $jobQueueItem.sys_id
              }
              catch {
                SNFail $jobQueueItem.sys_id
                Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                
              }
              }

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
                    if([string]::IsNullOrWhiteSpace($ParameterObject.message) -and [string]::IsNullOrWhiteSpace($ParameterObject.username)){
                        New-MgInvitation -InvitedUserEmailAddress $ParameterObject.email -InviteRedirectUrl $ParameterObject.url
                    } elseif(-Not [string]::IsNullOrWhiteSpace($ParameterObject.message) -and [string]::IsNullOrWhiteSpace($ParameterObject.username)){
                       $params = @{
	                InvitedUserEmailAddress = $ParameterObject.email
                       SendInvitationMessage = $true
                       CustomizedMessageBody = $ParameterObject.message
                       InviteRedirectUrl = $ParameterObject.url
                        }
                        $guser = New-MgInvitation -BodyParameter $params 
                    }
                    elseif(-Not [string]::IsNullOrWhiteSpace($ParameterObject.username) -and [string]::IsNullOrWhiteSpace($ParameterObject.message)){
                       $params = @{
	                InvitedUserEmailAddress = $ParameterObject.email
                       InviteRedirectUrl = $ParameterObject.url
                        InvitedUserDisplayName = $ParameterObject.username
                        }
                        $guser = New-MgInvitation -BodyParameter $params 
                    }
                    else{
                    $params = @{
	                InvitedUserEmailAddress = $ParameterObject.email
                       SendInvitationMessage = $true
                       CustomizedMessageBody = $ParameterObject.message
                       InviteRedirectUrl = $ParameterObject.url
                     InvitedUserDisplayName = $ParameterObject.username
                        }
                        $guser = New-MgInvitation -BodyParameter $params
                    }

                    $email = $ParameterObject.email
                    Write-Output $email
                    try {
                    
	$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                   Import-Module Microsoft.Graph.Beta.Users
                    Start-Sleep -Seconds 60
                    $guser22 = Get-MgBetaUser -Filter "usertype eq 'Guest' and mail eq '$email'" 
                    
                   Write-Output $guser22.Id

                    if (-Not [string]::IsNullOrWhiteSpace($ParameterObject.companyname)){
                            Update-MgUser -UserId $guser22.Id -CompanyName $ParameterObject.companyname
                    }

                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.manager)){
                                    $manager = Get-MgUser -UserId $ParameterObject.manager
                                    $mgmanager = $manager.Id
                                    $NewManager = @{
                                        "@odata.id"="https://graph.microsoft.com/beta/users/$mgmanager"
                                    }

                                    Set-MgUserManagerByRef -UserId $guser22.Id -BodyParameter $NewManager
                                    
                                    }  

                   if (-Not [string]::IsNullOrWhiteSpace($ParameterObject.sponsor)){
         
                    
                   $DefaultSponsorId = (Get-MgUser -UserId $ParameterObject.sponsor).Id
                   $Body = '{"@odata.id": "https://graph.microsoft.com/beta/users/' + $DefaultSponsorId + '"}'
                   Write-Output $Body
                    $Uri = ("https://graph.microsoft.com/beta/users/{0}/sponsors/`$ref" -f $guser22.Id)
                    Write-Output $Uri
                    Invoke-MgGraphRequest -Uri $Uri -Method POST -Body $Body
                   }

                   

                    $ServiceNowURI = "https://$instance.service-now.com//api/x_autps_active_dir/domain/$domainID/aduser"
                  
                        $userInput = @{
                            'ObjectGuid'        = $guser22.Id
                            'Domain'            = $domainID
                            'GivenName'         = $guser22.givenname
                            'Surname'           = $guser22.surname
                            'UserPrincipalName' = $guser22.UserPrincipalName
                            'Enabled'           = $guser22.AccountEnabled
                            'Name'              = $guser22.DisplayName
                            'City'              = $guser22.City
                            'Company'           = $guser22.CompanyName
                            'Country'           = $guser22.Country
                            'Email'				= $guser22.Mail
                            'Department'        = $guser22.Department
                            'Description'       = $guser22.Description
                            'MailNickName'      = $guser22.MailNickname
                            'Mobile'            = $guser22.Mobile
                            'PostalCode'        = $guser22.PostalCode
                            'Title'             = $guser22.JobTitle
                            'UserType'          = "Guest"
                            'EmployeeID'        = $guser22.EmployeeId
                        }

                        
                         
                        $json = $userInput | ConvertTo-Json
                       
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                     
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                   SNComplete $jobQueueItem.sys_id
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/ready"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    throw
                }
                    
                    
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
                                    $coun = $countries | Where-Object {$_.EnglishName -eq $ParameterObject.country } | Select-Object -First 1
                                    $cou =$coun.TwoLetterISORegionName
                                    Write-Output "Usage location $cou "
                                    Update-MgUser -UserId $user.Id -UsageLocation $cou

                                }
                                if((-Not [string]::IsNullOrWhiteSpace($ParameterObject.preferredlang)) -and (-Not [string]::IsNullOrWhiteSpace($ParameterObject.country))){
                                    $ParameterObject.preferredlang
                                     $coun = $countries | Where-Object {($_.LanguageName -match $ParameterObject.preferredlang) -and ($_.EnglishName -eq $ParameterObject.country)}
                                     Write-Output "country $coun"
                                    $language =$coun.Language
                                    Write-Output "Language $language "

                                   Update-MgUser -UserId $user.Id -PreferredLanguage $language

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
            if ($ParameterObject.action -eq "Update-Username") {
                try {
                    
                        Get-ADUser -Identity $ParameterObject.user | Rename-ADObject -NewName $ParameterObject.fullname -Credential $ADcredentials
                        $userafter = Get-ADUser -Identity $ParameterObject.user
                         Set-ADUser -Instance $userafter `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
                        # Rename-ADObject -Identity $ParameterObject.user -NewName $ParameterObject.fullname -Credential $ADcredentials
                         $user = Get-ADUser -Identity $ParameterObject.user `
                        -Properties GivenName, Surname, UserPrincipalName, DisplayName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
                    Write-Output $ParameterObject.fullname                      
                    Write-Output $user.DisplayName
                    Write-Output $user.DistinguishedName
                    Write-Output $user.name
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
            #
             if ($ParameterObject.action -eq "Update-UserPath") {
                try {
                     
                     $userguid = $ParameterObject.user
 $user = Get-ADUser -Identity $userguid `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
   $path = $ParameterObject.path               
                   $user2= Get-ADUser $userguid | Move-ADObject -TargetPath $path -Server $domainControllerIP -Credential $ADcredentials -PassThru:$true
                      
                    Write-Output $user2
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
                catch{
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
                        if ($parmName -ne "usersysid" -and $parmName -ne "action" -and $parmName -ne "user" -and $parmName -ne "objectguid" -and $parmName -ne "fullname") {   
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
                                    Write-Output $ParameterObject.country 
                                    Write-Output $coun.TwoLetterISORegionName
                                    Write-Output $coun
                                    Write-output $coun.LCID
                                    $cou = $coun.TwoLetterISORegionName
                                   # $user.country = $cou
                                   
                                   Set-ADUser -Identity $ParameterObject.user -Replace @{c=$coun.TwoLetterISORegionName;co=$coun.Name;countrycode=$coun.LCID} -Server $domainControllerIP -Credential $ADcredentials 
                                    #Set-ADUser -Instance $user -Server $domainControllerIP -Credential $ADcredentials 

                                }

                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.fullname)){
                        Rename-ADObject -Identity $ParameterObject.objectguid -NewName $ParameterObject.fullname -Credential $ADcredentials
                    }

                      if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute1)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute1
                            if(-not($userea.extensionattribute1)){
                                Set-ADUser $userea -Add @{"extensionattribute1"=$ParameterObject.extensionattribute1} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute1"=$ParameterObject.extensionattribute1} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute2)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute2
                            if(-not($userea.extensionattribute2)){
                                
                                Set-ADUser $userea -Add @{"extensionattribute2"=$ParameterObject.extensionattribute2} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute2"=$ParameterObject.extensionattribute2} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute3)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute3
                            if(-not($userea.extensionattribute3)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute3"=$ParameterObject.extensionattribute3} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute3"=$ParameterObject.extensionattribute3} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute4)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute4
                            if(-not($userea.extensionattribute4)){
                                
                                Set-ADUser $userea -Add @{"extensionattribute4"=$ParameterObject.extensionattribute4} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute4"=$ParameterObject.extensionattribute4} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute5)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute5
                            if(-not($userea.extensionattribute5)){
                                
                                Set-ADUser $userea -Add @{"extensionattribute5"=$ParameterObject.extensionattribute5} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute5"=$ParameterObject.extensionattribute5} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute6)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute6
                            if(-not($userea.extensionattribute6)){
                              
                                Set-ADUser $userea -Add @{"extensionattribute6"=$ParameterObject.extensionattribute6} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute6"=$ParameterObject.extensionattribute6} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute7)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute7
                            if(-not($userea.extensionattribute7)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute7"=$ParameterObject.extensionattribute7} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute7"=$ParameterObject.extensionattribute7} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute8)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute8
                            if(-not($userea.extensionattribute8)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute8"=$ParameterObject.extensionattribute8} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute8"=$ParameterObject.extensionattribute8} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute9)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute9
                            if(-not($userea.extensionattribute9)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute9"=$ParameterObject.extensionattribute9} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute9"=$ParameterObject.extensionattribute9} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute10)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute10
                            if(-not($userea.extensionattribute10)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute10"=$ParameterObject.extensionattribute10} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute10"=$ParameterObject.extensionattribute10} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute11)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute11
                            if(-not($userea.extensionattribute11)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute11"=$ParameterObject.extensionattribute11} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute11"=$ParameterObject.extensionattribute11} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute12)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute12
                            if(-not($userea.extensionattribute12)){
                                
                                Set-ADUser $userea -Add @{"extensionattribute12"=$ParameterObject.extensionattribute12} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute12"=$ParameterObject.extensionattribute12} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute13)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute13
                            if(-not($userea.extensionattribute13)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute13"=$ParameterObject.extensionattribute13} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute13"=$ParameterObject.extensionattribute13} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute14)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute14
                            if(-not($userea.extensionattribute14)){
                              
                                Set-ADUser $userea -Add @{"extensionattribute14"=$ParameterObject.extensionattribute14} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute14"=$ParameterObject.extensionattribute14} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.extensionattribute15)){
                        $userea = Get-ADUser -Identity $ParameterObject.user -Properties extensionattribute15
                            if(-not($userea.extensionattribute15)){
                               
                                Set-ADUser $userea -Add @{"extensionattribute15"=$ParameterObject.extensionattribute15} -Server $domainControllerIP -Credential $ADcredentials
                            }else {
                                Set-ADUser $userea -Replace @{"extensionattribute15"=$ParameterObject.extensionattribute15} -Server $domainControllerIP -Credential $ADcredentials
                            }
                        
                    }

                    $user = Get-ADUser -Identity $ParameterObject.user `
                        -Properties GivenName, Surname, UserPrincipalName, DisplayName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title, `
                        extensionAttribute1, extensionAttribute2, extensionAttribute3, extensionAttribute4, extensionAttribute5, extensionAttribute6, extensionAttribute7, extensionAttribute8, extensionAttribute9, extensionAttribute10, extensionAttribute11, extensionAttribute12, extensionAttribute13, extensionAttribute14, extensionAttribute15 `
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
                        'extensionattribute1'   = $user.extensionAttribute1
                        'extensionattribute2'   = $user.extensionattribute2
                        'extensionattribute3'   = $user.extensionattribute3
                        'extensionattribute4'   = $user.extensionattribute4
                        'extensionattribute5'   = $user.extensionattribute5
                        'extensionattribute6'   = $user.extensionattribute6
                        'extensionattribute7'   = $user.extensionattribute7
                        'extensionattribute8'   = $user.extensionattribute8
                        'extensionattribute9'   = $user.extensionattribute9
                        'extensionattribute10'   = $user.extensionattribute10
                        'extensionattribute11'   = $user.extensionattribute11
                        'extensionattribute12'   = $user.extensionAttribute12
                        'extensionattribute13'   = $user.extensionAttribute13
                        'extensionattribute14'   = $user.extensionattribute14
                        'extensionattribute15'   = $user.extensionAttribute15
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
                                    $coun = $countries | Where-Object {$_.EnglishName -eq $ParameterObject.country} | Select-Object -First 1
                                    $cou = $coun.TwoLetterISORegionName
                                    Write-Output "country"
                                    Write-Output $cou

                                }
                                Write-Output $ParameterObject.jobtitle
                                Write-Output $ParameterObject.employeeid
                                Write-Output $ParameterObject.streetaddress
                    Update-MgUser -UserId $ParameterObject.user -DisplayName $ParameterObject.displayname -GivenName $ParameterObject.givenname -Surname $ParameterObject.surname -Department $ParameterObject.department -JobTitle $ParameterObject.jobtitle -OfficeLocation $ParameterObject.officelocation `
                        -City $ParameterObject.city -PostalCode $ParameterObject.postalcode -Country $cou -CompanyName $ParameterObject.companyname -MobilePhone $ParameterObject.mobilephone -StreetAddress $ParameterObject.streetaddress -EmployeeId $ParameterObject.employeeid
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

               Update-MgUserAuthenticationPhoneMethod -UserId $ParameterObject.user -PhoneAuthenticationMethodId "3179e48a-750b-4051-897c-87b9720928f7" -BodyParameter $params

           }
            if((-Not [string]::IsNullOrWhiteSpace($ParameterObject.preferredlanguage)) -and (-Not [string]::IsNullOrWhiteSpace($ParameterObject.country))){
                                    $ParameterObject.preferredlanguage
                                     $coun = $countries | Where-Object {($_.LanguageName -match $ParameterObject.preferredlanguage) -and ($_.EnglishName -eq $ParameterObject.country)} | Select-Object -First 1
                                     Write-Output "country $coun"
                                    $language =$coun.Language
                                    Write-Output "Language $language "

                                   Update-MgUser -UserId $ParameterObject.user -PreferredLanguage $language

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
                        -Properties GivenName, SamAccountName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, DIsplayName, ObjectClass, ObjectGuid, AccountExpirationDate, accountExpires, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title, `
                        extensionAttribute1, extensionAttribute2, extensionAttribute3, extensionAttribute4, extensionAttribute5, extensionAttribute6, extensionAttribute7, extensionAttribute8, extensionAttribute9, extensionAttribute10, extensionAttribute11, extensionAttribute12, extensionAttribute13, extensionAttribute14, extensionAttribute15 `
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
                            'Path'                  = $user.DistinguishedName
                            'extensionattribute1'   = $user.extensionAttribute1
                            'extensionattribute2'   = $user.extensionattribute2
                            'extensionattribute3'   = $user.extensionattribute3
                            'extensionattribute4'   = $user.extensionattribute4
                            'extensionattribute5'   = $user.extensionattribute5
                            'extensionattribute6'   = $user.extensionattribute6
                            'extensionattribute7'   = $user.extensionattribute7
                            'extensionattribute8'   = $user.extensionattribute8
                            'extensionattribute9'   = $user.extensionattribute9
                            'extensionattribute10'   = $user.extensionattribute10
                            'extensionattribute11'   = $user.extensionattribute11
                            'extensionattribute12'   = $user.extensionAttribute12
                            'extensionattribute13'   = $user.extensionAttribute13
                            'extensionattribute14'   = $user.extensionattribute14
                            'extensionattribute15'   = $user.extensionAttribute15
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


             if ($ParameterObject.action -eq "Import-Managers") {

                try{
                     $users = Get-ADUser -Filter * `
                        -Properties Manager -Server $domainControllerIP `
                        -Credential $ADcredentials
      
                    foreach ($User in $users) {
                         if ($User.Manager -ne $null) {

                Write-Output $User.Manager
                $Manager = (Get-ADUser $User.Manager).ObjectGuid
                $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/usermanager”

                $userInput = @{
			                'ObjectGuid'            = $User.ObjectGuid
                         'Manager' = $Manager
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
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }


            if ($ParameterObject.action -eq "Import-AzureAD-Managers") {

                try{
                     $users = Get-MgUser -ExpandProperty "manager"
      
                    foreach ($User in $users) {
                        $Manager =$User.manager
                        #$Manager = Get-MgUserManager -UserId $User.Id
                       
                          if (-Not [string]::IsNullOrWhiteSpace($Manager)) {
                        #$Manager = Get-MgUserManager -UserId $User.Id
                Write-Output $Manager.Id
                
                $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/useradmanager”

                 $userInput = @{
			                'ObjectGuid'            = $User.Id
                         'Manager' = $Manager.Id
                        }
                          
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                      
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    
                    }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                  
                    SNComplete $jobQueueItem.sys_id
                    }
                
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }


            if ($ParameterObject.action -eq "Import-Users") {
                try {
                   
                    $users = Get-ADUser -Filter * -Properties whenCreated, description | Where-Object {$_.whenCreated -ge ((Get-Date).AddDays(-1)).Date } |select GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, DisplayName, ObjectClass, ObjectGuid, AccountExpirationDate, accountExpires, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title 
      
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
                $users = Get-MgUser -All 
                   $users.count
                    $ServiceNowURI = "https://$instance.service-now.com//api/x_autps_active_dir/domain/$domainID/aduser"
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                   # $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identitylink"
                    
                   
                    $users | ForEach-Object -Parallel { 
                        $userinfo = Get-MgBetaUser -UserId $_.Id -Property "displayName,accountEnabled,UserType,GivenName,Surname,UserPrincipalName,City,CompanyName,Country,Mail,Department,Description,MailNickName,Mobile,PostalCOde,JobTitle,EmployeeId" 
                        
                        $usertype = $userinfo.UserType 
                        $accountenabled = $userinfo.accountEnabled
                      
                         $mfasms =  Get-MgUserAuthenticationPhoneMethod -UserId $_.UserPrincipalName | Select-Object @{ N='UserPrincipalName'; E={ $_.UserPrincipalName }}, ID, PhoneNumber, PhoneType
                        $userprincname = $_.UserPrincipalName
                        #$employeeId = $UserExtProperties["employeeId"]
                        $userInput = @{
                            'ObjectGuid'        = $_.Id
                            'Domain'            = $using:domainID
                            'GivenName'         = $_.givenname
                            'Surname'           = $_.surname
                            'UserPrincipalName' = $_.UserPrincipalName
                            'Username'          = $userprincname.Substring(0, $userprincname.IndexOf('@'))
                            'Enabled'           = $accountenabled
                            'Name'              = $_.DisplayName
                            'City'              = $_.City
                            'Company'           = $_.CompanyName
                            'Country'           = $_.Country
                            'Email'				= $_.Mail
                            'Department'        = $_.Department
                            'Description'       = $_.Description
                            'MailNickName'      = $_.MailNickname
                            'Mobile'            = $_.Mobile
                            'PostalCode'        = $_.PostalCode
                            'Title'             = $_.JobTitle
                            'UserType'          = $usertype
                            'EmployeeID'        = $_.EmployeeId
                            'mfasms'            = $mfasms.PhoneNumber
                        }

                       
                         
                        $json = $userInput | ConvertTo-Json
                      
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                       # Write-Output $body
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                      #  Write-Output "servicenow uri" 
                      #  Write-Output $using:ServiceNowURI 
                      #  Write-Output "servicenowheaders " 
                      #  Write-Output $using:ServiceNowHeaders
                        $response = Invoke-RestMethod -Headers $using:ServiceNowHeaders -Method 'PUT' -Uri $using:ServiceNowURI -Body $body
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
            #Import guest users
                        if ($ParameterObject.action -eq "Initial-Import-AzureAD-GuestUsers") {
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
                    $users = Get-MgUser -Filter "userType eq 'Guest'" | select $properties 
                   
                    $ServiceNowURI = "https://$instance.service-now.com//api/x_autps_active_dir/domain/$domainID/aduser"
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                   # $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identitylink"
                    
                   
                    foreach ($user in $users) {
                        $userinfo = Get-MgBetaUser -UserId $user.Id -Property "displayName,accountEnabled,UserType" 
                        Write-Output $userinfo.UserType 
                        Write-Output $userinfo.accountEnabled
                        Write-Output $user.DisplayName $user.country $user.city $user.companyName $user.department 
                        $usertype = $userinfo.UserType 
                        $accountenabled = $userinfo.accountEnabled
                      
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
                            'Enabled'           = $accountenabled
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
                            'UserType'          = $usertype
                            'EmployeeID'        = $user.EmployeeId
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


              if ($ParameterObject.action -eq "Initial-Import-AzureAD-MemberUsers") {
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
                    $users = Get-MgUser -Filter "userType eq 'Member'" | select $properties 
                   
                    $ServiceNowURI = "https://$instance.service-now.com//api/x_autps_active_dir/domain/$domainID/aduser"
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                   # $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identitylink"
                    
                   
                    foreach ($user in $users) {
                        $userinfo = Get-MgBetaUser -UserId $user.Id -Property "displayName,accountEnabled,UserType" 
                        Write-Output $userinfo.UserType 
                        Write-Output $userinfo.accountEnabled
                        Write-Output $user.DisplayName $user.country $user.city $user.companyName $user.department 
                        $usertype = $userinfo.UserType 
                        $accountenabled = $userinfo.accountEnabled
                      
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
                            'Enabled'           = $accountenabled
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
                            'UserType'          = $usertype
                            'EmployeeID'        = $user.EmployeeId
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
            #
            if ($ParameterObject.action -eq "Import-MFA") {
                try {
                  
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
                    $user = Get-MgUser -UserId $ParameterObject.id | select $properties 
                   
                    $ServiceNowURI = "https://$instance.service-now.com//api/x_autps_active_dir/domain/$domainID/aduser"
                   # $ServiceNowURI2 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identity"
                   # $ServiceNowURI3 = "https://$instance.service-now.com/api/x_autps_active_dir/domain/identitylink"
                    
                   
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
            #####

             if ($ParameterObject.action -eq "Import-AzureAD-Users") {
                try {
                    
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

                    $Date = $dte.AddDays(-1)
                    $users = Get-MgUser -Filter "CreatedDateTime ge $([datetime]::UtcNow.AddDays(-1).ToString("s"))Z"  | select $properties 
                   
                    $ServiceNowURI = "https://$instance.service-now.com//api/x_autps_active_dir/domain/$domainID/aduser"
                   
                    foreach ($user in $users) {
                        $UserExtProperties = Get-MgUserExtension -UserId $user.Id
                        #Import-Module Microsoft.Graph.DeviceManagement.Enrolment
                        $objectid = $user.Id
                       
                       
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
                            'mfasms'            = $mfasms.PhoneNumber
                        }

                        
                         
                        $json = $userInput | ConvertTo-Json
                       
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
                     
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/aduser/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
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
                    if ($ParameterObject.managedby -ne '') {
                    $createGroup = New-ADGroup -Name $ParameterObject.name `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Path $ParameterObject.path `
                        -Description $ParameterObject.description `
                        -GroupScope $ParameterObject.groupScope `
                        -GroupCategory $ParameterObject.groupCategory `
                        -ManagedBy $ParameterObject.managedby `
                        -PassThru:$true
                    }else{
                        $createGroup = New-ADGroup -Name $ParameterObject.name `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials `
                        -Path $ParameterObject.path `
                        -Description $ParameterObject.description `
                        -GroupScope $ParameterObject.groupScope `
                        -GroupCategory $ParameterObject.groupCategory `
                        -PassThru:$true
                    }
                    $group = Get-ADGroup -Identity $createGroup.ObjectGUID `
                        -Properties Description `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
                    $g = Get-ADGroup -Identity $createGroup.ObjectGUID -Properties Description, ManagedBy `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials 
                        Write-Output $g.ManagedBy

                    if ($ParameterObject.notes -ne ' '){
                        Set-ADGroup -Id $createGroup.ObjectGUID -Replace @{info=$ParameterObject.notes} -Server $domainControllerIP -Credential $ADcredentials
                    }
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
                           $mailnickname = $ParameterObject.name + (New-Guid).Guid.Substring(0,10)
                       }
                        
                            $mailenabled = $false
                        
                        Write-Output "mail enabled "
                        Write-Output $mailenabled
                        if ($ParameterObject.securityenabled -eq "true"){
                            $securityenabled = $true
                        }else{
                            $securityenabled = $false
                        }
                        if ($ParameterObject.isassignedtorole -eq "true"){
                            $isassignedtorole = $true
                        }else{
                            $isassignedtorole = $false
                        }

                        Write-Output "Dynamic $($ParameterObject.dynamic)"
                        if($ParameterObject.dynamic -eq "false"){
                        if ($ParameterObject.grouptype -eq "microsoft365"){
                            Write-Output "Not dynamic microsoft 365"
                       $params = @{
	                        description = $ParameterObject.description
	                        displayName = $ParameterObject.name
	                        groupTypes = @(
		                        "Unified"
	                        )
	                        mailEnabled = $mailenabled
	                       mailNickname = $mailnickname
	                    securityEnabled = $securityenabled
                        isAssignableToRole = $isassignedtorole
                            } 
                        }elseif($ParameterObject.grouptype -eq "security") {
                            Write-Output "Not dynamic security"
                            $params = @{
	                        description = $ParameterObject.description
	                        displayName = $ParameterObject.name
	                        groupTypes = @(     
	                        )
	                        mailEnabled = $false
	                       mailNickname = $mailnickname
	                    securityEnabled = $true
                        isAssignableToRole = $isassignedtorole
                            } 
                        } }
                         elseif($ParameterObject.dynamic -eq "true") {
                             if ($ParameterObject.grouptype -eq "microsoft365"){
                                 Write-Output "dynamic microsoft 365"
                       $params = @{
	                        description = $ParameterObject.description
	                        displayName = $ParameterObject.name
	                        groupTypes = @(
		                        "DynamicMembership", "Unified"
	                        )
	                        mailEnabled = $mailenabled
	                       mailNickname = $mailnickname
	                    securityEnabled = $securityenabled
                        isAssignableToRole = $isassignedtorole
                        MembershipRule = $ParameterObject.membershiprule
                        MembershipRuleProcessingState = "On"
                            } 
                        }elseif($ParameterObject.grouptype -eq "security") {
                            Write-Output "dynamic security"
                            $params = @{
	                        description = $ParameterObject.description
	                        displayName = $ParameterObject.name
	                        groupTypes = @(   
                                "DynamicMembership"  
	                        )
	                        mailEnabled = $false
	                       mailNickname = $mailnickname
	                    securityEnabled = $true
                        isAssignableToRole = $isassignedtorole
                        MembershipRule = $ParameterObject.membershiprule
                        MembershipRuleProcessingState = "On"
                            } 
                        }
                         }
                           
                   $createGroup = New-MgGroup -BodyParameter $params

                
                   ##if ( $ParameterObject.isassignabletorole -eq 'true'){
                   ##    $createGroup = New-MgGroup -DisplayName $ParameterObject.name  -MailNickName $mailnickname -Description $ParameterObject.description -MailEnabled:$false -SecurityEnabled -IsAssignableToRole
                   ##}else{
                   ##    $createGroup = New-MgGroup -DisplayName $ParameterObject.name  -MailNickName $mailnickname -Description $ParameterObject.description -MailEnabled:$false -SecurityEnabled
                  ## }
                    
                    $group = Get-MgGroup -GroupId $createGroup.Id 
                   Write-Output "group id"
                   Write-Output $group.Id
                     if ($ParameterObject.owner -ne ' '){
                        New-MgGroupOwner -GroupId $group.Id -DirectoryObjectId $ParameterObject.owner
                    }
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
                        if ($parmName -ne "groupsysid" -and $parmName -ne "action" -and $parmName -ne "group" -and $parmName -ne "name" -and $ParmName -ne "managedby" -and $ParmName -ne "notes") {   
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
                        if( $ParameterObject.notes -ne ' '){
                            Set-ADGroup -Id $ParameterObject.group -Replace @{info=$ParameterObject.notes} -Server $domainControllerIP -Credential $ADcredentials
                        }
                    if ($ParameterObject.managedby -ne ' '){
                         $Managedby = Get-ADUser -Identity $ParameterObject.managedby `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
                       #$Managedby =  Get-ADUser  -Server $domainControllerIP -Credential $ADcredentials -Filter 'ObjectGUID -eq "$user"' 
                       $var = $Managedby
                            If( $null -eq $var ){
                                Throw "user not found"
                                }
                      
                       $manager = $Managedby.DistinguishedName
                       $group = Get-ADGroup  -Server $domainControllerIP -Credential $ADcredentials -Id $ParameterObject.group
                       $group.ManagedBy = $manager
                       Set-ADGroup -Instance $Group -Server $domainControllerIP -Credential $ADcredentials -PassThru:$true
                        #Set-ADGroup -Identity "c39a1add-f773-4c1a-97bd-be6d243aea47" -ManagedBy $Managedby -Server $domainControllerIP -Credential $ADcredentials
                        $g = Get-ADGroup -Identity $ParameterObject.group -Properties Description, ManagedBy `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials 
                        Write-Output $g.ManagedBy
                        Write-Output $g.Name 
                       
                       # Write-Output $ParameterObject.managedby
                       #$Managedby =  Get-ADUser  -Server $domainControllerIP -Credential $ADcredentials -Identity $ParameterObject.managedby
                      # Write-Output $Managedby.DistinguishedName
                       # Get-ADGroup  -Server $domainControllerIP -Credential $ADcredentials -Identity $ParameterObject.group -Properties ManagedBy | Set-ADGroup -Server $domainControllerIP -Credential $ADcredentials -ManagedBy $Managedby.DistinguishedName
                        #Set-ADObject -Identity $group.DistinguishedName -Replace @{"ManagedBy" = $($ParameterObject.managedby)} -Server $domainControllerIP `
                       # -Credential $ADcredentials
                        # Set-ADGroup -Identity $ParameterObject.group  -ManagedBy $ParameterObject.managedby -Server $domainControllerIP `
                        #-Credential $ADcredentials
                     }
                     $group1 = Get-ADGroup -Identity $group.DistinguishedName | select Name, ManagedBy
                     Write-Output $group1
                    Write-Output "Group scope category "
                    Write-Output $group.GroupScope 
                    Write-Output $group.GroupCategory
                    Write-Output $group.ManagedBy
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
                            #if ($null -ne $member.ObjectType) {
                                $memberInput = @{
                                    'Domain'      = $domainID
                                    'GroupGUID'   = $group.Id
                                    'Name'        = $member.DisplayName
                                   # 'ObjectClass' = $member.ObjectType
                                    'ObjectId'    = $member.Id
                                }
                                $gmjson = $memberInput | ConvertTo-Json
                                $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                                Write-Verbose "ServiceNow groupmember input: $gmbody"
                                $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                                $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
                           # }
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
            #Get Azure AD Group Members
            if ($ParameterObject.action -eq "Get-AzureAD-GroupMembers") {
                try {
                    $group = Get-MgGroup -GroupId $ParameterObject.group 
                    Write-Output $group.DisplayName
                    
                        $groupMembers = Get-MgGroupMemberAsUser -GroupId $group.Id
                        Write-Output "Group members of update group $groupMembers"
                        $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroupmember"
                        foreach ($member in $groupMembers) {
                            #if ($null -ne $member.UserType) {
                                $memberInput = @{
                                    'Domain'      = $domainID
                                    'GroupGUID'   = $group.Id
                                    'Name'        = $member.DisplayName
                                   # 'ObjectClass' = $member.ObjectType
                                    'ObjectId'    = $member.Id
                                }
                                $gmjson = $memberInput | ConvertTo-Json
                                $gmbody = [regex]::Replace($gmjson, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                                Write-Verbose "ServiceNow groupmember input: $gmbody"
                                $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                                $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
                           #}
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
            ##
            # Get Sponsors
            if ($ParameterObject.action -eq "Import-AzureAD-GuestSponsors") {

                try{
                     $users = Get-MgUser  -Filter "userType eq 'Guest'"
      
                    foreach ($User in $users) {
                        $userid = $User.Id
                        $url = "https://graph.microsoft.com/beta/users"
                        $object = "sponsors"
                        $body = @{}
 
                        $sponsor = Invoke-MgGraphRequest -Uri "$url/$($userid)/sponsors?&$select=id" -Method GET -Body $body -OutputType PSObject
                       
                        Write-Output "sponsor " + $sponsor.value.Id
                        $Sponsor = $sponsor.value.Id
                        #$Manager =((Get-MgUser -ExpandProperty "manager").manager).Id 
                       # $Sponsor = Get-MgUserSponsor -UserId $User.Id
                          if ($Sponsor -ne $null) {
                        #$Manager = Get-MgUserManager -UserId $User.Id
                Write-Output $Sponsor
                
                $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/useradsponsors”

                 $userInput = @{
			                'ObjectGuid'            = $User.Id
                         'Sponsor' = $Sponsor
                        }
                          
                        $json = $userInput | ConvertTo-Json
                        $body = [regex]::Replace($json, '(?<=")(.*?)(?=":)', { $args[0].Groups[1].Value.ToLower().replace(' ', '_') })
                        Write-Verbose "ServiceNow input: $body"
                        $body = [System.Text.Encoding]::UTF8.GetBytes($body)
                        $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
                      
                        $output = $response.RawContent
                        Write-Verbose "ServiceNow output: $output"
                    
                    }
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user/cleanup"
                    $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
                  
                    SNComplete $jobQueueItem.sys_id
                    }
                
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }
            ###
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
                    
		$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                    $groups = Get-MgGroup -All  
      
          
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/adgroup"
		  
           
                    foreach ($group in $groups) {
                        Write-Output $group.GroupTypes
                        if ($group.groupType -ne "Unified"){
                            if($group.MailEnabled -eq $true -and $group.SecurityEnabled -eq $false){
                                $grouptype = "Distribution"
                            }else{
                                $grouptype = "security"
                            }
                        }else{
                            $grouptype = "microsoft365"
                        }
                         if ([string]::IsNullOrWhiteSpace($group.onPremisesDomainName)) {
                                $source = "Cloud"
                            }else{
                                $source = "Windows Server AD"
                            }
			 
                        $groupInput = @{
                            'Domain'          = $domainID     
                            'Name'            = $group.DisplayName
                            'ObjectGuid'      = $group.Id
                            'Description'     = $group.Description
                            'MailEnabled'     = $group.MailEnabled
                            'MailNickName'    = $group.mailNickname
                            'Source'          = $source
                            'SecurityEnabled' = $group.SecurityEnabled
                            'IsAssignableToRole' =$group.IsAssignableToRole
                            'grouptype'        = $grouptype
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
                   
		$ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
      
        Write-Verbose $ServiceNowURI
        $response = Invoke-RestMethod -Method "PATCH" -Uri $ServiceNowURI -Headers $ServiceNowHeaders | ConvertTo-Json
    
                    $groups = Get-MgGroup -All | Where-Object {$_.CreatedDateTime -ge ((Get-Date).AddDays(-1)).Date} 
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
                        -Properties Description, ManagedBy `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
           
                    foreach ($group in $groups) {
                        Write-Output $group.ManagedBy
                        $groupInput = @{
                            'Domain'            = $domainID
                            'GroupScope'        = $group.GroupScope
                            'GroupCategory'     = $group.GroupCategory
                            'SamAccountName'    = $group.SamAccountName
                            'DistinguishedName' = $group.DistinguishedName
                            'ObjectClass'       = $group.ObjectClass
                            'ObjectGuid'        = $group.ObjectGuid
                            'Name'              = $group.Name
                            'Path'              = $group.DistinguishedName
                            'managedby'         = $group.ManagedBy
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
                        -Properties whenCreated, description | Where-Object {$_.whenCreated -ge ((Get-Date).AddDays(-1)).Date} 
                        
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

                $userexists = Get-ADGroupMember -Identity $group | Where-Object {$_.ObjectGuid -eq $user.ObjectGuid}  
                        if($userexists){  
                            throw 'the user is already a member'  
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
                    SNFail $jobQueueItem.sys_id
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                   try{
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
                   catch {
                        Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                    }

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
                        -DirectoryObjectId $ParameterObject.usermember -ErrorAction Stop
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
                    $output = $response.RawContent
                    Write-Verbose "ServiceNow output: $output"
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    SNFail $jobQueueItem.sys_id
                    Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
		
                    try {
                        $usersysid = $ParameterObject.usersysid
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
                    catch {
                        Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                    }
                    
                
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
          
                      $groupMember = Remove-MgGroupMemberDirectoryObjectByRef -GroupId $group.Id -DirectoryObjectId $user.Id
          
          
                    SNComplete $jobQueueItem.sys_id
                }
                catch {
                    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
                    SNFail $jobQueueItem.sys_id
                }
            }


       
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
