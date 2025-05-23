param(
    [Parameter(Mandatory = $true)]
    [string] $domainID, 
  
    [Parameter(Mandatory = $true)]
    [string] $snowCredentialsName, 
  
    [Parameter(Mandatory = $true)]
    [string] $instance
)

$PSStyle.OutputRendering = [System.Management.Automation.OutputRendering]::PlainText

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



# Setup connections

if($null -eq $ADcredentialsName) {
    Write-Warning "Active Directory Credentials not provided. No AD connection will be available"
} else {
	$ADcredentials = Get-AutomationPSCredential -Name $ADcredentialsName
}


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


$TimeNow = Get-Date
$TimeEnd = $TimeNow.addMinutes(2)

while ($TimeNow -le $TimeEnd) { 
    $TimeNow = Get-Date
    $ServiceNowURI = "https://$instance.service-now.com/api/now/table/x_autps_active_dir_command_queue?sysparm_query=domain%3D$domainID%5Ecommand%3DCreate-User%5Estatus%3D1%5EORDERBYsys_created_on&sysparm_limit=1"
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
                        $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname 
                        $exists = [bool] (Get-ADUser -Filter "DisplayName -eq '$displayname'" -ErrorAction Ignore)
                        if ($exists){
                            $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname + " (" + $ParameterObject.username + ")"
                        }
                    }
                    elseif ($null -ne $ParameterObject.surname -and $ParameterObject.surname -ne '') {
                        $displayname = $ParameterObject.surname 
                         $exists = [bool] (Get-ADUser -Filter "DisplayName -eq '$displayname'" -ErrorAction Ignore)
                        if ($exists){
                             $displayname = $ParameterObject.surname + " (" + $ParameterObject.username + ")"
                        }
                    }
                    elseif ($null -ne $ParameterObject.givenname -and $ParameterObject.givenname -ne '') {
                        $displayname = $ParameterObject.givenname 
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
                        $path = $ParameterObject.path
                    }
                    else{
                       $path = $domain.UsersContainer  
                    }
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
                        -Path $path `
                        -Department $ParameterObject.department `
                        -EmployeeID $ParameterObject.employeeid `
                        -EmployeeNumber $ParameterObject.employeenumber `
                        -Description $ParameterObject.description `
                        -AccountPassword $userPassword `
                        -StreetAddress $ParameterObject.streetaddress `
                        -Enabled:$true `
                        -ChangePasswordAtLogon:$false `
                        -PassThru:$true
                        

                    $user = Get-ADUser -Identity $ParameterObject.username `
                        -Properties GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, EmployeeType, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials

                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.country)){
                                    
                                     Set-ADUser -Identity $ParameterObject.username -Replace @{c=$ParameterObject.country;co=$ParameterObject.englishname;countrycode=$ParameterObject.iso} -Server $domainControllerIP -Credential $ADcredentials 
                                }
                                if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.preferredlanguage)){
                                   
                                    Set-ADObject -Identity $user.DistinguishedName -replace @{preferredLanguage=$ParameterObject.preferredlanguage} -Server $domainControllerIP -Credential $ADcredentials
                     }
                              
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.expirationdate)){
                        Set-ADAccountExpiration -Identity $ParameterObject.username -DateTime $ParameterObject.expirationdate -Server $domainControllerIP -Credential $ADcredentials
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
                    if(-Not [string]::IsNullOrWhiteSpace($ParameterObject.employeetype)){
                         Set-ADUser -Identity $user -Add @{'employeeType' = $ParameterObject.employeetype} -Server $domainControllerIP -Credential $ADcredentials
                    }
                   
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
                   
                    Write-Verbose "ServiceNow URL $ServiceNowURI"
                    $user = Get-ADUser -Identity $ParameterObject.username `
                        -Properties GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, ObjectClass, ObjectGuid, AccountExpirationDate, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, EmployeeType, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title `
                        -Server $domainControllerIP `
                        -Credential $ADcredentials
                        $Info = Get-ADUser -Identity $ParameterObject.username -Properties * | Select-Object AccountExpirationDate
                       
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
                    catch {
                        Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
                    }
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
