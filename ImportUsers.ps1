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
    $ServiceNowURI = "https://$instance.service-now.com/api/now/table/x_autps_active_dir_command_queue?sysparm_query=domain%3D$domainID%5Ecommand%3DImport-Users%5Estatus%3D1%5EORDERBYsys_created_on&sysparm_limit=1"
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


            if ($ParameterObject.action -eq "Import-Users") {
                try {
                   
                    $users = Get-ADUser -Filter * -Properties whenCreated, description | Where-Object {$_.whenCreated -ge ((Get-Date).AddDays(-1)).Date } |select GivenName, Surname, UserPrincipalName, Enabled, SamAccountName, DistinguishedName, Name, DisplayName, ObjectClass, ObjectGuid, AccountExpirationDate, accountExpires, AccountLockoutTime, CannotChangePassword, City, Company, Country, Department, Description, EmailAddress, EmployeeID, EmployeeNumber, EmployeeType, lastLogon, LockedOut, MobilePhone, Office, OfficePhone, PasswordExpired, PasswordNeverExpires, PostalCode, Title 
      
                    $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
                   
                    foreach ($user in $users) {
                         $Info = Get-ADUser -Identity $user.SamAccountName -Properties * | select AccountExpirationDate
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
                            'accountexpirationdate' = $Info.AccountExpirationDate
                            'accountExpires'        = $user.accountExpires
                            'AccountLockoutTime'    = $user.AccountLockoutTime
                            'CannotChangePassword'  = $user.CannotChangePassword
                            'City'                  = $user.City
                            'Company'               = $user.Company
                            'Country'               = $user.Country
                            'Department'            = $user.Department
                            'employeeType'          = $user.EmployeeType
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
