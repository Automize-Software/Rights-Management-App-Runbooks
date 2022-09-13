param(
  [Parameter(Mandatory=$true)]
  [string] $domainName,
  
  [Parameter(Mandatory=$true)]
  [string] $domainID, 
  
  [Parameter(Mandatory=$true)]
  [string] $domainControllerIP, 
  
  [Parameter(Mandatory=$true)]
  [string] $credentialsName, 
  
  [Parameter(Mandatory=$true)]
  [string] $snowCredentialsName, 
  
  [Parameter(Mandatory=$true)]
  [string] $instance
)

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
    } catch {
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
    } catch {
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
        'status' = 3
        'exception' = $($_.Exception.Message)
      }
      $json = $SnowInput | ConvertTo-Json
      $body = [System.Text.Encoding]::UTF8.GetBytes($json)
      $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri "https://$($instance).service-now.com/api/now/table/x_autps_active_dir_command_queue/$($sys_id)" -Body $body
      $output = $response.RawContent
      Write-Verbose "ServiceNow output: $output"
    } catch {
      Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
    }
}

#Write-Verbose "Runbook started - $($metadata.startTime)" -Verbose
 
if (Get-Module -ListAvailable -Name "ActiveDirectory") {
    Write-Verbose "Found ActiveDirectory module"
} else {
  try {
    Write-Verbose "Did not find Active Directory module. Trying to install the RSAT-AD-PowerShell Windows Feature"
    Install-WindowsFeature RSAT-AD-PowerShell
  } catch {
    Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
    throw "Could not find ActiveDirectory module. Please install this module"
  }
}

$credentials = Get-AutomationPSCredential -Name $credentialsName
$snowCredentials =  Get-AutomationPSCredential -Name $snowCredentialsName
$ServiceNowAuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $snowCredentials.UserName, $snowCredentials.GetNetworkCredential().Password)))
$ServiceNowHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$ServiceNowHeaders.Add('Authorization',('Basic {0}' -f $ServiceNowAuthInfo))
$ServiceNowHeaders.Add('Accept','application/json')
$ServiceNowHeaders.Add('Content-Type','application/json; charset=utf-8')

# Do an initial import
try {
  $updateURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/syncstate/updating"
  Write-Verbose $updateURI
  $response = Invoke-RestMethod -Method "PATCH" -Uri $updateURI -Headers $ServiceNowHeaders | ConvertTo-Json

  $domain = Get-ADDomain -Server $domainControllerIP -Credential $credentials
  $forest = Get-ADForest -Server $domainControllerIP -Credential $credentials
  $pam = Get-ADOptionalFeature -Server $domainControllerIP -Credential $credentials -filter {name -like "Privileged*"}
  $pamEnabled = $false

  if(($pam.PSobject.Properties.name -match "EnabledScopes")){
    Write-Verbose "Found EnabledScopes in response"
    $myObject = [PSCustomObject]$pam
    $EnabledScopes = [PSCustomObject]$pam.PSobject.Properties['EnabledScopes']
    if($EnabledScopes.Value.count -eq 0){
      $pamEnabled = $false
    } else {
      $pamEnabled = $true
    }
  } 
  
  $domainInput = @{
    'domain_mode' = ($domain.DomainMode).ToString()
    'name' = $domain.Name
    'forest_mode' = ($forest.ForestMode).ToString()
    'forest_name' = $forest.Name
    'pam_enabled' = $pamEnabled
    'sync_state' = "ready"
  }
  
  $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID"
  
  $json = $domainInput | ConvertTo-Json
  $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
  Write-Verbose "ServiceNow input: $body"
  $body = [System.Text.Encoding]::UTF8.GetBytes($body)
  $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
  $output = $response.RawContent
  Write-Verbose "ServiceNow output: $output"
} catch {
  Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
  #throw
}

$TimeNow = Get-Date
$TimeEnd = $TimeNow.addMinutes(60)

while ($TimeNow -le $TimeEnd) { 
  $TimeNow = Get-Date
  $ServiceNowURI = "https://$instance.service-now.com/api/now/table/x_autps_active_dir_command_queue?sysparm_query=domain%3D$domainID%5Estatus%3D1%5EORDERBYsys_created_on&sysparm_limit=1"
  Write-Verbose "ServiceNow URI: $ServiceNowURI"
  $jobQueue = Invoke-RestMethod -Method "GET" -Uri $ServiceNowURI -Headers $ServiceNowHeaders 
  if($jobQueue.result){
    $jobQueueItem = $jobQueue.result[0]
    Write-Verbose "Processing command queue item with sys_id $($jobQueueItem.sys_id)"
    SNWIP $jobQueueItem.sys_id
    try {
      $JSONObject = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($jobQueueItem.input))
      $ParameterObject = $JSONObject | ConvertFrom-Json
      Write-Verbose "Executing action $($ParameterObject.action)"
      if($ParameterObject.action -eq "Create-User") {
        try {
          
          if($null -ne $ParameterObject.givenname -and $null -ne $ParameterObject.surname -and $ParameterObject.givenname -ne '' -and $ParameterObject.surname -ne '') {
            $displayname = $ParameterObject.givenname + " " + $ParameterObject.surname + " (" + $ParameterObject.username + ")"
          } elseif ($null -ne $ParameterObject.surname -and $ParameterObject.surname -ne ''){
            $displayname = $ParameterObject.surname + " (" + $ParameterObject.username + ")"
          } elseif ($null -ne $ParameterObject.givenname -and $ParameterObject.givenname -ne ''){
            $displayname = $ParameterObject.givenname + " (" + $ParameterObject.username + ")"
          } else {
            $displayname = $ParameterObject.username
          }
          
          $samAccountName = $ParameterObject.username
          $userPrincipalName = $samtAccountName + "@" + $domainName
          $userPassword = ConvertTo-SecureString $ParameterObject.password -AsPlainText -Force
          
          $createUser = New-ADUser -SamAccountName $samAccountName `
            -Server $domainControllerIP `
          	-Credential $credentials  `
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
            -Properties GivenName,Surname,UserPrincipalName,Enabled,SamAccountName,DistinguishedName,Name,ObjectClass,ObjectGuid,AccountExpirationDate,AccountLockoutTime,CannotChangePassword,City,Company,Country,Department,Description,EmailAddress,EmployeeID,EmployeeNumber,lastLogon,LockedOut,MobilePhone,Office,OfficePhone,PasswordExpired,PasswordNeverExpires,PostalCode,Title `
            -Server $domainControllerIP `
            -Credential $credentials
      
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
      
          Write-Verbose "ServiceNow URL $ServiceNowURI"
          
          $userInput = @{
            'GivenName' = $user.GivenName
            'Surname' = $user.Surname
            'UserPrincipalName' = $user.UserPrincipalName
            'Enabled' = $user.Enabled
            'SamAccountName' = $user.SamAccountName
            'DistinguishedName' = $user.DistinguishedName
            'Name' = $user.Name
            'ObjectClass' = $user.ObjectClass
            'ObjectGuid' = $user.ObjectGuid
            'AccountExpirationDate' = $user.AccountExpirationDate
            'AccountLockoutTime' = $user.AccountLockoutTime
            'CannotChangePassword' = $user.CannotChangePassword
            'City' = $user.City
            'Company' = $user.Company
            'Country' = $user.Country
            'Department' = $user.Department
            'Description' = $user.Description
            'EmailAddress' = $user.EmailAddress
            'EmployeeID' = $user.EmployeeID
            'EmployeeNumber' = $user.EmployeeNumber
            'LockedOut' = $user.LockedOut
            'MobilePhone' = $user.MobilePhone
            'Office' = $user.Office
            'OfficePhone' = $user.OfficePhone
            'PasswordExpired' = $user.PasswordExpired
            'PasswordNeverExpires' = $user.PasswordNeverExpires 
            'PostalCode' = $user.PostalCode
            'Title' = $user.Title
            'sysid' = $ParameterObject.usersysid
          }
          $json = $userInput | ConvertTo-Json
          $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
          Write-Verbose "ServiceNow input: $body"
          $body = [System.Text.Encoding]::UTF8.GetBytes($body)
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
          $output = $response.RawContent
          Write-Verbose "ServiceNow output: $output"
          SNComplete $jobQueueItem.sys_id
        } catch {
          SNFail $jobQueueItem.sys_id
          Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
          try {
            $usersysid = $ParameterObject.usersysid
            $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
        
            Write-Verbose "ServiceNow URL $ServiceNowURI"
            
            $userInput = @{
              'sysid' = $ParameterObject.usersysid
              'Sync State' = "Failed"
            }
            $json = $userInput | ConvertTo-Json
            $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
            Write-Verbose "ServiceNow input: $body"
            $body = [System.Text.Encoding]::UTF8.GetBytes($body)
            $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
            $output = $response.RawContent
            Write-Verbose "ServiceNow output: $output"
          } catch {
            Write-Error "Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)"
          }
        }
      }
      
      if($ParameterObject.action -eq "Update-User") {
        try{
          $user = Get-ADUser -Identity $ParameterObject.user `
            -Properties GivenName,Surname,Description,title,office,postalcode,city,country,company,emailaddress,officephone,mobilephone,department,employeeid,employeenumber `
            -Server $domainControllerIP `
            -Credential $credentials
            
          $ParameterObject.PSObject.Properties | ForEach-Object {
            $parmName = $_.Name
            $parmValue = $_.Value
            if($parmName -ne "usersysid" -and $parmName -ne "action" -and $parmName -ne "user"){   
              if($parmValue -eq ""){
                $user.$parmName = $null
              } elseif($parmValue -eq "false") {
                $user.$parmName = $false
              } elseif($parmValue -eq "true") {
                $user.$parmName = $true
              } else {
                $user.$parmName = $parmValue
              }
            }
          } 
      
          Set-ADUser -Instance $user `
            -Server $domainControllerIP `
            -Credential $credentials
          
          $user = Get-ADUser -Identity $ParameterObject.user `
            -Properties GivenName,Surname,UserPrincipalName,Enabled,SamAccountName,DistinguishedName,Name,ObjectClass,ObjectGuid,AccountExpirationDate,AccountLockoutTime,CannotChangePassword,City,Company,Country,Department,Description,EmailAddress,EmployeeID,EmployeeNumber,lastLogon,LockedOut,MobilePhone,Office,OfficePhone,PasswordExpired,PasswordNeverExpires,PostalCode,Title `
            -Server $domainControllerIP `
            -Credential $credentials
      
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
      
          Write-Verbose "ServiceNow URL $ServiceNowURI"
          
          $userInput = @{
            'GivenName' = $user.GivenName
            'Surname' = $user.Surname
            'UserPrincipalName' = $user.UserPrincipalName
            'Enabled' = $user.Enabled
            'SamAccountName' = $user.SamAccountName
            'DistinguishedName' = $user.DistinguishedName
            'Name' = $user.Name
            'ObjectClass' = $user.ObjectClass
            'ObjectGuid' = $user.ObjectGuid
            'AccountExpirationDate' = $user.AccountExpirationDate
            'AccountLockoutTime' = $user.AccountLockoutTime
            'CannotChangePassword' = $user.CannotChangePassword
            'City' = $user.City
            'Company' = $user.Company
            'Country' = $user.Country
            'Department' = $user.Department
            'Description' = $user.Description
            'EmailAddress' = $user.EmailAddress
            'EmployeeID' = $user.EmployeeID
            'EmployeeNumber' = $user.EmployeeNumber
            'lastLogon' = $user.lastLogon
            'LockedOut' = $user.LockedOut
            'MobilePhone' = $user.MobilePhone
            'Office' = $user.Office
            'OfficePhone' = $user.OfficePhone
            'PasswordExpired' = $user.PasswordExpired
            'PasswordNeverExpires' = $user.PasswordNeverExpires
            'PostalCode' = $user.PostalCode
            'Title' = $user.Title
            'sysid' = $ParameterObject.usersysid
          }
          $json = $userInput | ConvertTo-Json
          $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
          Write-Verbose "ServiceNow input: $body"
          $body = [System.Text.Encoding]::UTF8.GetBytes($body)
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
          $output = $response.RawContent
          Write-Verbose "ServiceNow output: $output"
          SNComplete $jobQueueItem.sys_id
        } catch {
          SNFail $jobQueueItem.sys_id
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          $usersysid = $ParameterObject.usersysid
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
      
          Write-Verbose "ServiceNow URL $ServiceNowURI"
          
          $userInput = @{
            'sysid' = $ParameterObject.usersysid
            'Sync State' = "Failed"
          }
          $json = $userInput | ConvertTo-Json
          $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
          Write-Verbose "ServiceNow input: $body"
          $body = [System.Text.Encoding]::UTF8.GetBytes($body)
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
          $output = $response.RawContent
          Write-Verbose "ServiceNow output: $output"
          
        } 
      }
      
      if($ParameterObject.action -eq "Remove-User") {
        try{
          $user = Remove-ADUser -Identity $ParameterObject.user `
            -Server $domainControllerIP `
            -Credential $credentials `
            -Confirm:$false
          SNComplete $jobQueueItem.sys_id
        } catch { 
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
      
          SNFail $jobQueueItem.sys_id
        } 
      }
      
      if($ParameterObject.action -eq "Set-User-Password") {
        try{
          $user = Set-ADAccountPassword -Identity $ParameterObject.user `
            -Reset `
            -NewPassword (ConvertTo-SecureString -AsPlainText $ParameterObject.password -Force) `
            -Server $domainControllerIP `
            -Credential $credentials `
            -Confirm:$false
          Write-Output "User password has been set"  
          if($ParameterObject.mustChange -eq $true) {
            Set-ADUser -Identity $ParameterObject.user `
              -ChangePasswordAtLogon $true `
              -Server $domainControllerIP `
              -Credential $credentials `
              -Confirm:$false
            Write-Output "User must change password at next login"
          }
          
          if($ParameterObject.unlock -eq $true) {
            Unlock-ADAccount -Identity $ParameterObject.user `
              -Server $domainControllerIP `
              -Credential $credentials `
              -Confirm:$false
            Write-Output "User has been unlocked"
          }
          SNComplete $jobQueueItem.sys_id
        } catch { 
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
        } 
      }
      
      if($ParameterObject.action -eq "Unlock-User") {
        try{
          Unlock-ADAccount -Identity $ParameterObject.user `
            -Server $domainControllerIP `
            -Credential $credentials `
            -Confirm:$false
          Write-Output "User has been unlocked"
          SNComplete $jobQueueItem.sys_id
        } catch { 
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
        } 
      }
      
      if($ParameterObject.action -eq "Enable-User") {
        try{
          Enable-ADAccount -Identity $ParameterObject.user `
            -Server $domainControllerIP `
            -Credential $credentials `
            -Confirm:$false
          Write-Output "User has been enabled"
          SNComplete $jobQueueItem.sys_id
        } catch { 
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
        } 
      }
      
      if($ParameterObject.action -eq "Disable-User") {
        try{
          Disable-ADAccount -Identity $ParameterObject.user `
            -Server $domainControllerIP `
            -Credential $credentials `
            -Confirm:$false
          Write-Output "User has been disabled"
          SNComplete $jobQueueItem.sys_id
        } catch { 
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
        } 
      }
      
      if($ParameterObject.action -eq "Import-Users") {
        try {
          $users = Get-ADUser -Filter * `
            -Properties GivenName,Surname,UserPrincipalName,Enabled,SamAccountName,DistinguishedName,Name,ObjectClass,ObjectGuid,AccountExpirationDate,accountExpires,AccountLockoutTime,CannotChangePassword,City,Company,Country,Department,Description,EmailAddress,EmployeeID,EmployeeNumber,lastLogon,LockedOut,MobilePhone,Office,OfficePhone,PasswordExpired,PasswordNeverExpires,PostalCode,Title `
            -Server $domainControllerIP `
            -Credential $credentials
      
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user"
           
          foreach($user in $users) {
            $userInput = @{
              'Domain' = $domainID
              'GivenName' = $user.GivenName
              'Surname' = $user.Surname
              'UserPrincipalName' = $user.UserPrincipalName
              'Enabled' = $user.Enabled
              'SamAccountName' = $user.SamAccountName
              'DistinguishedName' = $user.DistinguishedName
              'Name' = $user.Name
              'ObjectClass' = $user.ObjectClass
              'ObjectGuid' = $user.ObjectGuid
              'AccountExpirationDate' = $user.AccountExpirationDate
              'accountExpires' = $user.accountExpires
              'AccountLockoutTime' = $user.AccountLockoutTime
              'CannotChangePassword' = $user.CannotChangePassword
              'City' = $user.City
              'Company' = $user.Company
              'Country' = $user.Country
              'Department' = $user.Department
              'Description' = $user.Description
              'EmailAddress' = $user.EmailAddress
              'EmployeeID' = $user.EmployeeID
              'EmployeeNumber' = $user.EmployeeNumber
              'lastLogon' = $user.lastLogon
              'LockedOut' = $user.LockedOut
              'MobilePhone' = $user.MobilePhone
              'Office' = $user.Office
              'OfficePhone' = $user.OfficePhone
              'PasswordExpired' = $user.PasswordExpired
              'PasswordNeverExpires' = $user.PasswordNeverExpires
              'PostalCode' = $user.PostalCode
              'Title' = $user.Title
            }
            $json = $userInput | ConvertTo-Json
            $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
            Write-Verbose "ServiceNow input: $body"
            $body = [System.Text.Encoding]::UTF8.GetBytes($body)
            $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
            $output = $response.RawContent
            Write-Verbose "ServiceNow output: $output"
          }
          
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/user/cleanup"
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI
          SNComplete $jobQueueItem.sys_id
        } catch {
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
        }
      }
      
      if($ParameterObject.action -eq "Create-Group") {
        try {
          $createGroup = New-ADGroup -Name $ParameterObject.name `
            -Server $domainControllerIP `
          	-Credential $credentials  `
          	-Description $ParameterObject.description `
          	-GroupScope $ParameterObject.groupScope `
          	-GroupCategory $ParameterObject.groupCategory `
          	-PassThru:$true
          	
          $group = Get-ADGroup -Identity $createGroup.ObjectGUID `
            -Properties Description `
            -Server $domainControllerIP `
          	-Credential $credentials
      
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
      
          Write-Verbose "ServiceNow URL $ServiceNowURI"
          
          $groupInput = @{
            'Enabled' = $group.Enabled
            'SamAccountName' = $group.SamAccountName
            'DistinguishedName' = $group.DistinguishedName
            'Name' = $group.Name
            'ObjectClass' = $group.ObjectClass
            'ObjectGuid' = $group.ObjectGuid
            'Description' = $group.Description
            'GroupScope' = $group.GroupScope
            'GroupCategory' = $group.GroupCategory
            'sysid' = $ParameterObject.groupsysid
          }
          $json = $groupInput | ConvertTo-Json
          $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
          Write-Verbose "ServiceNow input: $body"
          $body = [System.Text.Encoding]::UTF8.GetBytes($body)
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
          $output = $response.RawContent
          Write-Verbose "ServiceNow output: $output"
          SNComplete $jobQueueItem.sys_id
        } catch {
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
          $groupsysid = $ParameterObject.groupsysid
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
      
          Write-Verbose "ServiceNow URL $ServiceNowURI"
          
          $groupInput = @{
            'sysid' = $ParameterObject.groupsysid
            'Sync State' = "Failed"
          }
          $json = $groupInput | ConvertTo-Json
          $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
          Write-Verbose "ServiceNow input: $body"
          $body = [System.Text.Encoding]::UTF8.GetBytes($body)
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
          $output = $response.RawContent
          Write-Verbose "ServiceNow output: $output"
        } 
      }
      
      if($ParameterObject.action -eq "Update-Group") {
        try{
          $group = Get-ADGroup -Identity $ParameterObject.group `
            -Properties Description `
            -Server $domainControllerIP `
          	-Credential $credentials
            
          $ParameterObject.PSObject.Properties | ForEach-Object {
            $parmName = $_.Name
            $parmValue = $_.Value
            if($parmName -ne "groupsysid" -and $parmName -ne "action" -and $parmName -ne "group" -and $parmName -ne "name"){   
              if($parmValue -eq ""){
                $group.$parmName = $null
              } elseif($parmValue -eq "false") {
                $group.$parmName = $false
              } elseif($parmValue -eq "true") {
                $user.$parmName = $true
              } else {
                $group.$parmName = $parmValue
              }
            }
          } 
      
          Set-ADGroup -Instance $group `
            -Server $domainControllerIP `
            -Credential $credentials
          
          $group = Get-ADGroup -Identity $ParameterObject.group `
            -Properties Description `
            -Server $domainControllerIP `
          	-Credential $credentials
      
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
      
          Write-Verbose "ServiceNow URL $ServiceNowURI"
          
          $groupInput = @{
            'Enabled' = $group.Enabled
            'SamAccountName' = $group.SamAccountName
            'DistinguishedName' = $group.DistinguishedName
            'Name' = $group.Name
            'ObjectClass' = $group.ObjectClass
            'ObjectGuid' = $group.ObjectGuid
            'Description' = $group.Description
            'GroupScope' = $group.GroupScope
            'GroupCategory' = $group.GroupCategory
            'sysid' = $ParameterObject.groupsysid
          }
          $json = $groupInput | ConvertTo-Json
          $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
          Write-Verbose "ServiceNow input: $body"
          $body = [System.Text.Encoding]::UTF8.GetBytes($body)
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
          $output = $response.RawContent
          Write-Verbose "ServiceNow output: $output"
          if($response.result.sync_policy -gt 0){
            $groupMembers = Get-ADGroupMember -Server $domainControllerIP -Credential $credentials -Identity $group.ObjectGuid
            $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/groupmember"
            foreach($member in $groupMembers) {
              if($null -ne $member.ObjectClass){
                $memberInput = @{
                  'Domain' = $domainID
                  'GroupGUID' = $group.ObjectGuid
                  'SamAccountName' = $member.SamAccountName
                  'DistinguishedName' = $member.DistinguishedName
                  'ObjectClass' = $member.ObjectClass
                  'ObjectGuid' = $member.ObjectGuid
                  'Name' = $member.Name
                }
                $gmjson = $memberInput | ConvertTo-Json
                $gmbody = [regex]::Replace($gmjson,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
                Write-Verbose "ServiceNow groupmember input: $gmbody"
                $gmbody = [System.Text.Encoding]::UTF8.GetBytes($gmbody)
                $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
              }
            }
          }
          SNComplete $jobQueueItem.sys_id
        } catch { 
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
      
          Write-Verbose "ServiceNow URL $ServiceNowURI"
          
          $groupInput = @{
            'sysid' = $ParameterObject.groupsysid
            'Sync State' = "Failed"
          }
          $json = $groupInput | ConvertTo-Json
          $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
          Write-Verbose "ServiceNow input: $body"
          $body = [System.Text.Encoding]::UTF8.GetBytes($body)
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
          $output = $response.RawContent
          Write-Verbose "ServiceNow output: $output"
        } 
      }
      
      if($ParameterObject.action -eq "Remove-Group") {
        try{
          $group = Remove-ADGroup -Identity $ParameterObject.group `
            -Server $domainControllerIP `
          	-Credential $credentials `
          	-Confirm:$false
          SNComplete $jobQueueItem.sys_id
        } catch { 
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
        } 
      }
      
      if($ParameterObject.action -eq "Import-Groups") {
        try {
          $groups = Get-ADGroup -Filter * `
            -Properties Description `
            -Server $domainControllerIP `
          	-Credential $credentials
      
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/group"
           
          foreach($group in $groups) {
            $groupInput = @{
              'Domain' = $domainID
              'GroupScope' = $group.GroupScope
              'GroupCategory' = $group.GroupCategory
              'SamAccountName' = $group.SamAccountName
              'DistinguishedName' = $group.DistinguishedName
              'ObjectClass' = $group.ObjectClass
              'ObjectGuid' = $group.ObjectGuid
              'Name' = $group.Name
              'Description' = $group.Description
            }
            $json = $groupInput | ConvertTo-Json
            $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
            Write-Verbose "Servicenow input: $body"
            $body = [System.Text.Encoding]::UTF8.GetBytes($body)
            $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowURI -Body $body
            if($response.result.sync_policy -gt 0){
              $groupMembers = Get-ADGroupMember -Server $domainControllerIP -Credential $credentials -Identity $group.ObjectGuid
              $ServiceNowGroupMemberURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/groupmember"
              foreach($member in $groupMembers) {
                if($null -ne $member.ObjectClass){
                  $memberInput = @{
                    'Domain' = $domainID
                    'GroupGUID' = $group.ObjectGuid
                    'SamAccountName' = $member.SamAccountName
                    'DistinguishedName' = $member.DistinguishedName
                    'ObjectClass' = $member.ObjectClass
                    'ObjectGuid' = $member.ObjectGuid
                    'Name' = $member.Name
                  }
                  $gmjson = $memberInput | ConvertTo-Json
                  $gmbody = [regex]::Replace($gmjson,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
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
        } catch {
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
        }
      }
      
      if($ParameterObject.action -eq "Create-Group-Member") {
        try {
          $group = Get-ADGroup -Identity $ParameterObject.group `
            -Server $domainControllerIP `
          	-Credential $credentials
          	
          if(!$group) {
            throw "The group was not found"
          }
          
          $user = Get-ADUser -Identity $ParameterObject.user `
            -Server $domainControllerIP `
          	-Credential $credentials
          	
          if(!$user) {
            throw "The user was not found"
          }
          
          if($null -ne $ParameterObject.ttl){
            $groupMember = Add-ADGroupMember `
            -Identity $group.ObjectGuid `
            -MemberTimeToLive $ParameterObject.ttl `
            -Members $user.ObjectGuid `
            -Server $domainControllerIP `
            -Credential $credentials `
            -PassThru:$true
          } else {
            $groupMember = Add-ADGroupMember `
            -Identity $group.ObjectGuid `
            -Members $user.ObjectGuid `
            -Server $domainControllerIP `
            -Credential $credentials `
            -PassThru:$true
          }
          
          Write-Output $groupMember | ConvertTo-Json
          
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
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PUT' -Uri $ServiceNowGroupMemberURI -Body $gmbody
          SNComplete $jobQueueItem.sys_id
        } catch {
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
          $ServiceNowURI = "https://$instance.service-now.com/api/x_autps_active_dir/domain/$domainID/groupmember"
      
          Write-Verbose "ServiceNow URL $ServiceNowURI"
          
          $groupInput = @{
            'sysid' = $ParameterObject.membersysid
            'Sync State' = "Failed"
          }
          $json = $groupInput | ConvertTo-Json
          $body = [regex]::Replace($json,'(?<=")(.*?)(?=":)',{$args[0].Groups[1].Value.ToLower().replace(' ','_')})
          Write-Verbose "ServiceNow input: $body"
          $body = [System.Text.Encoding]::UTF8.GetBytes($body)
          $response = Invoke-RestMethod -Headers $ServiceNowHeaders -Method 'PATCH' -Uri $ServiceNowURI -Body $body
          $output = $response.RawContent
          Write-Verbose "ServiceNow output: $output"
        }
      }
      
      if($ParameterObject.action -eq "Remove-Group-Member") {
        try {
          $group = Get-ADGroup -Identity $ParameterObject.group `
            -Server $domainControllerIP `
          	-Credential $credentials
          	
          if(!$group) {
            throw "The group was not found"
          }
          
          $user = Get-ADUser -Identity $ParameterObject.user `
            -Server $domainControllerIP `
          	-Credential $credentials
          	
          if(!$user) {
            throw "The user was not found"
          }
          
          $groupMember = Remove-ADGroupMember `
          -Identity $group.ObjectGuid `
          -Members $user.ObjectGuid `
          -Server $domainControllerIP `
          -Credential $credentials `
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
        } catch {
          Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
          SNFail $jobQueueItem.sys_id
        }
      }
    } catch {
      Write-Error ("Exception caught at line $($_.InvocationInfo.ScriptLineNumber), $($_.Exception.Message)")
      SNFail $jobQueueItem.sys_id
    }
  } else {
    Write-Verbose "Nothing in the command queue. Sleeping for 60 seconds"
    Start-Sleep -Seconds 60
  }
}
