<# Defining Variables #>

# Azure Connection 
$connectionName = "AzureRunAsConnection"

# Booleans for existance of resource 
$existsRG = 0                           # Do not change (verify if Ressource Group exists) 
$existsSA = 0                           # Do not change (verify if Storage Account exists)
$existsContainer = 0                    # Do not change (verify if Blob container  exists)

$keyVaultBoolean = 0                    # If KeyVault is used, then 1 else Secret 0 
$usersBoolean = 1                       # If user file must be updated, 1 else 0 
$usersLicensesBoolean = 0               # If user file must be updated, 1 else 0 
$groupsBoolean = 1                      # If teams groups file must be updated, 1 else 0 
$channelsBoolean = 0                    # If teams channels must be updated, 1 else 0 
$licencesRatioBoolean = 0               # If licenses subscriptions & ratio is enabled 1, else à 0 
$groupsLicensesBoolean = 0              # If groups licenses is enabled 1, else 0 

# Azure Resource Names  
$newRGName =   "AzureRG"
$location = "westeurope"                                         # TO COMPLETE
$storageAccountName = "keolispocvgu"                             # TO COMPLETE
$containerName = "testgroup"                                        # TO COMPLETE

#Infos for App Registration in Azure  
$clientId =   ""  #"f61be736-c8fb-400f-bb03-292d79ad8ff2"            # TO COMPLETE
$tenantName =  ""                                                  #"keolisgroup.onmicrosoft.com"                 # TO COMPLETE

if($keyVaultBoolean -eq 1){
    $keyVaultName = "ReportingO365KVault"                                   # TO COMPLETE
    $secretName = "graphAPIsecret"                               # TO COMPLETE
    $msolpasswordName = "MSOnlinePassword"
    $msoluserName = "MSOnlineUser"
} 

#Graph API URL  
$resource = "https://graph.microsoft.com/"
$apiUrlBeta = 'https://graph.microsoft.com/beta'
$apiUrlOne = 'https://graph.microsoft.com/v1.0'
#Requests properties
$dateSuffix = Get-Date -Format "yyyyMMdd"

# Connecting to Azure environment
try
{
    $servicePrincipalConnection = Get-AutomationConnection -Name $connectionName         

    "Logging in to Azure..."

    Add-AzureRmAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 
} catch {
    if (!$servicePrincipalConnection)
    {
        $errorMessage = "Connection $connectionName not found."
        throw $errorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

# If KeyVault is used, we must get the secret id

if($keyVaultBoolean -eq 1){
    $clientSecret = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $secretName
    $clientSecret = $clientSecret.SecretValueText

    $msolpassword = Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $msolpasswordName
    $msolpassword = $msolpassword.SecretValueText

    $msoluser =  Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $msoluserName
    $msoluser = $msoluser.SecretValueText

    $secStringPassword = ConvertTo-SecureString $msolpassword -AsPlainText -Force

    $credObject = New-Object System.Management.Automation.PSCredential ($msoluser, $secStringPassword)

} else {
    #$credObject = Get-AutomationPSCredential -Name $AutomationPSCredential    
}

# Testing and/or Creating Ressource Group

$rgs = Get-AzureRmResourceGroup 

foreach($rg in $rgs){ 
    if($rg.ResourceGroupName -eq $newRGName) {
    $existsRG = 1 
    } 
}

if($existsRG -eq 1){
    "Ressource Group already Exists, continuing ..."
}else {
    "Creating Ressource Group ..."
    New-AzureRMResourceGroup -Name $newRGName -Location $location
}

# Testing and/or Creating Storage Account

$sas = Get-AzureRmStorageAccount -ResourceGroupName $newRGName
foreach ($sa in $sas){
    if($sa.StorageAccountName -eq $storageAccountName){
        $existsSA = 1 
        $storageAccount = Get-AzureRmStorageAccount -ResourceGroupName $newRGName -AccountName $storageAccountName
    }
}

if($existsSA -eq 1){
    "Storage Account already exists, continuing ..."
} else {
    "Creating Storage Account ..."
    $storageAccount = New-AzureRmStorageAccount -ResourceGroupName $newRGName -Name $storageAccountName -SkuName Standard_LRS -Location $location 
}

$ctx = $storageAccount.Context

# Testing and/or Creating Storage Container
try {
    $containers = Get-AzureStorageContainer -Context $ctx -Name $containerName -ErrorAction silentlycontinue  

    foreach ($container in $containers){
        if($container.CloudBlobContainer.Name -eq $containerName){
            $existsContainer = 1 
        }
    }
} catch [Microsoft.WindowsAzure.Storage.StorageException] {
    "Container does not exists"
}

if($existsContainer -eq 1){
    "Storage Account already exists, continuing ..."
} else {
    "Creating Container ..."
    $Newcontainer = New-AzureStorageContainer -Name $containerName -Context $ctx -Permission blob
}

# Connecting to App Reg to get Token

"Getting Graph API output for " + $tenantName 
"Date Suffix : " + $dateSuffix 

$reqTokenBody = @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    client_Id     = $clientID
    Client_Secret = $clientSecret
} 

"Requesting Token ... " 

$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method POST -Body $reqTokenBody -UseBasicParsing

$ReqHeaders = @{
    Authorization = "Bearer $($tokenResponse.access_token)"
    'Content-Type' = "application\json"
}

if($licencesRatioBoolean -eq 1){

    Connect-MsolService -Credential $credObject

    $Availablelicences =  Get-MsolAccountSku | Select SKUPartNumber,ActiveUnits,ConsumedUnits,SkuId
    $availablelicencesFileName = "Availablelicences.json"
    $availablelicencesFile = New-Item -Force -ItemType File -Name $availablelicencesFileName
    $Availablelicences = ConvertTo-Json $Availablelicences | Out-File -FilePath $availablelicencesFile -Append
    Set-AzureStorageBlobContent -File $availablelicencesFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force   

    $availableSubscriptions = Get-MsolSubscription |Select ObjectId, DateCreated, IsTrial, NextLifecycleDate, OcpSubscriptionId, SKUPartNumber, Status, TotalLicenses
    $availableSubscriptionsFileName = "AvailableSubscriptions.json"
    $availableSubscriptionsFile = New-Item -Force -ItemType File -Name $availableSubscriptionsFileName
    $availableSubscriptions = ConvertTo-Json $availableSubscriptions | Out-File -FilePath $availableSubscriptionsFile -Append
    Set-AzureStorageBlobContent -File $availableSubscriptionsFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force     

}

# Generate User File with Odata Link

        $usersExtensionUrl = $apiUrlBeta + "/users?`$select=displayName,UserPrincipalName,companyName,Id,extension_4a304a434e9c489eabbe56158cd30a6c_division,country,signInActivity" 
        # id,UserPrincipalName,displayName,givenName,surname,usageLocation,mail,Department,jobTitle,signInSessionsValidFromDateTime,userType,accountEnabled,createdDateTime,deletedDateTime,creationType,proxyAddresses,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesImmutableId,assignedLicenses,assignedPlans,signInActivity,companyName,country,extension_4a304a434e9c489eabbe56158cd30a6c_division" 
        # #,extension_4a304a434e9c489eabbe56158cd30a6c_division

$usersExtensionUrl

<# Clean Folder Before Exec #> 

Get-AzureStorageBlob -Container $containerName -Context $storageAccount.Context -Blob users_details_* | Remove-AzureStorageBlob

if($usersBoolean -eq 1){

    $userslist = @()
    $i = 1 
    $x = 0 
    $Listiterator = 0 

    "Browsing Users in AD ..." 

    while($i -eq 1){
        $usersData = Invoke-RestMethod -Headers $ReqHeaders -Uri $usersExtensionUrl -Method Get
        $userslist += $usersData

        if($usersData.'@odata.nextLink'){
            $usersExtensionUrl = $usersData.'@odata.nextLink'
        } else {
            "All users have been parsed"
            $i = 0 
        }
        $Listiterator = $Listiterator + 1 

        if(($Listiterator -eq 20) -or ($i -eq 0) ){
            $userFileName = "users_details_{0}.json" -f $x
            $userFile = New-Item -Force -ItemType File -Name $userFileName
            $users = ConvertTo-Json $userslist.value | Out-File -FilePath $userFile -Append

            Set-AzureStorageBlobContent -File $userFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

            $userslist = @()
            $x = $x + 1 
            $Listiterator = 0 
        }
    }
}

$usersLicensesUrl = $apiUrlBeta + "/users?`$select=Id,assignedLicenses"
# id,UserPrincipalName,displayName,givenName,surname,usageLocation,mail,Department,jobTitle,signInSessionsValidFromDateTime,userType,accountEnabled,createdDateTime,deletedDateTime,creationType,proxyAddresses,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesImmutableId,assignedLicenses,assignedPlans,signInActivity,companyName,country,extension_4a304a434e9c489eabbe56158cd30a6c_division" 
# #,extension_4a304a434e9c489eabbe56158cd30a6c_division

$usersLicensesUrlUrl

if($usersLicensesBoolean -eq 1){

    $usersLicenseslist = @()
    $i = 1 
    $x = 0 
    $Listiterator = 0 

    "Browsing usersLicenses in AD ..." 

    while($i -eq 1){
        $usersLicensesData = Invoke-RestMethod -Headers $ReqHeaders -Uri $usersLicensesUrl -Method Get
        $usersLicenseslist += $usersLicensesData

        if($usersLicensesData.'@odata.nextLink'){
            $usersLicensesUrl = $usersLicensesData.'@odata.nextLink'
        } else {
            "All usersLicenses have been parsed"
            $i = 0 
        }
        $Listiterator = $Listiterator + 1 

        if(($Listiterator -eq 20) -or ($i -eq 0) ){
            $userFileName = "usersLicenses_{0}.json" -f $x
            $userFile = New-Item -Force -ItemType File -Name $userFileName
            $usersLicenses = ConvertTo-Json $usersLicenseslist.value | Out-File -FilePath $userFile -Append

            Set-AzureStorageBlobContent -File $userFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

            $usersLicenseslist = @()
            $x = $x + 1 
            $Listiterator = 0 
        }
    }
}

#$groupsUrl = $apiUrlBeta + "/groups?`$filter=resourceProvisioningOptions/any(c:c+eq+'Team')&`$select=displayName,id,resourceProvisioningOptions,createdDateTime" 
$groupsUrl = $apiUrlBeta + "/groups?`$select=displayName,id,resourceProvisioningOptions,createdDateTime" 

"Requesting Token ... " 

$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method POST -Body $reqTokenBody -UseBasicParsing

$ReqHeaders = @{
    Authorization = "Bearer $($tokenResponse.access_token)"
    'Content-Type' = "application\json"
}

# If boolean groups is activated
if($groupsBoolean -eq 1){

    $groupslist = @()
    $i = 1  
    $x = 0 
    $Listiterator = 0 

    while($i -eq 1){

        $groupsData = Invoke-RestMethod -Headers $ReqHeaders -Uri $groupsUrl -Method Get
        $groupIds = $groupsData.value.id 

        # Foreach groups in the list, browse attributes
        foreach($groupId in $groupIds){
            
            $isTeam = $groupsData.value | where { $_.id -eq $groupId } 
            
            if($isTeam.resourceProvisioningOptions -eq "Team") {

                # Get all members of the group
                $membersUrl = $apiUrlOne + "/groups/{$groupId}/members?`$select=id"            
                $memberslist = @()
                $mi = 1

                # While odata list of members is not empty
                while($mi -eq 1){

                    $membersData = Invoke-RestMethod -Headers $ReqHeaders -Uri $membersUrl -Method Get
                    $memberslist += $membersData.value.id

                    if($membersData.'@odata.nextLink'){
                        $membersUrl = $membersData.'@odata.nextLink'
                    } else {
                        $mi = 0 
                    }
                }

                $ownersUrl = $apiUrlOne + "/groups/{$groupId}/owners?`$select=id"

                $ownerslist = @()
                $oi = 1

                # While odata list of owners is not empty 
                while($oi -eq 1){

                    $ownersData = Invoke-RestMethod -Headers $ReqHeaders -Uri $ownersUrl -Method Get
                    
                    $ownerslist += $ownersData.value.id
                    
                    if($ownersData.'@odata.nextLink'){
                        $ownersUrl = $ownersData.'@odata.nextLink'
                    } else {
                        $oi = 0 
                    }
                }


                # If the group is a team
                if($channelsBoolean -eq 1){  
                    $teamGroupChannelUrl = $apiUrlBeta + "/teams/{$groupId}/channels?`$select=id,displayName"
                    $teamGroupChannellist = @()

                    $ci = 1 

                    # While odata list of teams channel is not empty
                    while($ci -eq 1){
                            
                        $teamGroupChannelData = Invoke-RestMethod -Headers $ReqHeaders -Uri $teamGroupChannelUrl -Method Get

                        if($teamGroupChannelData.'@odata.nextLink'){
                            $teamGroupChannelUrl = $teamGroupChannelData.'@odata.nextLink'
                        } else {
                            $ci = 0
                        }
                    }

                    $teamGroupChannellist += $teamGroupChannelData.value

                    $groupsData.value | where { $_.id -eq $groupId } | Add-Member -Name "channels" -value $teamGroupChannelList -MemberType NoteProperty 
                }    
            }
            else {
                $memberslist = @()
                $ownerslist = @()
            }
            #Add members to corresponding team 
            $groupsData.value | where { $_.id -eq $groupId } | Add-Member -Name "members" -value $memberslist -MemberType NoteProperty
            $groupsData.value | where { $_.id -eq $groupId } | Add-Member -Name "owners" -value $ownerslist -MemberType NoteProperty

        }

        $groupslist += $groupsData

        if($groupsData.'@odata.nextLink'){
            $groupsUrl = $groupsData.'@odata.nextLink'
        } else {
            $i = 0 
        }


        $Listiterator = $Listiterator + 1 

        if(($Listiterator -eq 10) -or ($i -eq 0) ){
            
            $groupsFileName = "groups_{0}.json" -f $x
            $groupsFile = New-Item -Force -ItemType File -Name $groupsFileName
            $groups = ConvertTo-Json $groupslist.value | Out-File -FilePath $groupsFile -Append
            Set-AzureStorageBlobContent -File $groupsFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

            $groupslist = @()
            $x = $x + 1 
            $Listiterator = 0 
        }

    }
}

$groupsAssignedLicensesUrl = $apiUrlBeta + "/groups?`$select=id,assignedLicenses" 

"Requesting Token ... " 

$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method POST -Body $reqTokenBody -UseBasicParsing

$ReqHeaders = @{
    Authorization = "Bearer $($tokenResponse.access_token)"
    'Content-Type' = "application\json"
}


# If boolean groups Licenses is activated
if($groupsLicensesBoolean -eq 1){

    $groupsLicenseslist = @()
    $i = 1  
    $x = 0 
    $Listiterator = 0 


    while($i -eq 1){

        $groupsLicensesData = Invoke-RestMethod -Headers $ReqHeaders -Uri $groupsAssignedLicensesUrl -Method Get

        $groupsLicenseslist += $groupsLicensesData

        if($groupsLicensesData.'@odata.nextLink'){
            $groupsAssignedLicensesUrl = $groupsLicensesData.'@odata.nextLink'
        } else {
            $i = 0 
        }


        $Listiterator = $Listiterator + 1 

        if(($Listiterator -eq 10) -or ($i -eq 0) ){
            
            $groupsLicensesFileName = "groupsLicenses_{0}.json" -f $x
            $groupsLicensesFile = New-Item -Force -ItemType File -Name $groupsLicensesFileName
            $groupsLicenses = ConvertTo-Json $groupsLicenseslist.value | Out-File -FilePath $groupsLicensesFile -Append
            Set-AzureStorageBlobContent -File $groupsLicensesFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

            $groupsLicenseslist = @()
            $x = $x + 1 
            $Listiterator = 0 
        }

    }
}
