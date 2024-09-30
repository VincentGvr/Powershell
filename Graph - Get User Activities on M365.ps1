<# Defining Variables #>

# Azure Connection 
$connectionName = "AzureRunAsConnection"

# Booleans for existance of resource 
$existsRG = 0                           # Do not change (verify if Ressource Group exists) 
$existsSA = 0                           # Do not change (verify if Storage Account exists)
$existsContainer = 0                    # Do not change (verify if Blob container  exists)

$keyVaultBoolean = 1                    # If KeyVault is used, then 1 else Secret 0 
$graphLogsBoolean = 1                   # If graph API consumption details and counts is enable, 1 else 0 
$historicalBoolean = 1                  # If historical details must be updated 1, eles 0 

# Azure Resource Names  
$newRGName =   ""
$location = ""                                         # TO COMPLETE
$storageAccountName = ""                             # TO COMPLETE
$containerName = ""                              # TO COMPLETE

#Infos for App Registration in Azure  
$clientId =  ""              # TO COMPLETE
$tenantName = ""                 # TO COMPLETE

if($keyVaultBoolean -eq 1){
    $keyVaultName = ""                                        # TO COMPLETE
    $secretName = ""                                    # TO COMPLETE
}
#Graph API URL  
$resource = "https://graph.microsoft.com/"
$apiUrlBeta = 'https://graph.microsoft.com/beta'
$apiUrlOne = 'https://graph.microsoft.com/v1.0'
#Requests properties
$period = "D90"
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
"Period : " + $period 

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

if($graphLogsBoolean -eq 1){
    # Exchange & Mailbox 
    $arrSet = @("getEmailActivityUserDetail","getEmailActivityCounts","getEmailActivityUserCounts","getEmailAppUsageUserDetail","getEmailAppUsageAppsUserCounts","getEmailAppUsageUserCounts","getEmailAppUsageVersionsUserCounts","getMailboxUsageDetail","getMailboxUsageMailboxCounts","getMailboxUsageStorage")

    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/beta/reports/{0}(period='{1}')" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing

        $DataFileName = "{0}_{1}.csv" -f $arr, $dateSuffix
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

    }

    # Office groups 365 

    $apiUrlBeta = 'https://graph.microsoft.com/v1.0'
    $arrSet = @("getOffice365GroupsActivityDetail","getOffice365GroupsActivityCounts","getOffice365GroupsActivityGroupCounts","getOffice365GroupsActivityStorage","getOffice365GroupsActivityFileCounts")

    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/beta/reports/{0}(period='{1}')" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing
        
        $DataFileName = "{0}_{1}.csv" -f $arr, $dateSuffix
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

    }

    # OneDrive

    $arrSet = @("getOneDriveActivityUserDetail","getOneDriveActivityUserCounts","getOneDriveActivityFileCounts","getOneDriveUsageAccountDetail","getOneDriveUsageAccountCounts","getOneDriveUsageFileCounts","getOneDriveUsageStorage")

    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/beta/reports/{0}(period='{1}')" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing
        
        $DataFileName = "{0}_{1}.csv" -f $arr, $dateSuffix
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

    }

    # Sharepoint

    $arrSet = @("getSharePointActivityUserDetail","getSharePointActivityFileCounts","getSharePointActivityUserCounts","getSharePointActivityPages","getSharePointSiteUsageDetail","getSharePointSiteUsageFileCounts","getSharePointSiteUsageSiteCounts","getSharePointSiteUsageStorage","getSharePointSiteUsagePages")

    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/beta/reports/{0}(period='{1}')" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing

        $DataFileName = "{0}_{1}.csv" -f $arr, $dateSuffix
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

    }

    # Skype For Business

    $arrSet = @("getSkypeForBusinessActivityUserDetail","getSkypeForBusinessActivityCounts","getSkypeForBusinessActivityUserCounts","getSkypeForBusinessDeviceUsageUserDetail","getSkypeForBusinessDeviceUsageDistributionUserCounts","getSkypeForBusinessDeviceUsageUserCounts","getSkypeForBusinessOrganizerActivityCounts","getSkypeForBusinessOrganizerActivityUserCounts","getSkypeForBusinessOrganizerActivityMinuteCounts","getSkypeForBusinessParticipantActivityCounts","getSkypeForBusinessParticipantActivityUserCounts","getSkypeForBusinessParticipantActivityMinuteCounts","getSkypeForBusinessPeerToPeerActivityCounts","getSkypeForBusinessPeerToPeerActivityUserCounts","getSkypeForBusinessPeerToPeerActivityMinuteCounts")

    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/beta/reports/{0}(period='{1}')" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing

        $DataFileName = "{0}_{1}.csv" -f $arr, $dateSuffix
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

    }

    # O365 

    $arrSet = @("getOffice365ActivationsUserDetail","getOffice365ActivationCounts","getOffice365ActivationsUserCounts")

    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/v1.0/reports/{0}" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing

        $DataFileName = "{0}_{1}.json" -f $arr, $dateSuffix
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

    }

    # Yammer

    $arrSet = @("getYammerActivityUserDetail","getYammerActivityCounts","getYammerActivityUserCounts","getYammerDeviceUsageUserDetail","getYammerDeviceUsageDistributionUserCounts","getYammerDeviceUsageUserCounts","getYammerGroupsActivityDetail","getYammerGroupsActivityGroupCounts","getYammerGroupsActivityCounts")

    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/beta/reports/{0}(period='{1}')" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing

        $DataFileName = "{0}_{1}.csv" -f $arr, $dateSuffix
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

    }

    # Teams 

    $arrSet = @("getTeamsDeviceUsageUserDetail","getTeamsDeviceUsageUserCounts","getTeamsDeviceUsageDistributionUserCounts","getTeamsUserActivityUserDetail","getTeamsUserActivityCounts","getTeamsUserActivityUserCounts")

    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/beta/reports/{0}(period='{1}')" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing

        $DataFileName = "{0}_{1}.csv" -f $arr, $dateSuffix
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

    } 

    $arrSet = @("getOffice365ActiveUserDetail", "getOffice365ActiveUserCounts", "getOffice365ServicesUserCounts") 
    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/beta/reports/{0}(period='{1}')" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing
            
        $DataFileName = "{0}_{1}.csv" -f $arr, $dateSuffix        
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force
    } 

    # Applications

    $ReqHeaders = @{
        Authorization = "Bearer $($tokenResponse.access_token)"
        'Content-Type' = "text/csv"
    }

    $arrSet = @("getM365AppUserDetail","getM365AppUserCounts","getM365AppPlatformUserCounts")
    foreach($arr in $arrset){

        $uri = "https://graph.microsoft.com/beta/reports/{0}(period='{1}')/content" -f $arr, $period
        $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing

        $DataFileName = "{0}_{1}.csv" -f $arr, $dateSuffix 
        $DataFile = New-Item -Force -ItemType File -Name $DataFileName
        $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
        Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Force

    }
}

if($historicalBoolean -eq 1){

    $dateListsFileName = "Datelist.json"
    $dateListsFile = Get-AzureStorageBlobContent -Container $containerName -Context $storageAccount.Context -Blob $dateListsFileName -Destination "./$dateListsFileName"  | Where {$_.Name -eq $dateListsFileName}

    $dateListsFile

    if(-not $dateListsFile ){
        $dateList = @()
    } else {
        $dateList = Get-Content -Path "./$dateListsFileName" | ConvertFrom-Json
    }

    $dateSuffix 
    $todayDateTime = [datetime]::parseexact($dateSuffix, 'yyyyMMdd', $null) 

    $maxdate = $todayDateTime.AddDays(-11)

    Foreach($date in $dateList){
        $lastDate = [datetime]::parseexact($date.ToString(), 'yyyy-MM-dd', $null)
        if($lastDate -gt $maxdate){
            $maxdate = $lastDate
        }
    }

    $maxdate = $maxdate.AddDays(1)
    $APICallsList = @()

    while($maxdate -lt $todayDateTime.AddDays(-4)){
        $APICallsList += $maxdate
        $maxdate = $maxdate.AddDays(1)
    }

    Foreach($date in $APICallsList){
        
        "Requesting Token ... " 

        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantName/oauth2/v2.0/token" -Method POST -Body $reqTokenBody -UseBasicParsing

        $ReqHeaders = @{
            Authorization = "Bearer $($tokenResponse.access_token)"
            'Content-Type' = "application\json"
        }

        Start-Sleep -s 10
        $arrSet = @("getM365AppUserDetail","getOneDriveActivityUserDetail","getOneDriveUsageAccountDetail",  "getOffice365GroupsActivityDetail"  ,"getEmailAppUsageUserDetail", "getOffice365ActiveUserDetail","getTeamsUserActivityUserDetail","getTeamsDeviceUsageUserDetail","getSharePointSiteUsageDetail","getSharePointActivityUserDetail","getYammerGroupsActivityDetail","getYammerActivityUserDetail","getEmailActivityUserDetail","getSkypeForBusinessActivityUserDetail")
        #getOffice365ActivationsUserDetail cannot be historized. It is only the last snapshot. "getMailboxUsageDetail also, there is no slice per day per users."        
        
        foreach($arr in $arrset){

            $uri = "https://graph.microsoft.com/beta/reports/{0}(date={1})" -f $arr, $date.ToString('yyyy-MM-dd')
            $uri

            $Datas = Invoke-RestMethod -Headers $ReqHeaders -Uri $uri -Method Get -UseBasicParsing

            $DataFileName = "histo_{0}_{1}.csv" -f $arr, $date.ToString('yyyy_MM_dd')
            $DataFile = New-Item -Force -ItemType File -Name $DataFileName
            $Datas = $Datas.ToString().Replace("ï»¿","") | Out-File -FilePath $DataFile -Append
            Set-AzureStorageBlobContent -File $DataFile -Container $containerName -BlobType "Block" -Context $ctx -Force

        }
    }
    
    Foreach($date in $APICallsList){
        $scope = $date.ToString('yyyy-MM-dd')
        $dateList += $date.ToString('yyyy-MM-dd')
    }

    $newDateListFile = New-Item -Force -ItemType File -Name $dateListsFileName
    $dateList | ConvertTo-Json | Out-File $newDateListFile -Append
    Set-AzureStorageBlobContent -File $newDateListFile -Container $containerName -BlobType "Block" -Context $ctx -Verbose -Force

}
