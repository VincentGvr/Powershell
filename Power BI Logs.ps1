Function WriteFileToBlob($obj, $filename, $type) {

	Write-Output $filename
#   $filePath = "$env:temp\" + $filename 				# azure function	
	$filePath = ("C:\temp\dev\" + $filename)		 	#autacc

	if($type -eq "json"){
		$obj | ConvertTo-Json | Out-File -FilePath $filePath						# automation account
	} elseif($type -eq "csv") {
		$obj | Export-Csv -Path $filePath -NoTypeInformation -Encoding UTF8 
	} else {
		$obj | Out-File -FilePath $filePath
	}

	Set-AzStorageBlobContent -Container $containerName -File $filePath -Context $storageContext -Force # automation account
	Remove-Item -Path $filePath -Force
	$obj = @()
# 	Set-AzStorageBlobContent -Container $containerName -File $filePath -Blob $filename -Context $storageContext # azure function

}

Function GetFileAz($fileName){
	try {
    	Get-AzStorageBlobContent -Container $containerName -Blob $fileName -Context $storageContext -Destination ("C:\temp\dev\" + $fileName) -ErrorAction Stop
		return (Get-Content -Path ("C:\temp\dev\" + $fileName)) | ConvertFrom-Json 
	} catch {
		$body = @{
				"modifiedSince" = 0 
			} | ConvertTo-Json
		return $body

	}
}

Function GetLastModifiedDate($fileName){
    try{
        $json = GetFileAz -fileName $fileName
        return $json.modifiedSince
    } catch {
        return 0
    }
}

Function GetPbiToken($appi, $appscr, $tntId){

	$appscr = ConvertTo-SecureString -String $appscr -AsPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential($appi,$appscr)
    Connect-PowerBIServiceAccount -Tenant $tntId -ServicePrincipal -Credential ($credentials)
	
	<# Authenticate with REST API 
		$reqTokenBody = @{
			Grant_Type    = "client_credentials"
			Scope         = "https://graph.microsoft.com/.default"
			client_Id     = $clientID
			Client_Secret = $clientSecret
		} 

		"Requesting Token ... " 

		$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $reqTokenBody -UseBasicParsing

		$ReqHeaders = @{
			Authorization = "Bearer $($tokenResponse.access_token)"
			'Content-Type' = "application\json"
		}
	#> 

}

Function main($start){

	New-Item -ItemType Directory -Path "C:\temp\dev\"

	#Scripts Parameters 
	$keyVaultBoolean 	= 0
	$testInventory 		= 0
	$testAuditLogs 		= 1
	$testUsers 			= 0
	$testGroups 		= 0

	$DaystoGet 			= 12												# TO MODIFY ACCORDING TO USECASE
	$intervalMinutes  	= 60 # 1440 for a full day 

	# Azure Resource Names  
	$tenantId 			= "" 			# TO COMPLETE
	$subscription 		= ""			# TO COMPLETE
	$resourceGroup 		= ""                                         # TO COMPLETE
	$storageAccountName = ""                             	# TO COMPLETE
	$containerName 		= ""                      				# TO COMPLETE
	$keyVaultName 		= ""										# TO COMPLETE
	
	if($keyVaultBoolean -eq 1){
		$secretNameAppSecret 	= ""                         # TO COMPLETE
		$secretNameAppId 		= "" 							# TO COMPLETE
	}

	$connectionName = "AzureRunAsConnection"
	$servicePrincipalConnection = Get-AutomationConnection -Name $connectionName
	Connect-AzAccount -ServicePrincipal -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint 

	Set-AzContext -Subscription $subscription

	$storAccKeys = Get-AzStorageAccountKey -ResourceGroupName $resourceGroup -Name $storageAccountName
	$primaryKey = $storAccKeys | Where-Object keyname -eq 'key1' | Select-Object -ExpandProperty value

	$storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $primaryKey

	try {
		New-AzStorageContainer -Name $containerName -Context $storageContext -ErrorAction Stop
	} catch [Microsoft.WindowsAzure.Commands.Storage.Common.ResourceAlreadyExistException] {
		Write-Output ('Container {0} already exists in Storage Account {1}' -f $containerName, $storageAccountName)
	} catch {
		throw $_
	}

	if($keyVaultBoolean -eq 1){
		$appSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretNameAppSecret -AsPlainText
		$appId = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretNameAppId -AsPlainText
	}

	$skip = 0

	$output = @()
	$usersPS = @()
	$prepUsers = @()

	#GetPbiToken($appId, $appSecret, $tenantId)

	$appSecretSec = ConvertTo-SecureString -String $appSecret -AsPlainText -Force
	$credentials = New-Object System.Management.Automation.PSCredential($appId,$appSecretSec)
	Connect-PowerBIServiceAccount -Tenant $tenantId -ServicePrincipal -Credential ($credentials)

	if($testInventory -eq 1){

		$capacitiesList = @()
		$capacitiesAdminList = @()

		$capacitiesURI = "https://api.powerbi.com/v1.0/myorg/admin/capacities" 

		$capacities = Invoke-PowerBIRestMethod -Url $capacitiesURI -Method GET  | ConvertFrom-Json 

		$capacitiesList += $capacities.value      | Select-Object @{N='capacityId'; E={$_.Id}}, id, displayName,sku,state,capacityUserAccessRight,region
		$capacitiesAdminList += $capacities.value | Select-Object @{N='capacityId'; E={$_.Id}}, admins -ExpandProperty admins -ExcludeProperty admins

		WriteFileToBlob -obj $capacitiesList 		-filename "capacities.json" 		-type "json"
		WriteFileToBlob -obj $capacitiesAdminList  	-filename "capacitiesAdmin.json"  	-type "json"

        <#$lastModifiedDateFile = "LastWorkspaceExtractionDate.json"
    
        $Lastdate = GetLastModifiedDate -filename $lastModifiedDateFile

        if(($Lastdate -ne 0) -and ($Lastdate -ne "0") -and ($Lastdate -ne $null)){
            $url = "https://api.powerbi.com/v1.0/myorg/admin/workspaces/modified?modifiedSince=" + $Lastdate.ToString("yyyy-MM-ddT00:00:00") + ".0000000Z&excludePersonalWorkspaces=True"
        } else { #>
            $url = "https://api.powerbi.com/v1.0/myorg/admin/workspaces/modified?excludePersonalWorkspaces=True"
        #}

		$wks = Invoke-PowerBIRestMethod -Url $url -Method GET | ConvertFrom-Json 

		$skip = 100 

		$totalValues = $wks.Count

		Write-Host "Total Values " $wks.Count -ForegroundColor Cyan

		$totalBatches =  $totalValues / $skip

		$i = 0

		While($i -lt $totalBatches){
			$i 
			$from = $i * $skip
			$to = (($i + 1) * $skip) - 1 
			if($to -gt $totalValues) { $to = $totalValues }
			Write-Host $from " to " $to 

			$body = @{
				"workspaces" = $wks[$from..$to].Id 
			} | ConvertTo-Json 

			$scanIdUrl = "https://api.powerbi.com/v1.0/myorg/admin/workspaces/getInfo?lineage=True&datasourceDetails=True&datasetSchema=False&datasetExpressions=False&getArtifactUsers=True"

			$scan = Invoke-PowerBIRestMethod -Url $scanIdUrl -Method POST -Body $body | ConvertFrom-Json   

			$scanStatusUrl = "https://api.powerbi.com/v1.0/myorg/admin/workspaces/scanStatus/" + $scan.id 

			$scanStatus = @() 

			Add-Member -InputObject $scanStatus -NotePropertyName Status -NotePropertyValue KO

			For($j = 0; $j -lt 10; $j ++){

				if($scanStatus.status -eq "Succeeded"){

				$scanResultUrl =  "https://api.powerbi.com/v1.0/myorg/admin/workspaces/scanResult/" + $scan.id 
				$scanResult = Invoke-PowerBIRestMethod -Url $scanResultUrl -Method GET

				WriteFileToBlob -obj $scanResult -filename ("scanResult_" + (get-date).ToString("yyyy_MM_dd") + "_$i.json") -type "other"

				if($testGroups -eq 1){
						$usersPS += $prepUsers.workspaces.users
						$usersPS += $prepUsers.workspaces.datasets.users
						$usersPS += $prepUsers.workspaces.reports.users
						$usersPS += $prepUsers.workspaces.dataflows.users
				}

				Write-Host "File has been processed" -ForeGroundColor Cyan
				break 
				} else {
				
					Write-Host "status is not succeeded" -ForeGroundColor Yellow

					$scanstatus = Invoke-PowerBIRestMethod -Url $scanStatusUrl -Method GET | ConvertFrom-Json

					Write-Host "Sleep 10 seconds"
					Start-Sleep -s 10
				}
			}
			$i += 1
		}

		if($totalValues -gt 0){
			$lastModifiedDateObj =  @{
				"modifiedSince" = (get-date).ToString("yyyy-MM-ddT00:00:00")+ ".0000000Z"
			}

			WriteFileToBlob -obj $lastModifiedDateObj -filename $lastModifiedDateFile -type "json"
		}
		
		Get-AzStorageBlob -Container $containerName -Context $storageContext -Prefix scanResult_ | Where-Object {$_.Name.Substring(0,21) -ne ("scanResult_" + (get-date).ToString("yyyy_MM_dd"))} | Remove-AzStorageBlob

		$groupsToGraph = $usersPS | Where-Object principalType -eq "Group" | Select-Object graphId -Unique 

		Foreach($capa in $capacities.value){
			$id = $capa.Id

			$refreshURI = "https://api.powerbi.com/v1.0/myorg/admin/capacities/$id/refreshables?`$expand=capacity,group"
			
			$i = 1
			$x = 1

			while($i -eq 1){
				if($capa.Sku -eq "PP3") {
					Write-Host "   Premium Per User - not in scope"
					$i = 0 
				} elseif ($capa.Sku.Substring(0,1) -eq "A"){
					Write-Host "   Embedded Capacities - not in scope"
					$i = 0 
				} else {
					if($SPAuthent -eq 1){
	#                    $refreshables = Invoke-RestMethod -Uri $refreshURI -Headers $getContentHeader -Method GET
						$refreshables = Invoke-PowerBIRestMethod -Url $refreshURI -Method GET | ConvertFrom-Json 
					} else {
						$refreshables = Invoke-PowerBIRestMethod -Url $refreshURI -Method GET | ConvertFrom-Json 
					}


					WriteFileToBlob -obj $refreshables.value -filename ($pathFile + "refreshables_" + $id + "_" + $x + ".json") -type "json"

					if($refreshables.'@odata.nextLink'){
						$refreshURI = $refreshables.'@odata.nextLink'
					} else {
						$i = 0 
					}
				}
			}
			$x += 1
		}

		Write-Host "Retrieving Refreshables Done !"
		
		$pipelinesURI = "https://api.powerbi.com/v1.0/myorg/admin/pipelines?`$expand=users,stages"
							
		$i = 1

		while($i -eq 1){
			if($SPAuthent -eq 1){
				#$pipelines = Invoke-RestMethod -Uri $pipelinesURI -Headers $getContentHeader -Method GET
				$pipelines = Invoke-PowerBIRestMethod -Url $pipelinesURI -Method GET | ConvertFrom-Json 
			} else {
				$pipelines = Invoke-PowerBIRestMethod -Url $pipelinesURI -Method GET | ConvertFrom-Json 
			}

			$pipeUsers = $pipelines.value   | Select-Object @{N='pipelineId'; E={$_.Id}}, users     -ExpandProperty users   -ExcludeProperty users
			$pipeStages = $pipelines.value  | Select-Object @{N='pipelineId'; E={$_.Id}}, stages    -ExpandProperty stages  -ExcludeProperty stages 
			$pipes =  $pipelines.value      | Select-Object @{N='pipelineId'; E={$_.Id}}, *                                 -ExcludeProperty users, stages 
			
			WriteFileToBlob -obj $pipeUsers -filename "pipelines_users.json" -type "json"
			WriteFileToBlob -obj $pipeStages -filename "pipelines_stages.json" -type "json"
			WriteFileToBlob -obj $pipes -filename "pipelines.json" -type "json"

			if($pipelines.'@odata.nextLink'){
				$pipelines = $pipelines.'@odata.nextLink'
			} else {
				$i = 0 
			}
	} 
	}

	if($testAuditLogs -eq 1){

		$continue = 1

		$oldestDay = -($DaystoGet)
		$oldestDayPlusOne = $oldestDay + 1 

		while ($oldestDay -lt 0) {
			
			[DateTime] $start = (get-date).AddDays($oldestDay).ToString("MM/dd/yyyy")
			[DateTime] $end = (get-date).AddDays($oldestDayPlusOne).ToString("MM/dd/yyyy")
			[DateTime] $currentStart = $start
			[DateTime] $currentEnd = $start
			
			$dailyLogs = @()

			$fileName = "AuditLogs" + $currentStart.ToString("yyyyMMdd") + ".csv"
			while ($continue -eq 1) {

				$currentEnd = $currentStart.AddMinutes($intervalMinutes)

				Write-Host "Retrieving logs between $currentStart and $currentEnd"

				if(($currentEnd.Hour -eq 0)){
					$output = Get-PowerBIActivityEvent -StartDateTime $currentStart.ToString("yyyy-MM-ddTHH:mm:ss") -EndDateTime $currentEnd.AddSeconds(-1).ToString("yyyy-MM-ddTHH:mm:ss") | ConvertFrom-Json
				} else {
					$output = Get-PowerBIActivityEvent -StartDateTime $currentStart.ToString("yyyy-MM-ddTHH:mm:ss") -EndDateTime $currentEnd.ToString("yyyy-MM-ddTHH:mm:ss") | ConvertFrom-Json
				}
		
				# Do not delete : get activity by API and not with Power BI Powershell commands 
				# $ActivityURI = "https://api.powerbi.com/v1.0/myorg/admin/activityevents?startDateTime='" + $currentStart.ToString("yyyy-MM-ddTHH:mm:ss")+ ".000Z'&endDateTime='" + $currentEnd.ToString("yyyy-MM-ddTHH:mm:ss") + ".000Z'"
				# $output = Invoke-RestMethod -Uri $ActivityURI -Headers $getContentHeader -Method GET
				# $output =  $output.activityEventEntities
				
				$dailyLogs += $output | Select-Object RecordType, CreationTime, UserId, UserAgent, Activity, CapacityId, WorkspaceId, ObjectId, DatasetId, ReportId, DataConnectivityMode,ConsumptionMethod #, DashboardId
				$currentStart = $currentEnd
				
				if ($currentEnd -ge $end ) {
					$continue = 0 
				}
	
			}
			
			WriteFileToBlob -obj $dailyLogs -filename $fileName -type "csv"

			$dailyLogs = @()

			$oldestDay = $oldestDay + 1 
			$oldestDayPlusOne = $oldestDay +1 
			$continue = 1
		}

	}

	if($testUsers -eq 1){
		<# Get Azure AD Info via API #> 

				if($keyVaultBoolean -eq 1){
					$appSecret = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretNameAppSecret -AsPlainText
					$appId = Get-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretNameAppId -AsPlainText
				}

			$ReqTokenBody = @{
				grant_Type    = "client_credentials"
				scope         = "https://graph.microsoft.com/.default"
				client_Id     = $appId
				client_Secret = $appSecret
			} 

			$TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody -UseBasicParsing
		
			$ReqHeaders = @{
				Authorization = "Bearer $($TokenResponse.access_token)"
				"ContentType" = "application\json"
			}

		<#$skuList = @()
		$skuList += "f8a1db68-be16-40ed-86d5-cb42ce701560" #(Pro)
		$skuList += "a403ebcc-fae0-4ca2-8c8c-7a907fd6c235" #(Free) 
		$skuList += "45bc2c81-6072-436a-9b0b-3b12eefbc402" #(O365 Addon) 

		foreach($skuId in $skuList) {#>
			#$skuId = "f8a1db68-be16-40ed-86d5-cb42ce701560"
			#$usersUrl = "https://graph.microsoft.com/beta/users?&`$filter=assignedLicenses/any(x:x/skuId eq $skuId)&`$select=id,UserPrincipalName,assignedLicenses" 
			
			$usersUrl = "https://graph.microsoft.com/v1.0/users?&`$select=UserPrincipalName,id,mail,assignedLicenses,companyName"

			$userslist = @()
			$i = 1 
			$x = 0 
			$Listiterator = 0 

			Write-Host "Retrieving Users from Azure AD ..." 

			$booloo = 1 

			while($booloo -eq 1){

				$usersData = Invoke-RestMethod -Headers $ReqHeaders -Uri $usersUrl -Method Get
				
				$userslist += $usersData.value | Select-Object UserPrincipalName, id, mail, assignedLicenses, companyName

				if($usersData.'@odata.nextLink'){
					$usersUrl = $usersData.'@odata.nextLink'
				} else {
					"All users have been parsed"
					$booloo = 0 
				}
				$Listiterator = $Listiterator + 1 

				if(($Listiterator -eq 100) -or ($booloo -eq 0) ){

					$userFileName = "usersAD_{0}.json" -f $x

					WriteFileToBlob -obj $userslist -filename $userFileName -type "json"

					$userslist = @()
					$x = $x + 1 
					$Listiterator = 0 
				}
			}
		#}
	}

	if($testGroups -eq 1){
		#$apiUrlBeta = 'https://graph.microsoft.com/beta'
		$apiUrlOne = 'https://graph.microsoft.com/v1.0'

		$reqTokenBody = @{
			grant_Type    = "client_credentials"
			scope         = "https://graph.microsoft.com/.default"
			client_Id     = $appId
			client_Secret = $appSecret
		} 

		"Requesting Token ... " 

		$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Method POST -Body $reqTokenBody -UseBasicParsing

		$ReqHeaders = @{
			Authorization = "Bearer $($tokenResponse.access_token)"
			"ContentType" = "application\json"
		}

		#$groupsUrl = $apiUrlBeta + "/groups?`$select=displayName,id,resourceProvisioningOptions,createdDateTime" 

		$groupslist = @()
		$i = 1  
		$x = 0 
		$Listiterator = 0 

		while($i -eq 1){

	#        $groupsData = Invoke-RestMethod -Headers $ReqHeaders -Uri $groupsUrl -Method Get
	#        $groupIds = $groupsData.value.id 

			# Foreach groups in the list, browse attributes
			foreach($groupId in $groupsToGraph.graphId){
					
					$groupsUrl = $apiUrlOne + "/groups/{" + $groupId + "}?`$select=displayName,id,resourceProvisioningOptions,createdDateTime" 
					Try {
						$groupsData = Invoke-RestMethod -Headers $ReqHeaders -Uri $groupsUrl -Method Get

						# Get all members of the group
						$membersUrl = $apiUrlOne + "/groups/{" + $groupId + "}/members?`$select=id"            
						$memberslist = @()
						$mi = 1

						# While odata list of members is not empty
						while($mi -eq 1){
							Try {
								$membersData = Invoke-RestMethod -Headers $ReqHeaders -Uri $membersUrl -Method Get -ErrorAction SilentlyContinue 
							} Catch {
								$err = $_
								$membersData = @()
								Write-Host $err 
							}
							$memberslist += $membersData.value.id

							if($membersData.'@odata.nextLink'){
								$membersUrl = $membersData.'@odata.nextLink'
							} else {
								$mi = 0 
							}
						}

						$ownersUrl = $apiUrlOne + "/groups/{" + $groupId + "}/owners?`$select=id"

						$ownerslist = @()
						$oi = 1

						# While odata list of owners is not empty 
						while($oi -eq 1){
							Try {
								$ownersData = Invoke-RestMethod -Headers $ReqHeaders -Uri $ownersUrl -Method Get -ErrorAction SilentlyContinue 
							} Catch {
								$err = $_
								$ownersData = @()
							}
							
							$ownerslist += $ownersData.value.id
					
							if($ownersData.'@odata.nextLink'){
								$ownersUrl = $ownersData.'@odata.nextLink'
							} else {
								$oi = 0 
							}
						}

					#Add members to corresponding team 
					$groupsData | Where-Object { $_.id -eq $groupId } | Add-Member -Name "members" -value $memberslist -MemberType NoteProperty
					$groupsData | Where-Object { $_.id -eq $groupId } | Add-Member -Name "owners" -value $ownerslist -MemberType NoteProperty
					$groupslist += $groupsData
					
				} Catch {
					$err = $_
				}
			}
					
			if($groupsData.'@odata.nextLink'){
				$groupsUrl = $groupsData.'@odata.nextLink'
			} else {
				$i = 0 
			}

			$Listiterator = $Listiterator + 1

			if(($Listiterator -eq 10) -or ($i -eq 0) ){
			
				$groupsFileName = $pathFile + "groups_{0}.json" -f $x
				
				WriteFileToBlob -obj $groupslist -filename $groupsFileName -type "json"

				$groupslist = @()
				$x = $x + 1 
				$Listiterator = 0 
			}

		}
	}
}

main -start "start"
