Connect-MSGraph

$tenantId = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
$appId = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
$appSecret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

$resourceAppIdUri = 'https://api-gcc.securitycenter.microsoft.us'
$oAuthUri = "https://login.microsoftonline.com/$TenantId/oauth2/token"
## body for authenticating for a token
$body = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}

## Getting an access token

$response = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $body -ErrorAction Stop

$aadToken = $response.access_token

#Get list of devices and details from Intune

$machines = Get-IntuneManagedDevice -filter "operatingSystem eq 'ios'"  | select DeviceName, AzureADdeviceID, managedDeviceOwnerType 

Foreach ($machine in $machines)

{

#Comment sleep statement out if only planning to modify a small number of devices

 
Start-Sleep -Seconds 3

$url = "https://api-gcc.securitycenter.microsoft.us/api/machines/" +($machine).azureADDeviceID+ "/tags"

$headers = @{
    'Content-Type' = 'application/json'
     Accept = 'application/json'
     Authorization = "Bearer $aadToken"
     }
## Setting available tags to be used in the script
$tag= @{

  'Value' = ($machine).deviceName

  'Action' = 'Add'

}
$tag2= @{

  'Value' = 'Supervised'

  'Action' = 'Add'

}
$tag3= @{

  'Value' = 'Unsupervised'

  'Action' = 'Add'
}


#Output

$body3 = ConvertTo-Json -InputObject $tag

$webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body3 -ErrorAction Stop

## This section looks at the owner type and if it is company marks the device as Supervised in MDE.
if (($machine).managedDeviceOwnerType -eq "company")
{
$body4 = ConvertTo-Json -InputObject $tag2
$webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body4 -ErrorAction Stop
}
## This section will mark devices that are not listed as company owned as Unsupervised, this would also catch devices that are marked as "unknown". Uncomment to use this section.
if (($machine).managedDeviceOwnerType -eq "personal")
{
$body5 = ConvertTo-Json -InputObject $tag3
$webResponse = Invoke-WebRequest -Method Post -Uri $url -Headers $headers -Body $body5 -ErrorAction Stop
}


}