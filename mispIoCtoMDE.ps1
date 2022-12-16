param (   

    [Parameter(Mandatory=$false)]
    [bool]$batchUpload = $false, 

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 500)]
    [int]$batchSize = 500,

    [Parameter(Mandatory=$true)]
    [ValidateSet('sha1','sha256')]                #Select which hash type to ingest this run
    [string]$hashFormat,

    [Parameter(Mandatory=$false)]
    [string]$mispServer = '0.0.0.0',               #MISP server IP address

    [Parameter(Mandatory=$false)]
    [string]$mispTag = 'tlp;red&&tlp;amber',            

    [Parameter(Mandatory=$false)]
    [string]$mispTime = '4d',

    [Parameter(Mandatory=$false)]
    [ValidateSet('Alert','AlertAndBlock','Allowed')]   #Validate that the input contains valid value
    [string]$atpAction = 'Alert',                         #Set default action to 'Alert'
    
    [Parameter(Mandatory=$false)]
    [string]$atpTitle = 'IoC from MISP', 
   
    [Parameter(Mandatory=$false)]
    [ValidateSet('Informational','Low','Medium','High')]   #Validate that the input contains valid value
    [string]$atpSeverity = 'Medium',                   #Set default severity to 'Medium'
    
    [Parameter(Mandatory=$false)]
    [string]$atpDescription = 'MISP Provided indicator',     

    [Parameter(Mandatory=$false)]
    [string]$atpRecommendedActions,     

    [Parameter(Mandatory=$false)]
    [string]$authKey = 'XXXXXXXXXXX', #Input MISP authkey
    
    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 30)]
    [string]$atpExpiration = 7                                #Set default expiration to 7 days
     
 )

$hashOutputFile = "./JSON_DATA.txt"

 ### Paste your own tenant ID here
$tenantId = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

 ### Paste your own app ID here
$appId = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

 ### Paste your own app keys here
$appSecret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

$securitycenterUrl = "https://api.securitycenter.windows.com/api/indicators"     

[datetime]$datetimeOffsetTest = [DateTime]::Now.AddDays($atpExpiration)


# ===================================================================

# Upload functions

# -------------------------------------------------------------------

function Upload-Indicator {

    param (   
        [Parameter(Mandatory=$true)]
        [string]$indicator, 

        [Parameter(Mandatory=$true)]
        [string]$token, 

        [Parameter(Mandatory=$false)]
        [int]$retry = 0

    )

    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token"
    }

    $body = 
        @{
	        indicatorValue = ($indicator|out-string).Trim()    
            indicatorType = $(if ($hashFormat -eq 'sha1') {"FileSha1"} else {"FileSha256"})
            expirationTime = $datetimeOffsetTest |  get-date -Format "yyyy-MM-ddTHH:mm:ssZ" 
            action = $atpAction
            title = $atpTitle 
            severity = $atpSeverity	
            description = $atpDescription 
            recommendedActions = $atpRecommendedActions 
        }

    $response = try {

            (Invoke-WebRequest -Method Post -Uri $securitycenterUrl -Body ($body | ConvertTo-Json) -Headers $headers -ErrorVariable ErrorBody -ErrorAction Stop)

        } catch [System.Net.WebException] {

            Write-Output("An exception was caught: $($_.Exception.Message)")

            $_.Exception.Response 
        }

    if(Get-Member -inputobject $response -name "BaseResponse" -Membertype Properties){
        $responseStatus = $response.BaseResponse.StatusCode
    } else {
        $responseStatus = $response.StatusCode
    }

    if ($responseStatus -ne 200) {

        #Check the response status code
        if($responseStatus -eq 409) {

            #If the indicatorValue is already in your Microsoft Defender ATP list with a different "action" field, it won't be submitted
            Write-Output("Indicator $indicator has a conflict")

        } elseif ($responseStatus -eq 429) {

# For some reason, the 429 response does not seem to have a Retry-After header.
#            $waitFor = $response.GetResponseHeader('Retry-After')
            $waitFor = 15

            if ($retry -lt 6) {

                Write-Output("Throttling; waiting for $waitFor seconds...")

                Start-Sleep -Second $waitFor

                Upload-Indicator -indicator $indicator -token $token -retry ($retry + 1)

            } else {

                Write-Output("Too many retries. Indicator upload failed with rate-limiting for: $indicator")

                return
            }
        }
        else {

            #Action failed for some reason
            Write-Output("Indicator $indicator failed to submit with status: " + $responseStatus)
        }
    }
    else {

        Write-Output("Indicator $indicator added OK")
    }

    return
}


# -------------------------------------------------------------------


function BatchUpload-Indicators {

    param (   
        [Parameter(Mandatory=$true)]
        [string[]]$indicatorArray, 

        [Parameter(Mandatory=$true)]
        [string]$token, 

        [Parameter(Mandatory=$false)]
        [int]$retry = 0

    )

    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token"
    }

    $innerList = New-Object System.Collections.Generic.List[System.Object]

    foreach ($indicator in $indicatorArray) {
        
        if (! $indicator.Startswith("#")) {
            $innerBody = 
                @{
	                indicatorValue = ($indicator|out-string).Trim()    
                    indicatorType = $(if ($hashFormat -eq 'sha1') {"FileSha1"} else {"FileSha256"})
                    expirationTime = $datetimeOffsetTest |  get-date -Format "yyyy-MM-ddTHH:mm:ssZ" 
                    action = $atpAction
                    severity = $atpSeverity	
                    title = $atpTitle 
                    description = $atpDescription 
                    recommendedActions = $atpRecommendedActions 
                }

            $innerList.Add($innerBody)
        }
    }

    if ($innerList.Count -gt 0) {

        $body =
            @{
                Indicators = $innerList.ToArray()
            }

        $batchUploadURL = $securitycenterUrl + '/import'

        $response = try {

                (Invoke-WebRequest -Method Post -Uri $batchUploadURL -Body ($body | ConvertTo-Json -Depth 2) -Headers $headers -ErrorAction Stop)

            } catch [System.Net.WebException] {

                Write-Output("An exception was caught: $($_.Exception.Message)")

                $_.Exception.Response 
            }

        if(Get-Member -inputobject $response -name "BaseResponse" -Membertype Properties){
            $responseStatus = $response.BaseResponse.StatusCode
        } else {
            $responseStatus = $response.StatusCode
        }

        if ($responseStatus -ne 200) {

            #Check the response status code
            if($responseStatus -eq 409) {

                #If the indicatorValue is already in your Microsoft Defender ATP list with a different "action" field, it won't be submitted
                Write-Output("Indicator batch has a conflict")

            } elseif ($responseStatus -eq 429) {

    # For some reason, the 429 response does not seem to have a Retry-After header.
    #            $waitFor = $response.GetResponseHeader('Retry-After')
                $waitFor = 15

                if ($retry -lt 6) {

                    Write-Output("Throttling; waiting for $waitFor seconds...")

                    Start-Sleep -Second $waitFor

                    Upload-Indicator -indicator $indicator -token $token -retry ($retry + 1)

                } else {

                    Write-Output("Too many retries. Indicator batch upload failed with rate-limiting of " + $innerList.Count +
                     " indicators starting: " + $innerList[0].indicatorValue)

                    return
                }
            }
            else {

                #Action failed for some reason
                Write-Output("Indicator batch failed to submit with status: $responseStatus")
                Write-Output $response
            }
        }
        else {

            $responseArray = (ConvertFrom-Json -InputObject $response.Content).value

            Write-Output("Wrote " + $responseArray.Count + " indicators starting: " + $innerList[0].indicatorValue)

            $failsList = New-Object System.Collections.Generic.List[System.Object]

            foreach ($thing in $responseArray) {
                if ($thing.isFailed) {

                    $failsList.Add(@($thing.indicator, $thing.failureReason))
                }
            }

            if ($failsList.Count -gt 0) {

                Write-Output("Failure to write indicators:")
                Write-Output($failsList.ToArray())
            }
        }
    }
    
    # Wait a second to rate-limit the batch submissions - should prevent us ever tripping too-many-requests.
    Start-Sleep -Second 1

    return
}


# ===================================================================

# Main body

# -------------------------------------------------------------------

# Authenticate with Security Center and get an authorisation token

$resourceAppIdUri = 'https://api.securitycenter.windows.com'
$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"

$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}

$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token


# -------------------------------------------------------------------

# Call MISP API and save result to JSON_DATA.txt


# Old-format hids interface
#$mispUrlString = 'https://' + $mispServer + '/events/hids/' + $hashFormat + '/download/' + $MISPTag + '/false/false/' + $MISPTime

# New REST interface
    $mispUrlString = 'https://' + $mispServer + '/attributes/restSearch/returnFormat:text/to_ids:0%7C%7C1/type:' +  $hashFormat + '/tags:' + $mispTag + '/publish_timestamp:' + $mispTime


$headers = @{
  'Accept' = 'application/json'
  'Content-Type' = 'application/json'
  'Authorization' = $authKey
}

$response = (Invoke-Webrequest -Headers $headers -Uri $mispUrlString -SkipCertificateCheck)

#Check the response status code
if ($response.StatusCode -ne 200) {

    Write-Output('MISP request failed with status: ' + $response.StatusCode)
    #MISP call failed
    return $false
}

Out-File -FilePath $hashOutputFile -InputObject $response.Content


# -------------------------------------------------------------------

# Build and call the MDATP indicators API with the data from MISP

$arrayOfIndicators = (($response.Content) -split '\r?\n' | Where { $_ -and $_.Trim() }).Trim()

Write-Output(" " + $arrayOfIndicators.Count + " lines returned from MISP.")

if ($batchUpload) {

    for ($i = 0; $i -lt $arrayOfIndicators.Count; $i+= $batchSize) {

        $j = $( if ($($i + $batchSize) -gt $arrayOfIndicators.Count) { ($arrayOfIndicators.Count - 1) } else { ($i + $batchSize - 1) } )

        # Clunky, but more intuitive than the raw 0-base index
        Write-Output($($i + 1) + " to " + $($j + 1) + " of " + $arrayOfIndicators.Count)

        BatchUpload-Indicators -indicatorArray $arrayOfIndicators[$i..$j] -token $token
    }
} else {

    #Call Microsoft Defender ATP API for each hash
    foreach ($indicator in $arrayOfIndicators) {

        #Ignore comments in the MISP-returned hashes data
        if (!($indicator.Startswith("#"))) {

            Upload-Indicator -indicator $indicator -token $token
        }
    }
}
