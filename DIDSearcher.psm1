function Show-Hierarchy {
    <#
.SYNOPSIS
Displays an object's values and the 'dot' paths to them

.DESCRIPTION
A detailed description of the Display-Object function.

.PARAMETER TheObject
The object that you wish to display

.PARAMETER depth
the depth of recursion (keep it low!)

.PARAMETER Avoid
an array of names of objects or arrays you wish to avoid.

.PARAMETER Parent
For internal use, but you can specify the name of the variable

.PARAMETER CurrentDepth
For internal use

.NOTES
https://www.red-gate.com/simple-talk/blogs/display-object-a-powershell-utility-cmdlet/
#>

    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true)]
        $TheObject,
        [int]$depth = 5,
        [Object[]]$Avoid = @('#comment'),
        [string]$Parent = '$',
        [int]$CurrentDepth = 0
    )

    if (($CurrentDepth -ge $Depth) -or ($nulll -eq $TheObject)) { 
        return 
    } #prevent runaway recursion
    $ObjectTypeName = $TheObject.GetType().Name #find out what type it is
    if ($ObjectTypeName -in 'HashTable', 'OrderedDictionary') {
        #If you can, force it to be a PSCustomObject
        $TheObject = [pscustomObject]$TheObject;
        $ObjectTypeName = 'PSCustomObject'
    } #first do objects that cannot be treated as an array.
    if ($TheObject.Count -le 1 -and $ObjectTypeName -ne 'object[]') {
        #not something that behaves like an array
        # figure out where you get the names from
        if ($ObjectTypeName -in @('PSCustomObject')) {
            # Name-Value pair properties created by Powershell  
            $MemberType = 'NoteProperty' 
        }
        else { 
            $MemberType = 'Property' 
        }
        #now go through the names 
        $TheObject | Get-Member -MemberType $MemberType | Where-Object { $_.Name -notin $Avoid } | ForEach-Object {
            Try { 
                $child = $TheObject.($_.Name) 
            }
            Catch { 
                $Child = $null 
            } # avoid crashing on write-only objects
            $brackets = ''
            if ($_.Name -like '*.*') { 
                $brackets = "'" 
            }
            if ($null -eq $child -or #is the current child a value or a null?
                $child.GetType().BaseType.Name -eq 'ValueType' -or
                $child.GetType().Name -in @('String', 'String[]')) { 
                [pscustomobject]@{ 
                    'Path'  = "$Parent.$brackets$($_.Name)$brackets"
                    'Value' = $Child 
                } 
            }
            elseif (($CurrentDepth + 1) -eq $Depth) {
                [pscustomobject] @{
                    'Path'  = "$Parent.$brackets$($_.Name)$brackets"
                    'Value' = $Child 
                }
            }
            else {
                #not a value but an object of some sort
                Show-Hierarchy -TheObject $child -depth $Depth -Avoid $Avoid `
                    -Parent "$Parent.$brackets$($_.Name)$brackets" `
                    -CurrentDepth ($currentDepth + 1)
            }
        }
    }
    else {
        #it is an array
        if ($TheObject.Count -gt 0) {
            0..($TheObject.Count - 1) | ForEach-Object {
                $child = $TheObject[$_];
                if (($null -eq $child) -or #is the current child a value or a null?
    ($child.GetType().BaseType.Name -eq 'ValueType') -or
    ($child.GetType().Name -in @('String', 'String[]'))) {
                    #if so display it 
                    [pscustomobject]@{ 
                        'Path'  = "$Parent[$_]"
                        'Value' = "$($child)" 
                    } 
                }
                elseif (($CurrentDepth + 1) -eq $Depth) {
                    [pscustomobject]@{ 
                        'Path'  = "$Parent[$_]"
                        'Value' = "$($child)" 
                    }
                }
                else {
                    #not a value but an object of some sort so do a recursive call
                    Show-Hierarchy -TheObject $child -depth $Depth -Avoid $Avoid -parent "$Parent[$_]" `
                        -CurrentDepth ($currentDepth + 1)
                }
  
            }
        }
        else { 
            [pscustomobject]@{ 
                'Path'  = "$Parent"
                'Value' = $Null 
            } 
        }
    }
}


function Get-DIDJWTDetails {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string]$token
    )

    <#
.SYNOPSIS

Decode a JWT Access Token and convert to a PowerShell Object.
JWT Access Token updated to include the JWT Signature (sig), JWT Token Expiry (expiryDateTime) and JWT Token time to expiry (timeToExpiry).

.DESCRIPTION

Decode a JWT Access Token and convert to a PowerShell Object.
JWT Access Token updated to include the JWT Signature (sig), JWT Token Expiry (expiryDateTime) and JWT Token time to expiry (timeToExpiry).

.PARAMETER token

The JWT Access Token to decode and udpate with expiry time and time to expiry

.INPUTS

Token from Pipeline 

.OUTPUTS

PowerShell Object

.SYNTAX

Get-DIDJWTDetails(linked_did)

.EXAMPLE

PS> Get-DIDJWTDetails('eyJ0eXAiOi........XmN4GnWQAw7OwMA')
or
PS> 'eyJ0eXAiOi........XmN4GnWQAw7OwMA' | Get-DIDJWTDetails

.LINK

https://blog.darrenjrobinson.com
https://blog.darrenjrobinson.com/jwtdetails-powershell-module-for-decoding-jwt-access-tokens-with-readable-token-expiry-time/ 

#>

    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

    # Token
    foreach ($i in 0..1) {
        $data = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($data.Length % 4) {
            0 { break }
            2 { $data += '==' }
            3 { $data += '=' }
        }
    }

    $decodedToken = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json 
    Write-Verbose "JWT Token:"
    Write-Verbose $decodedToken

    # Signature
    foreach ($i in 0..2) {
        $sig = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($sig.Length % 4) {
            0 { break }
            2 { $sig += '==' }
            3 { $sig += '=' }
        }
    }
    Write-Verbose "JWT Signature:"
    Write-Verbose $sig
    $decodedToken | Add-Member -Type NoteProperty -Name "sig" -Value $sig

    # Convert Expiry time to PowerShell DateTime
    $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $utcTime = $orig.AddSeconds($decodedToken.exp)
    $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
    $localTime = $utcTime.AddMinutes($offset)     # Return local time,
    
    $decodedToken | Add-Member -Type NoteProperty -Name "expiryDateTime" -Value $localTime
    
    # Time to Expiry
    $timeToExpiry = ($localTime - (get-date))
    $decodedToken | Add-Member -Type NoteProperty -Name "timeToExpiry" -Value $timeToExpiry

    return $decodedToken
}


function Search-DecentralizedIdentifier {
    <#
    .SYNOPSIS
    Search the ION and Web network for DIDs to discover their keys and endpoints
    
    .DESCRIPTION
    Search the ION and Web network for DIDs to discover their keys and endpoints
    
    .PARAMETER ION
    (optional) Search the ION network
    
   .PARAMETER Web
    (optional - default) Search the Web 

    .EXAMPLE
    Search-DecentralizedIdentifier -Web -FQDN "https://identity.foundation" 
    Search-DecentralizedIdentifier -Web -FQDN "https://identity.foundation/.well-known/did.json" 
    Search-DecentralizedIdentifier -Web -FQDN "https://identity.foundation" -outputHierarchy
    Search-DecentralizedIdentifier -ION -identifier 'EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJh_Diw' 
    Search-DecentralizedIdentifier -ION -identifier 'EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJh_Diw' -outputHierarchy
    
    .LINK
    http://darrenjrobinson.com/
    
    #>
    
    [cmdletbinding(DefaultParameterSetName = 'Web')]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = 'ION')]
        [switch]$ION,
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ParameterSetName = 'Web')]
        [switch]$Web, 
        [Parameter(Mandatory = $true, ParameterSetName = 'ION')]
        [string]$identifier,
        [Parameter(Mandatory = $true, ParameterSetName = 'Web')]
        [System.Uri]$FQDN,
        [Parameter(ParameterSetName = 'ION')]
        [Parameter(ParameterSetName = 'Web')]
        [switch]$outputHierarchy
    )

    try {
        $result = $null 
        if ($ION) {
            $result = (Invoke-RestMethod -Uri "https://beta.discover.did.microsoft.com/1.0/identifiers/did:ion:$($identifier)").didDocument
        }
        elseif ($Web) {
            if ($FQDN.Segments.Count -gt 1) {
                $result = Invoke-RestMethod -Uri $FQDN.AbsoluteUri
            }
            else {
                try {
                    $result = Invoke-RestMethod -Uri "$($FQDN.AbsoluteUri).well-known/did.json"
                } catch {
                    $result = Invoke-RestMethod -Uri "$($FQDN.AbsoluteUri).well-known/did-configuration.json"
                }
            }
        }
        else {
            Write-Output "Specify option -Web (and FQDN) or -ION (and Identifier) to perform DID search."
        }

        if ($outputHierarchy) {
            return $result | Show-Hierarchy
        }
        else {
            return $result
        }
    }
    catch {
        Write-Error $PSItem.Exception.Message
    }
}

# SIG # Begin signature block
# MIINSwYJKoZIhvcNAQcCoIINPDCCDTgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUzrVFVuYyTkRW6s7hHccGNiTF
# DuagggqNMIIFMDCCBBigAwIBAgIQBAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0B
# AQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMTMxMDIyMTIwMDAwWhcNMjgxMDIyMTIwMDAwWjByMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQg
# Q29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# +NOzHH8OEa9ndwfTCzFJGc/Q+0WZsTrbRPV/5aid2zLXcep2nQUut4/6kkPApfmJ
# 1DcZ17aq8JyGpdglrA55KDp+6dFn08b7KSfH03sjlOSRI5aQd4L5oYQjZhJUM1B0
# sSgmuyRpwsJS8hRniolF1C2ho+mILCCVrhxKhwjfDPXiTWAYvqrEsq5wMWYzcT6s
# cKKrzn/pfMuSoeU7MRzP6vIK5Fe7SrXpdOYr/mzLfnQ5Ng2Q7+S1TqSp6moKq4Tz
# rGdOtcT3jNEgJSPrCGQ+UpbB8g8S9MWOD8Gi6CxR93O8vYWxYoNzQYIH5DiLanMg
# 0A9kczyen6Yzqf0Z3yWT0QIDAQABo4IBzTCCAckwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMweQYIKwYBBQUH
# AQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYI
# KwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaG
# NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0
# dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCgYIYIZIAYb9bAMwHQYDVR0OBBYE
# FFrEuXsqCqOl6nEDwGD5LfZldQ5YMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQA+7A1aJLPzItEVyCx8JSl2qB1dHC06
# GsTvMGHXfgtg/cM9D8Svi/3vKt8gVTew4fbRknUPUbRupY5a4l4kgU4QpO4/cY5j
# DhNLrddfRHnzNhQGivecRk5c/5CxGwcOkRX7uq+1UcKNJK4kxscnKqEpKBo6cSgC
# PC6Ro8AlEeKcFEehemhor5unXCBc2XGxDI+7qPjFEmifz0DLQESlE/DmZAwlCEIy
# sjaKJAL+L3J+HNdJRZboWR3p+nRka7LrZkPas7CM1ekN3fYBIM6ZMWM9CBoYs4Gb
# T8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIFVTCC
# BD2gAwIBAgIQDOzRdXezgbkTF+1Qo8ZgrzANBgkqhkiG9w0BAQsFADByMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBMB4XDTIwMDYxNDAwMDAwMFoXDTIzMDYxOTEyMDAwMFowgZEx
# CzAJBgNVBAYTAkFVMRgwFgYDVQQIEw9OZXcgU291dGggV2FsZXMxFDASBgNVBAcT
# C0NoZXJyeWJyb29rMRowGAYDVQQKExFEYXJyZW4gSiBSb2JpbnNvbjEaMBgGA1UE
# CxMRRGFycmVuIEogUm9iaW5zb24xGjAYBgNVBAMTEURhcnJlbiBKIFJvYmluc29u
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwj7PLmjkknFA0MIbRPwc
# T1JwU/xUZ6UFMy6AUyltGEigMVGxFEXoVybjQXwI9hhpzDh2gdxL3W8V5dTXyzqN
# 8LUXa6NODjIzh+egJf/fkXOgzWOPD5fToL7mm4JWofuaAwv2DmI2UtgvQGwRhkUx
# Y3hh0+MNDSyz28cqExf8H6mTTcuafgu/Nt4A0ddjr1hYBHU4g51ZJ96YcRsvMZSu
# 8qycBUNEp8/EZJxBUmqCp7mKi72jojkhu+6ujOPi2xgG8IWE6GqlmuMVhRSUvF7F
# 9PreiwPtGim92RG9Rsn8kg1tkxX/1dUYbjOIgXOmE1FAo/QU6nKVioJMNpNsVEBz
# /QIDAQABo4IBxTCCAcEwHwYDVR0jBBgwFoAUWsS5eyoKo6XqcQPAYPkt9mV1Dlgw
# HQYDVR0OBBYEFOh6QLkkiXXHi1nqeGozeiSEHADoMA4GA1UdDwEB/wQEAwIHgDAT
# BgNVHSUEDDAKBggrBgEFBQcDAzB3BgNVHR8EcDBuMDWgM6Axhi9odHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLWNzLWcxLmNybDA1oDOgMYYvaHR0
# cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwTAYD
# VR0gBEUwQzA3BglghkgBhv1sAwEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cu
# ZGlnaWNlcnQuY29tL0NQUzAIBgZngQwBBAEwgYQGCCsGAQUFBwEBBHgwdjAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tME4GCCsGAQUFBzAChkJo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElE
# Q29kZVNpZ25pbmdDQS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOC
# AQEANWoHDjN7Hg9QrOaZx0V8MK4c4nkYBeFDCYAyP/SqwYeAtKPA7F72mvmJV6E3
# YZnilv8b+YvZpFTZrw98GtwCnuQjcIj3OZMfepQuwV1n3S6GO3o30xpKGu6h0d4L
# rJkIbmVvi3RZr7U8ruHqnI4TgbYaCWKdwfLb/CUffaUsRX7BOguFRnYShwJmZAzI
# mgBx2r2vWcZePlKH/k7kupUAWSY8PF8O+lvdwzVPSVDW+PoTqfI4q9au/0U77UN0
# Fq/ohMyQ/CUX731xeC6Rb5TjlmDhdthFP3Iho1FX0GIu55Py5x84qW+Ou+OytQcA
# FZx22DA8dAUbS3P7OIPamcU68TGCAigwggIkAgEBMIGGMHIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25p
# bmcgQ0ECEAzs0XV3s4G5ExftUKPGYK8wCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcC
# AQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYB
# BAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFP0qX4b8u/At
# +3ezHIYCeb3R88ruMA0GCSqGSIb3DQEBAQUABIIBAHh6YInxdf9sr2czr+ZFq4Ro
# aLxzzJv1UDGnz2x7/YfJCpydXwzIJWadm+lc8p0Pyy0bKtT3WBm7RnroRsdfuqzE
# GTTATubkxURqiGrfJfE4kWwQlw1B+/HYGvhLCnaeWrjRaIIjY6uoo8CJk40uGOyj
# TaejdhIANukLE6y5IPkA9ZJx18BAtFGyq50nInmjtHrkgcYRf6DImMSGvyzIWuxE
# 392gXTYy8ZOXR69pRkLZj76Vj1kUu6u+LnQBtJyO7ZIbRK67FLY6d5RjmyTvL08k
# 4b6pxfsfs7xnyC55GN9IzjxkTcoYLvrg+ca9NV3TKBEriKjYNG93QCcnyZve02U=
# SIG # End signature block
