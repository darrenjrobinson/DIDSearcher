# Decentralized Identity PowerShell Module #

[![PSGallery Version](https://img.shields.io/powershellgallery/v/DIDSearcher.svg?style=flat&logo=powershell&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/DIDSearcher) [![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/DIDSearcher.svg?style=flat&logo=powershell&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/DIDSearcher)

## Description ##

A PowerShell Module enabling simple methods for searching the ION and Web networks for DIDs to discover their keys and endpoints.

## Installation ##

* From an Admin PowerShell session, install from the PowerShell Gallery

```powershell
install-module -name DIDSearcher
```

or download from the [PowerShell Gallery](https://www.powershellgallery.com/packages/DIDSearcher)

## Examples ##

### DID ION Network ###

Search the ION network using a DID to discover its keys and endpoints

```powershell
Search-DecentralizedIdentifier -ION -identifier 'EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJBh_Diw' | FL 
```

### Output ###

```powershell
id                 : did:ion:EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJBh_Diw
@context           : {https://www.w3.org/ns/did/v1, @{@base=did:ion:EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJBh_Diw}}
verificationMethod : {@{id=#key-1; controller=did:ion:EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJBh_Diw; type=EcdsaSecp256k1VerificationKey2019; publicKeyJwk=}}
authentication     : {#key-1}
```

Search the ION network using a DID to discover its keys and endpoints and output the document elements and heirarchy

```powershell
Search-DecentralizedIdentifier -ION -identifier 'EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJBh_Diw' -outputHierarchy
```

### Output ###

```powershell
Path                                     Value
----                                     -----
$.@context[0]                            https://www.w3.org/ns/did/v1
$.@context[1].@base                      did:ion:EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJBh_Diw
$.authentication[0]                      #key-1
$.id                                     did:ion:EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJBh_Diw
$.verificationMethod[0].controller       did:ion:EiB29JB4R0mbLmJ6_BEYjr8bGZKEPABwFopSNsDJBh_Diw
$.verificationMethod[0].id               #key-1
$.verificationMethod[0].publicKeyJwk.crv secp256k1
$.verificationMethod[0].publicKeyJwk.kty EC
$.verificationMethod[0].publicKeyJwk.x   70EFbTwnhjbsbcJl0Fja5OOPOfDTrlaqX2J_iXvxRRE
$.verificationMethod[0].publicKeyJwk.y   eWsMq6eJ-wpdIUGAMGTAdefazBH4sQMvuRo3U_mzM4o
$.verificationMethod[0].type             EcdsaSecp256k1VerificationKey2019
```

### DID Web ###

Get info from a DID Web document using the default-ish paths of *https://{FQDN}/.well-known/did.json* or *https://{FQDN}/.well-known/did-configuration.json*

By default *https://{FQDN}/.well-known/did.json* is tried first. If not present *https://{FQDN}/.well-known/did-configuration.json* is tried. 

```powershell
Search-DecentralizedIdentifier -Web -FQDN "https://identity.foundation" 
```

### Output ###

```powershell
@context : {https://www.w3.org/ns/did/v1}
id       : did:web:identity.foundation

```

In this instance Identity.Foundation has both a did.json and a did-configuration.json document. We can thereby call explicitly the .well-known/did-configuration.json document.

```powershell
Search-DecentralizedIdentifier -Web -FQDN "https://identity.foundation/.well-known/did-configuration.json" | Format-List
```

### Output ###

```powershell
@context    : https://identity.foundation/.well-known/did-configuration/v1
linked_dids : {@{@context=System.Object[]; issuer=did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM; issuanceDate=5/12/2020 7:08:28 AM; expirationDate=5/12/2025 7:08:28 AM; type=System.Object[]; credentialSubject=; proof=}, eyJhbGciOiJFZERTQSJ9.eyJleHAiOjE3NjQ4Nzg5MDgsImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNTA4LCJzdWIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cHM6Ly9pZGVudGl0eS5mb3VuZGF0aW9uLy53ZWxsLWtub3duL2RpZC1jb25maWd1cmF0aW9uL3YxIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImlkIjoiZGlkOmtleTp6Nk1rb1RIc2dOTnJieThKekNOUTFpUkx5VzVRUTZSOFh1dTZBQThpZ0dyTVZQVU0iLCJvcmlnaW4iOiJpZGVudGl0eS5mb3VuZGF0aW9uIn0sImV4cGlyYXRpb25EYXRlIjoiMjAyNS0xMi0wNFQxNDowODoyOC0wNjowMCIsImlzc3VhbmNlRGF0ZSI6IjIwMjAtMTItMDRUMTQ6MDg6MjgtMDY6MDAiLCJpc3N1ZXIiOiJkaWQ6a2V5Ono2TWtvVEhzZ05OcmJ5OEp6Q05RMWlSTHlXNVFRNlI4WHV1NkFBOGlnR3JNVlBVTSIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJEb21haW5MaW5rYWdlQ3JlZGVudGlhbCJdfX0.6ovgQ-T_rmYueviySqXhzMzgqJMAizOGUKAObQr2iikoRNsb8DHfna4rh1puwWqYwgT3QJVpzdO_xZARAYM9Dw}
```

Get info from a DID web document and output the DID document elements and heirarchy

```powershell
Search-DecentralizedIdentifier -Web -FQDN "https://identity.foundation/.well-known/did-configuration.json" -outputHierarchy 
```

### Output ###

```powershell
Path                                      Value
----                                      -----
$.@context                                https://identity.foundation/.well-known/did-configuration/v1
$.linked_dids[0].@context[0]              https://www.w3.org/2018/credentials/v1
$.linked_dids[0].@context[1]              https://identity.foundation/.well-known/did-configuration/v1
$.linked_dids[0].credentialSubject.id     did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM
$.linked_dids[0].credentialSubject.origin https://identity.foundation
$.linked_dids[0].expirationDate           5/12/2025 7:08:28 AM
$.linked_dids[0].issuanceDate             5/12/2020 7:08:28 AM
$.linked_dids[0].issuer                   did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM
$.linked_dids[0].proof.created            4/12/2020 8:08:28 PM
$.linked_dids[0].proof.jws                eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..D0eDhglCMEjxDV9f_SNxsuU-r3ZB9GR4vaM9TYbyV7yzs1WfdUyYO8rFZdedHbwQafYy8YOpJ1iJlkSmB4JaDQ
$.linked_dids[0].proof.proofPurpose       assertionMethod
$.linked_dids[0].proof.type               Ed25519Signature2018
$.linked_dids[0].proof.verificationMethod did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM#z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM
$.linked_dids[0].type[0]                  VerifiableCredential
$.linked_dids[0].type[1]                  DomainLinkageCredential
$.linked_dids[1]                          eyJhbGciOiJFZERTQSJ9.eyJleHAiOjE3NjQ4Nzg5MDgsImlzcyI6ImRpZDprZXk6ejZNa29USHNnTk5yYnk4SnpDTlExaVJMeVc1UVE2UjhYdXU2QUE4aWdHck1WUFVNIiwibmJmIjoxNjA3MTEyNTA4LCJzdWIiOiJkaΓÇª
```

Get info from a DID Web document providing the FQDN and path.

```powershell
Search-DecentralizedIdentifier -Web -FQDN "https://identity.foundation/.well-known/mydid.json" 
```

```powershell
Search-DecentralizedIdentifier -Web -FQDN "https://identity.foundation:9000/user/alice/did.json" 
```

## Decode a DID JWT ##

Decode a linked DID JWT from a DID document.
This is based off my [JWTDetails](https://blog.darrenjrobinson.com/jwtdetails-powershell-module-for-decoding-jwt-access-tokens-with-readable-token-expiry-time/) PowerShell Module. It also returns the expiryDateTime and timeToExpirey in as datetime elements in the PSObject.

```powershell
$didResult = Search-DecentralizedIdentifier -Web -FQDN "https://identity.foundation/.well-known/did-configuration.json"  
$didResult.linked_dids[1] | Get-DIDJWTDetails
```

### Output ###

```powershell
exp            : 1764878908
iss            : did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM
nbf            : 1607112508
sub            : did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM
vc             : @{@context=System.Object[]; credentialSubject=; expirationDate=5/12/2025 7:08:28 AM; issuanceDate=5/12/2020 7:08:28 AM; issuer=did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM; type=System.Object[]}
sig            : 6ovgQ+T/rmYueviySqXhzMzgqJMAizOGUKAObQr2iikoRNsb8DHfna4rh1puwWqYwgT3QJVpzdO/xZARAYM9Dw==
expiryDateTime : 5/12/2025 7:08:28 AM
timeToExpiry   : 1128.17:37:24.6985560
```

## Keep up to date ##

* [Visit my blog](https://blog.darrenjrobinson.com)
* [Follow darrenjrobinson on Twitter](https://twitter.com/darrenjrobinson)![](http://twitter.com/favicon.ico)
