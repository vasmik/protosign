/*
Package protosign provides the service-to-service trusted interaction tooling.

Overview

To improve the security in service-to-service interaction all the cross-service API calls should be executed
via trusted protocol with followed requirements:

	* All access tokens are signed with asymmetric encryption using the RS256 algorithm
		and represented in JWT format (https://tools.ietf.org/html/rfc7519)
	* All public keys of consumer services should be available for every target service in RO mode.
	* Token should contain information about:
		- consumer service name
		- subject service name
		- http method and path for the target endpoint
	* Token should have minimal acceptable live time (~1sec, potentially 10-100ms)

This combination can guarantee a decent security level for cross-service calls.
In the worst scenario if a private network is compromised and any token is exposed,
the violator can use this token for less than 1 second to call the same service to the same endpoint.

So, the most vulnerable endpoints are going to be ones which handle the methods with body (POST, PUT, PATCH)
because the request body is not signed. The expiration time becomes critical here and should be reduced to
possibly minimum value (potentially down to the range in 10-100ms).

Design

Typical services interaction schema:

	====================== PUBLIC_KEYS with R/O Access ========================
	service_1_rsa_public.pem
	service_2_rsa_public.pem
	---------------------------------------------------------------------------
	     ^                                              ^
	     |                                              |
	     |                                              |
	 ---------------------------                    ---------------------------
	| SERVICE_1                 | ===== JWT =====> | SERVICE_2                 |
	| service_1_rsa_private.pem |        |         | service_2_rsa_private.pem |
	 ---------------------------         |          ---------------------------
	                                     |
	                           ~~~~~~~~~~~~~~~~~~
	                         /  iss: service_1    \
	                        /   sub: service_2     \
	                       {    exp: 1623617697     } @ service_1_rsa_private.pem
	                        \   mtd: POST          /
	                         \  pth: /itm/123     /
	                           ~~~~~~~~~~~~~~~~~~

Example

Calling the service "service_2" by:

	POST /test/12345

Request headers:
	...
	Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJtdGQiOiJQT1NUIiwicHRoIjoiL3Rlc3QvMTIzNDUiLCJleHAi
	OjE2MjM2MTc2OTcsImlzcyI6ImFndyIsInN1YiI6ImhlbGxvIn0.NPHPuPiztTZE2eqJFxHZv1Ei94La7L7zNla1Ufc3-O518dJ3scVLZyjwHun
	k-yLfHxnlQNt6Vqj4Cp70KXNEYkeNBa8O0HyFSxt3wXQQoK4Xs3maUmasbCVGf6CZPsfnXUNaViFhahBBD4kLavNKfUDCLhPSjNsOIeWwLd6F6S
	_hVBeA1yTELIs3IhN6D23nX2h-UWaSUPJgT-Cr8CQUYt060OVPrYL9UXVkYNrdGVGhtpuC0WWiILH3t29deaggcWtvopXqRtjZTBN4xqOqdOh9f
	FT-gQCn_Qx2quGlVBt350WyphUbXtomngzIt1Y02mAVJF_g8ZyGsEyLK1nvQA
	...
	X-Request-Context: eyJpZGVudGl0eSI6eyJhY3RvciI6InNvbWUudXNlckBtZW5sb3NlY3VyaXR5LmNvbSIsInNlcnZpY2VzIjpbImhlbGxvI
	iwicG9saWN5IiwibG9nZmV0Y2giXX19
	X-Forwarded-For: 127.0.0.1
	X-Forwarded-Host: localhost:8080
	X-Origin-Host: localhost:10080
	X-Request-Id: f60fc069-2a6f-4b59-a8c7-99e8b554f080
	...

Token:
	eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJtdGQiOiJQT1NUIiwicHRoIjoiL3Rlc3QvMTIzNDUiLCJleHAiOjE2MjM2MTc2OTcsImlzcy
	I6ImFndyIsInN1YiI6ImhlbGxvIn0.NPHPuPiztTZE2eqJFxHZv1Ei94La7L7zNla1Ufc3-O518dJ3scVLZyjwHunk-yLfHxnlQNt6Vqj4Cp70K
	XNEYkeNBa8O0HyFSxt3wXQQoK4Xs3maUmasbCVGf6CZPsfnXUNaViFhahBBD4kLavNKfUDCLhPSjNsOIeWwLd6F6S_hVBeA1yTELIs3IhN6D23n
	X2h-UWaSUPJgT-Cr8CQUYt060OVPrYL9UXVkYNrdGVGhtpuC0WWiILH3t29deaggcWtvopXqRtjZTBN4xqOqdOh9fFT-gQCn_Qx2quGlVBt350W
	yphUbXtomngzIt1Y02mAVJF_g8ZyGsEyLK1nvQA

Token Header:
	{
		"alg": "RS256",
		"typ": "JWT"
	}

Token Body:
	{
		"mtd": "POST",             <-- should match request method
		"pth": "/test/12345",      <-- should match request path
		"exp": 1623617697,         <-- expiration time in 1 second after the issuing
		"iss": "service_1",        <-- consumer service to find public key
		"sub": "service_2"         <-- target service should match the service called
	}

Public Key:
	-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyp5kfDrjSBXgU0EySlWF
	8F6TA7CEa5OeJ48vyiuMlmwOKBFa/PDz1rDXGZpfNT9vieTQSB4J6p+SVr60KFbH
	8aI2cScb2YgXj5suHjSjLIdGnglZtUpGUF1nInsEMDUIdMNgKYSdvkuXbHTfVo0c
	AoGZQjobUFNEhVTSl9CAgj8Ew1uguR1Zzzw70MlqtRieFz5k3/8RWBQv55DB7pE+
	OGZHrtHOnhCeI+ARWx9W80uxrSjO/dryo2LX+VGsjew/jl3jEHzQ6xB7fyo8GDUf
	zwBfVVg33cfR+a9MOskJDHwWh6sJWO2VXbzrdJqL2DylTdH1YWL79muDUWBWK+1N
	xQIDAQAB
	-----END PUBLIC KEY-----


Target service should be able to:

	- validate token signature, using the issuer public key
	- check if the method and path values match the request
	- check the sub value matches the target service name


Components

Package provides set of components:

	- Token
		Helper module to extract authorization tokens

	- Keychain
		Provider for public RSA keys.
		Currently supported sources:
		- File
		- AWS S3 bucket

	- HTTP middleware helper
		Automatically checks access token using the Keychain
*/
package protosign
