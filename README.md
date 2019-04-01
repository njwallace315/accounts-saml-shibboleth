# meteor-accounts-shibboleth
> A meteor accounts package for SAML/Shibboleth.

<!-- [![NPM Version][npm-image]][npm-url]
[![Build Status][travis-image]][travis-url]
[![Downloads Stats][npm-downloads]][npm-url] -->

This package configures a service provider to connect the meteor accounts package with a shibboleth Idp. 
It sends SSO and SLO requests with an HTTP-Redirect binding. 
It currently works when using [samltest.id](https://samltest.id/) as the identity provider. 
Please note that I am not a cryptographer. Until this package is subjected to code review you’ll need to use it at your own discretion. 


![](header.png)

## Installation

Inside your package:

```sh
meteor add meteor-accounts-shibboleth
meteor add accounts-password
```

## Settings

The follwing attributes must be present in meteor settings for this package to work:

- `spSamlCert` - * *Required* * - The public key for your service provider.
- `spSamlKey` - * *Required* * - The private key for your service provider.
- `entryPoint` - * *Required* * - The HTTP-Redirect bound SSO entry point for your Idp.
- `logoutUrl` - * *Required* * - The HTTP-Redirect bound SLO url for your Idp.
- `idpMetadataUrl` - * *Required* * - The url where your Idp's metadata file can be accessed.
- `idpCert` - * *Required* * - The public certificate that can be used to validate your Idp's signature.
- `issuer` - The url where your application is running. If not set, this will default to the ROOT_URL environment variable.

- `generateUsers` - (Boolean) When true, users who authenticate but do not have an entry in the Meteor Users collection will have an entry created.
- `authFields` - (Object) Contains a dbfield and fname that are used to customize the how the users colleciton is queried to find the authenticated user.
- `authFields.dbfield` - Key value of the query that matches a path on a meteor users object.
- `fname` - Key value that matches a path on the profile object constructed from the login response. A more detailed explination can be found in the 'notes' section below.

## Usage example

For an example I recommend you clone [a meteor example app]( https://github.com/meteor/simple-todos-react.git) and remove the accounts ui and add ‘login’ and ‘logout’ buttons with the following onClick handlers: 

```javascript
handleLogin = () => {
    const provider = 'shibboleth-idp'
    Meteor.loginWithSaml({ provider }, (err, result) => {
      if (err) {
        console.log(err)
      }
      // ...
    })
  }

handleLogout = () => {
  const provider = 'shibboleth-idp'
  Meteor.logoutWithSaml({ provider }, (err, result) => {
    if (err) {
      console.log(err)
    }
    // ...
  })
}
```

Before you can start configuring your service provider you will need to [generate a public/private key pair]( https://spaces.at.internet2.edu/display/InCFederation/Key+Generation). These will be spSamlCert/spSamlKey.

In in your server folder create a folder called 'lib' and in that folder create a file named 'settings.js'. and add the following code. 

```javascript
Meteor.settings = {
    "public": {
        "debug": true,
    },
    "saml": {
        "provider": "shibboleth-idp",
        "generateUsers": true,
        "authFields": {
          "dbname": "email.addresses",
          "fname": "email"
        },
        "spSamlCert": '-----BEGIN CERTIFICATE-----<Your public cert>-----END CERTIFICATE-----\n',
        "spSamlKey": "-----BEGIN RSA PRIVATE KEY-----<Your Private Cert>-----END RSA PRIVATE KEY-----\n",
        "entryPoint": "https://samltest.id/idp/profile/SAML2/Redirect/SSO",
        "logoutUrl": "https://samltest.id/idp/profile/SAML2/Redirect/SLO",
        "idpMetadataUrl": "https://samltest.id/saml/idp",
        "issuer": "your-domain.com",
        "idpCert": '-----BEGIN CERTIFICATE-----<samltest.id Idp signing cert>-----\n'
    }

}
```
Fill in spSamlCert and spSamlKey with the public/private keys that you generated. Replace issuer with your domain (I recommend using [ngrok](https://ngrok.com/) if you're using localhost).  

Finally add samltest's signing cert which can be found [here](https://samltest.id/download/) in the 'SAMLtest's Idp' section's connection information. Note that your keys should contain the all of the newline characters. I got tripped up on cert formatting a couple of times so I left samltest.id's current signing cert below as an example.

```javascript
"idpCert": '-----BEGIN CERTIFICATE-----\nMIIDEjCCAfqgAwIBAgIVAMECQ1tjghafm5OxWDh9hwZfxthWMA0GCSqGSIb3DQEB\nCwUAMBYxFDASBgNVBAMMC3NhbWx0ZXN0LmlkMB4XDTE4MDgyNDIxMTQwOVoXDTM4\nMDgyNDIxMTQwOVowFjEUMBIGA1UEAwwLc2FtbHRlc3QuaWQwggEiMA0GCSqGSIb3\nDQEBAQUAA4IBDwAwggEKAoIBAQC0Z4QX1NFKs71ufbQwoQoW7qkNAJRIANGA4iM0\nThYghul3pC+FwrGv37aTxWXfA1UG9njKbbDreiDAZKngCgyjxj0uJ4lArgkr4AOE\njj5zXA81uGHARfUBctvQcsZpBIxDOvUUImAl+3NqLgMGF2fktxMG7kX3GEVNc1kl\nbN3dfYsaw5dUrw25DheL9np7G/+28GwHPvLb4aptOiONbCaVvh9UMHEA9F7c0zfF\n/cL5fOpdVa54wTI0u12CsFKt78h6lEGG5jUs/qX9clZncJM7EFkN3imPPy+0HC8n\nspXiH/MZW8o2cqWRkrw3MzBZW3Ojk5nQj40V6NUbjb7kfejzAgMBAAGjVzBVMB0G\nA1UdDgQWBBQT6Y9J3Tw/hOGc8PNV7JEE4k2ZNTA0BgNVHREELTArggtzYW1sdGVz\ndC5pZIYcaHR0cHM6Ly9zYW1sdGVzdC5pZC9zYW1sL2lkcDANBgkqhkiG9w0BAQsF\nAAOCAQEASk3guKfTkVhEaIVvxEPNR2w3vWt3fwmwJCccW98XXLWgNbu3YaMb2RSn\n7Th4p3h+mfyk2don6au7Uyzc1Jd39RNv80TG5iQoxfCgphy1FYmmdaSfO8wvDtHT\nTNiLArAxOYtzfYbzb5QrNNH/gQEN8RJaEf/g/1GTw9x/103dSMK0RXtl+fRs2nbl\nD1JJKSQ3AdhxK/weP3aUPtLxVVJ9wMOQOfcy02l+hHMb6uAjsPOpOVKqi3M8XmcU\nZOpx4swtgGdeoSpeRyrtMvRwdcciNBp9UZome44qZAYH1iqrpmmjsfI9pJItsgWu\n3kXPjhSfj1AJGR1l9JGvJrHki1iHTA==\n-----END CERTIFICATE-----\n'
```

in server/main.js add the following line:
```javascript
import './lib/settings'
```

You will need to [upload your service provider metadata to samltest.id's Idp](https://samltest.id/upload.php). Your metadata URL will be `https://<your-domain.com>/_saml/metadata/shibboleth-idp`. 

With this you should be able to use the login and logout buttons to authenticate with samltest's Idp. If you did not set `generateUsers` to true in your settings, you will need to create an account for the dummy users where `email.addresses` on the user object is equal to the email address given by samltest.

## Notes
* You may run into issues attempting to do this with localhost. I recommend using [ngrok](https://ngrok.com/) to forward traffic to localhost and use the generated forwarding address as your issuer.

* The 'dbname' and 'fname' fields in the 'authFields' object will be used to query the user's collection for the authenticated user as seen below:

  ```javascript
  Meteor.users.findOne({dbname: profile[fname]})
  ```
  where profile is not the user profile but an object that potentially contains the following fields:  
  `uid` - The userId likely used for sign in  
  `nameID` - Given the binding that this package uses this is the user's email. It will be stored on the user's object in the users collection and used as a session identifier when signing the user out.  
  `mail` - The user's email  
  `email` - Also the user's email  
  `eduPersonPrincipalName` - This corresponds to a user's 'netid' and is provided by some Idp's. You will not see this in samltest's login response.

  Leaving `authFields` out of the meteor settings will by default query the users collection with any/all of these attributes if they are present in the login response.

* If you run into any issues [samltest's Idp logs](https://samltest.id/logs/idp.log) are a good place to start troubbleshooting.

* It is only necessary to include Meteor's accounts-password package if `generateUsers` is set to true.
  

## Credits

This package was heavily inspired by tvoglund's [accounts-saml-shibboleth](https://github.com/tvoglund/accounts-saml-shibboleth) and bergie's [passport-saml](https://github.com/bergie/passport-saml). 

## License

MIT License

Copyright (c) 2019 Nathaniel Wallace

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.