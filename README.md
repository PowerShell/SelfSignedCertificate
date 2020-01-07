SelfSignedCertificate
===

Table of Contents:

- [Overview](#overview)
- [Install](#install)
- [Example Usage](#example-usage)
- [Suggested Improvements](#suggested-improvements)
- [License](#license)

### Disclaimer

This module is not officially supported.
It has been created as a convenience module
for the generation of self-signed certificates
to simplify the testing of HTTPS functionality.

This module should not be used in any production scenarios;
it is designed to create self-signed certificates for testing
purposes only.

Overview
---

This module is designed to be a convenient, cross-platform way
to generate self-signed certificates in both PowerShell Core and Windows PowerShell 5.1.

Since .NET Core already embeds its own cross-platform cryptography/certificate API,
this module is a native PowerShell script module, with no binary dependencies.

Some goals for this module include:

- Low or no dependency footprint
- User-friendly certificate input:
  - No fiddling with distinguished name formats
  - No arcane `X509HighlySpecificCryptoObject` assigning and manipulation
  - No raw binary/ASN.1/DER manipulation
- Relatively improved configurability:
  - Support multiple certificate formats
  - Support different certificate configurations, validity periods and extensions
- Simple cross-platform functionality:
  - We should be able to generate a certificate that works
    on Windows, Linux and macOS
  - Default settings should "just work" on respective platforms
  - Favor simplicity when possible, but not as a hard requirement

### Alternative tools

You may want to take a look at a few other alternatives for self-signed certificate generation,
listed here:

- Windows PowerShell's [`New-SelfSignedCertificate` cmdlet](https://docs.microsoft.com/en-us/powershell/module/pkiclient/new-selfsignedcertificate?view=win10-ps)
  from the PkiClient module.
  
  It can be used from PowerShell Core on Windows using the [WindowsCompatibility module](https://github.com/PowerShell/WindowsCompatibility)
  like this:
  
  ```powershell
  Install-Module WindowsCompatibility
  Import-WinModule PKI
  New-SelfSignedCertificate # args as needed
  ```
  
  However, this module is only available on Windows &mdash; there is no Linux version.
  
- The [`dotnet dotnet-dev-certs` global tool](https://www.nuget.org/packages/dotnet-dev-certs),
  designed for generating self-signed certificates for ASP.NET Core development.
  
  This can be installed from the dotnet CLI.
  
- [`openssl`](https://www.openssl.org/), which does work cross-platform,
  but may not be favorable compared to a PowerShell-native option
  and uses a PEM rather than PFX format.

Install
---

If Windows PowerShell's [`New-SelfSignedCertificate` cmdlet](https://docs.microsoft.com/en-us/powershell/module/pkiclient/new-selfsignedcertificate?view=win10-ps) is not imported, the following command should install without any interuption:

```powershell
Install-Module -Name SelfSignedCertificate
```

If there is an interuption during install stating, "The following commands are already available on this system:'New-SelfSignedCertificate'", most likely its from PkiClient module. One solution is to execute the `Remove-Module` command below for 'PKI' module. In an addition, if needed, after removal execute the `Import-Module` specifying a prefix to be used for all of its functions. Afterwards, execute the `Install-Module` again. For any subsequent PowerShell sessions, the following command(s) may not be needed as the `New-SelfSignedCertificate` from `SelfSignedCertificate` module should take precedence over PkiClient module.

```powershell
Remove-Module PKI
Import-Module PKI -Prefix PKI
```

Example Usage
---

### Basic Usage

To create a simple certificate the following will work:

```powershell
> New-SelfSignedCertificate
Certificate written to C:\Users\roholt\Documents\Dev\sandbox\certificate.pfx

Thumbprint                                Subject              EnhancedKeyUsageList
----------                                -------              --------------------
A51B016324B5D2F11340CDCC52004B8129C88D3B  CN=localhost

```

This will create a new certificate called `certificate.pfx` in your CWD
for `localhost`.
The command itself returns an `X509Certificate2` object
describing the certificate written to disk.
You can inspect this object to find its properties.
This certificate will have no key usages, no basic constraints,
no enhanced key usages and a Subject Idenitifer Key extension.

**Note**: To repeat this command, you will need the `-Force` parameter
in order to overwrite the old certificate you generated before.

### More Advanced Usage

The `New-SelfSignedCertificate` command allows the specification of
full distinguished names as well as a few other options:

```powershell
> $password = ConvertTo-SecureString -Force -AsPlainText 'your password'
> $distinguishedName = @{
    CommonName = 'example.org'
    Country = 'US'
    StateOrProvince = 'Nebraska'
    Locality = 'Omaha'
    Organization = 'Umbrella Corporation'
    OrganizationalUnit = 'Sales'
    EmailAddress = 'donotreply@umbrellacorp.com'
}
> $certificateParameters = $distinguishedName + @{
    OutCertPath = 'C:\Users\you\Documents\cert.pfx'
    StartDate = [System.DateTimeOffset]::Now
    Duration = [timespan]::FromDays(365)
    Passphrase = $password
    CertificateFormat = 'Pfx' # Values from [System.Security.Cryptography.X509Certificates.X509ContentType]
    KeyLength = 4096
    ForCertificateAuthority = $true
    KeyUsage = 'DigitalSignature','KeyEncipherment' # Values from [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]
    EnhancedKeyUsage = 'ServerAuthentication','ClientAuthentication'
}
> New-SelfSignedCertificate @certificateParameters -Force
WARNING: Parameter 'EmailAddress' is obsolete. The email name component is deprecated by the PKIX standard
Certificate written to C:\Users\roholt\Documents\Dev\sandbox\here.pfx

Thumbprint                                Subject              EnhancedKeyUsageList
----------                                -------              --------------------
7445433CB2BB4948E12794A167C6725DC214AA84  CN=example.org, O... {Server Authentication, Client Authentication}
```

The certificate produced by the above command will have the following properties:

- The issuer and subject distinguished name set to:

  ```text
  CN=example.org, OU=Sales, O=Umbrella Corporation, L=Omaha, S=Nebraska, C=US, E=donotreply@umbrellacorp.com
  ```

- Password protection (in this case with the password `'Your password'`).
- A one-year validity period starting from the creation time (with the milliseconds truncated).
- A 4096-bit RSA key.
- A basic constraints extension with `CertificateAuthority` set to `true`.
- The `Digital Signature` and `Key Encipherment` basic key usages indicated.
- The `Server Authentication` and `Client Authentication` enhanced key usages indicated.

The command also offers the `-AdditionalExtension` parameter,
which takes an array of `System.Security.Cryptography.X509Certificates.X509Extension`
to add to any generate certificate.

Suggested Improvments
---

### Support for other certificate formats

The module does not yet support PEM files,
which are heavily used in the Linux world.
While not a certificate format per-se,
they are a common encoding of certificates
and we should endeavour to support them in some way.

Presently, the author is not aware of PEM support
native to PowerShell Core or .NET Core.

### Ability to specify criticality on certificate extensions

The certificate extensions generated by this module
currently all set the `Critical` field to `false` to allow greater flexibility.

However it might be desirable to configure
any or all of these to be designated as `Critical`.
Ideally this could be done without cluttering up the commands already
large number of parameters.

### Better support for other enhanced key usages

Currently on the `ServerAuthentication` and `ClientAuthentication` enhanced
key usages are supported (in constraining way, for ease of use).

Ideally more options for this could be made available.

### Better, more-modular support for common certificate extensions

The module could provide a set of classes that generate `X509Extension`s
describing commonly used certificate extensions.

License
---

This module is MIT licensed. See the [LICENSE.txt](./LICENSE.txt).
