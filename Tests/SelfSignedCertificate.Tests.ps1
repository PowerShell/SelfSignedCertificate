# Copyright (c) Robert Holt. All rights reserved.
# Licensed under the MIT License.

using module ..\SelfSignedCertificate

function Get-MillisecondTruncatedTime
{
    param([System.DateTimeOffset]$Time)

    return $Time.AddTicks(-$Time.Ticks % [timespan]::TicksPerSecond)
}

Describe "Generates a simple self signed certificate" {
    BeforeAll {
        Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'SelfSignedCertificate'))

        $certSubject = @{
            CommonName = 'donotuse.example.info'
            Country = 'US'
            StateOrProvince = 'Nebraska'
            Locality = 'Omaha'
            Organization = 'Umbrella Corporation'
            OrganizationalUnit = 'Marketing'
            EmailAddress = 'donotreply@umbrella.com'
        }

        $certParameters = @{
            OutCertPath = Join-Path $TestDrive 'cert.pfx'
            FriendlyName = 'Test Certificate'
            KeyLength = 4096
            KeyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,[System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment
            CertificateFormat = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx
            EnhancedKeyUsage = 'ServerAuthentication','ClientAuthentication'
            ForCertificateAuthority = $true
            Passphrase = ConvertTo-SecureString -Force -AsPlainText 'password'
            StartDate = [System.DateTimeOffset]::Now.Subtract([timespan]::FromDays(1))
            Duration = [timespan]::FromDays(365)
        } + $certSubject

        New-SelfSignedCertificate @certParameters

        $distinguishedName = [CertificateDistinguishedName]$certSubject

        $loadedCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certParameters.OutCertPath, $certParameters.Passphrase)
    }

    It "Has the correct friendly name" {
        $loadedCert.FriendlyName | Should -BeExactly $certParameters.FriendlyName
    }

    It "Renders the distinguished name correctly" {
        $loadedCert.Issuer | Should -BeExactly $distinguishedName.ToString()
    }

    It "Has the issuer and subject as the same entity" {
        $loadedCert.Subject | Should -BeExactly $loadedCert.Issuer
    }

    It "Has the correct cryptographic parameters" {
        $sha256RsaOid = "1.2.840.113549.1.1.11"
        $loadedCert.SignatureAlgorithm.Value | Should -Be $sha256RsaOid
        $loadedCert.PublicKey.Key.KeySize | Should -Be $certParameters.KeyLength
    }

    It "Has the expected start date" {
        $expectedTime = Get-MillisecondTruncatedTime -Time $certParameters.StartDate
        $loadedCert.NotBefore | Should -Be $expectedTime
    }

    It "Has the expected expiry date" {
        $expiryDate = $certParameters.StartDate.Add($certParameters.Duration)
        $expectedTime = Get-MillisecondTruncatedTime -Time $expiryDate
        $loadedCert.NotAfter | Should -Be $expectedTime
    }

    It "Has a basic constraints extension" {
        $constraints = ($loadedCert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] })[0]

        $basicConstraintsOid = "2.5.29.19"

        $constraints.Critical | Should -BeFalse
        $constraints.HasPathLengthConstraint | Should -BeFalse
        $constraints.CertificateAuthority | Should -BeTrue
        $constraints.Oid.Value | Should -Be $basicConstraintsOid
    }

    It "Has a Subject Key Idenitifer" {
        $ski = ($loadedCert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension] })[0]

        $skiOid = "2.5.29.14" 

        $ski.Critical | Should -BeFalse
        $ski.Oid.Value | Should -Be $skiOid
    }

    It "Has an Authority Key Identifier" {
        $akiOid = "2.5.29.35"

        $aki = ($loadedCert.Extensions | Where-Object { $_.Oid.Value -eq $akiOid })

        $aki.Critical | Should -BeFalse
        $aki.Oid.Value | Should -Be $akiOid
    }

    It "Subject Key Identifier and Authority Key Identifier agree" {
        $ski = ($loadedCert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension] })[0]
        $aki = ($loadedCert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.35" })[0]

        $authorityIdentifier = ($aki.RawData[4..23] | ForEach-Object { $_.ToString('X2') }) -join ''

        $authorityIdentifier | Should -Be $ski.SubjectKeyIdentifier
    }
}
