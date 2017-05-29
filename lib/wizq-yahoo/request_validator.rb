module WizqYahoo
  class RequestValidator
    attr_accessor :key, :secret

    def initialize(key, secret)
      @key = key
      @secret = secret
    end

    def validate_signed_request(request)
      if signature_method = get_signature_method(request.params['oauth_consumer_key'])
        signature_method.check_signature(request, nil, nil, request.params['oauth_signature']) # request, consumer, token, sig
      else
        false
      end
    end

    private

      def get_signature_method(oauth_consumer_key)
        case oauth_consumer_key
        when 'sb.mbga-platform.jp'
          YahooMobageSandboxSignatureMethod.new
        when 'mbga-platform.jp'
          YahooMobageSignatureMethod.new
        else
          nil
        end
      end
  end

  class YahooMobageSandboxSignatureMethod < OAuthSignatureMethod_RSA_SHA1
    def fetch_public_cert(request)
<<-eos
-----BEGIN CERTIFICATE-----
MIICOTCCAaKgAwIBAgIJAK3cE459+jV9MA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV
BAMTE3NiLm1iZ2EtcGxhdGZvcm0uanAwHhcNMTUwNzE0MDkxOTQ2WhcNMTcwODI1
MDkxOTQ2WjAeMRwwGgYDVQQDExNzYi5tYmdhLXBsYXRmb3JtLmpwMIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDZ8xJKX1rPli72IF2L+tRV9Tk1c2kRixEEwzxR
T2bz37w/8XJQaMVxtFQMCYqquZUmHDss4JgF/prE4HGnX0j6x9MZUrt0k2VzDINm
Y+F61QJZCLqqy5MBxR9Dyu87DucPf7WsP3C1EMrfB8c29qVT7is+pMuYDowmsPql
eJ4pswIDAQABo38wfTAdBgNVHQ4EFgQUtNIqfC+B1PmcIhDmIA8+QxALZU4wTgYD
VR0jBEcwRYAUtNIqfC+B1PmcIhDmIA8+QxALZU6hIqQgMB4xHDAaBgNVBAMTE3Ni
Lm1iZ2EtcGxhdGZvcm0uanCCCQCt3BOOffo1fTAMBgNVHRMEBTADAQH/MA0GCSqG
SIb3DQEBBQUAA4GBALOFgNEL5x7tdorlPjwVlOSMZu+xgDR6oVmDEz+nYYBn1E2X
a3Td6+h1tgrkkPUIh8ydDdPQh1yKdAX0QSFifXXf3hUHSPh/A0JwqvrZTnmvZbp7
fWr0mq70uS4tlkNIUlAYlg7QwLZrW24k5V6ntjFmBqut10CYIIS8ln8e6WIg
-----END CERTIFICATE-----
eos
    end

    def fetch_private_cert(request)
<<-eos
-----BEGIN CERTIFICATE-----
MIICOTCCAaKgAwIBAgIJAK3cE459+jV9MA0GCSqGSIb3DQEBBAUAMB4xHDAaBgNV
BAMTE3NiLm1iZ2EtcGxhdGZvcm0uanAwHhcNMTAwODI1MDkzNzI4WhcNMTEwODI1
MDkzNzI4WjAeMRwwGgYDVQQDExNzYi5tYmdhLXBsYXRmb3JtLmpwMIGfMA0GCSqG
SIb3DQEBAQUAA4GNADCBiQKBgQDZ8xJKX1rPli72IF2L+tRV9Tk1c2kRixEEwzxR
T2bz37w/8XJQaMVxtFQMCYqquZUmHDss4JgF/prE4HGnX0j6x9MZUrt0k2VzDINm
Y+F61QJZCLqqy5MBxR9Dyu87DucPf7WsP3C1EMrfB8c29qVT7is+pMuYDowmsPql
eJ4pswIDAQABo38wfTAdBgNVHQ4EFgQUtNIqfC+B1PmcIhDmIA8+QxALZU4wTgYD
VR0jBEcwRYAUtNIqfC+B1PmcIhDmIA8+QxALZU6hIqQgMB4xHDAaBgNVBAMTE3Ni
Lm1iZ2EtcGxhdGZvcm0uanCCCQCt3BOOffo1fTAMBgNVHRMEBTADAQH/MA0GCSqG
SIb3DQEBBAUAA4GBALN/bYV+Vbr2z4edz2+hogP+PwW5IgV5sCohwcMAVVkmA9qs
RVPDSjm6E5e05kiCNAQQJpu2/d/i1xDuSjPpNMGaawapzNVbXh3xYwNkD8wrs1kM
tjKaDjOi4YhwIlhingNhsrozKW6jHBY/RXi/oRmAKsByIx72I4yFjHwZuXk+
-----END CERTIFICATE-----
eos
    end
  end

  class YahooMobageSignatureMethod < OAuthSignatureMethod_RSA_SHA1
    def fetch_public_cert(request)
<<-eos
-----BEGIN CERTIFICATE-----
MIICMDCCAZmgAwIBAgIJAKgXukluiO9rMA0GCSqGSIb3DQEBBQUAMBsxGTAXBgNV
BAMTEG1iZ2EtcGxhdGZvcm0uanAwHhcNMTUwNzE0MDkyMDQxWhcNMTcwODI1MDky
MDQxWjAbMRkwFwYDVQQDExBtYmdhLXBsYXRmb3JtLmpwMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDJiPISeGA1qFk3iCX/71yYN7DiHQhkkcEokr0WiOoHXEMH
bq25kb2oMFrUthS3FldzlCJQl6qfYcI2Q48LFoLjaaORkhNuW5WzqvRQSezyRBNS
3Z8LBmlEkqBnwLMA3BQTtgNctMajEzRGxd/1eLg4bQwpjVwzokxBVjNDZNh3dwID
AQABo3wwejAdBgNVHQ4EFgQUDGmQcD11YTlCXrGvuwbeO2g9tR0wSwYDVR0jBEQw
QoAUDGmQcD11YTlCXrGvuwbeO2g9tR2hH6QdMBsxGTAXBgNVBAMTEG1iZ2EtcGxh
dGZvcm0uanCCCQCoF7pJbojvazAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUA
A4GBAKlQHWdvTwezlK5iyeF5485nhPwR2EvtlfQ8SUjq5DWDC6Vwc/W/BxVHNFSg
mXkYwrvQCBjTyAt691vprqgusxq5eUrxBV+BWySjLQOkTBpU82N96qDicidzbylw
yESjbXbeMeZIZ6p3W19HrQEzwKd0KMWy6a81S46Oowh4HXhU
-----END CERTIFICATE-----
eos
    end

    def fetch_private_cert(request)
<<-eos
-----BEGIN CERTIFICATE-----
MIICMDCCAZmgAwIBAgIJAKgXukluiO9rMA0GCSqGSIb3DQEBBAUAMBsxGTAXBgNV
BAMTEG1iZ2EtcGxhdGZvcm0uanAwHhcNMTAwODI1MDkzNzM5WhcNMTEwODI1MDkz
NzM5WjAbMRkwFwYDVQQDExBtYmdhLXBsYXRmb3JtLmpwMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDJiPISeGA1qFk3iCX/71yYN7DiHQhkkcEokr0WiOoHXEMH
bq25kb2oMFrUthS3FldzlCJQl6qfYcI2Q48LFoLjaaORkhNuW5WzqvRQSezyRBNS
3Z8LBmlEkqBnwLMA3BQTtgNctMajEzRGxd/1eLg4bQwpjVwzokxBVjNDZNh3dwID
AQABo3wwejAdBgNVHQ4EFgQUDGmQcD11YTlCXrGvuwbeO2g9tR0wSwYDVR0jBEQw
QoAUDGmQcD11YTlCXrGvuwbeO2g9tR2hH6QdMBsxGTAXBgNVBAMTEG1iZ2EtcGxh
dGZvcm0uanCCCQCoF7pJbojvazAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBAUA
A4GBAAqX8b8CSfg9w7CyzpW2xMMYEgQtCh+z74+yDRb6VRVLqxGBW+1csd0IAH3T
NXY4rq3fwMJXnL56NCAcLu8cMjztSmp99qJ7hXsJH/r8mSZqmnv9avtz5/poNKJA
nETWH2q7bYK7+efS974dos+SGMcLwGDzcMpq705HJ/ZIT8jC
-----END CERTIFICATE-----
eos
    end
  end
end
