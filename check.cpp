#include "cryptopp/cryptlib.h"
#include "cryptopp/x509cert.h"
#include "cryptopp/secblock.h"
#include "cryptopp/filters.h"
#include "cryptopp/rsa.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/pem.h"
#include "cryptopp/files.h"

#include <iostream>
#include <string>

extern const std::string pemCertificate;

int main(int argc, char* argv[])
{
    using namespace CryptoPP;

    StringSource ss(pemCertificate, true);
    X509Certificate cert;
    PEM_Load(ss, cert);

    const SecByteBlock& signature = cert.GetCertificateSignature();
    const SecByteBlock& toBeSigned = cert.GetToBeSigned();
    const X509PublicKey& publicKey = cert.GetSubjectPublicKey();
    
    RSASS<PKCS1v15, SHA256>::Verifier verifier(publicKey);
    bool result = verifier.VerifyMessage(toBeSigned, toBeSigned.size(), signature, signature.size());

    if (result)
        std::cout << "Verified certificate" << std::endl;
    else
        std::cout << "Failed to verify certificate" << std::endl;

    std::cout << "Signature: ";
    //size_t size = std::min(signature.size(), (size_t)30);
    StringSource(signature, signature.size(), true, new HexEncoder(new FileSink(std::cout)));
    //std::cout << "..." << std::endl;

    std::cout << "\nTo Be Signed: ";
    //size = std::min(signature.size(), (size_t)30);
    StringSource(toBeSigned, toBeSigned.size(), true, new HexEncoder(new FileSink(std::cout)));
    //std::cout << "..." << std::endl;

    return 0;
}

const std::string pemCertificate =


    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIEZTCCA02gAwIBAgIUTrRCySQFQNRYcWKYxhHVNsult3cwDQYJKoZIhvcNAQEL\r\n"
    "BQAwfzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk5ZMREwDwYDVQQHDAhOZXcgWW9y\r\n"
    "azEVMBMGA1UECgwMRXhhbXBsZSwgTExDMRgwFgYDVQQDDA9FeGFtcGxlIENvbXBh\r\n"
    "bnkxHzAdBgkqhkiG9w0BCQEWEHRlc3RAZXhhbXBsZS5jb20wHhcNMTkxMDAxMDYx\r\n"
    "NzE0WhcNMjAwOTMwMDYxNzE0WjB/MQswCQYDVQQGEwJVUzELMAkGA1UECAwCTlkx\r\n"
    "ETAPBgNVBAcMCE5ldyBZb3JrMRUwEwYDVQQKDAxFeGFtcGxlLCBMTEMxGDAWBgNV\r\n"
    "BAMMD0V4YW1wbGUgQ29tcGFueTEfMB0GCSqGSIb3DQEJARYQdGVzdEBleGFtcGxl\r\n"
    "LmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL1tC7yUK8h7L/dg\r\n"
    "THkoQGYLhBI/jNIoN+HJUP6fnEIrhaYnH3bbFoXKcarOqZusKmhhRIsgGeeT2NG6\r\n"
    "0nWgkRbBUH2Ic1gNqzIhQsF8eirUGchaCyXuuueBvQUrnkJjVG9yyJ5XFdjjx4kX\r\n"
    "y9IMxAM80W3GmMxXkKlS1vYVqKmRNf/NUne5h/U/kRtkGqjDQpIG/y9et8+mY3CV\r\n"
    "vjh4AiFAIswPB5beUqSVuq+vx+VCo3vZw9KptuEwqphZMC8YVuSHi3/hQXuaBlG1\r\n"
    "sAfVR05KIl3tKVp428tQPZZZjreVZTBfWCwI/marlFFxkC9bWuIAzpy8tTPsB21r\r\n"
    "LDvXof8CAwEAAaOB2DCB1TAdBgNVHQ4EFgQUgrdpzgQ4EeZk2VRdMDXPeSPCvGsw\r\n"
    "HwYDVR0jBBgwFoAUgrdpzgQ4EeZk2VRdMDXPeSPCvGswDAYDVR0TAQH/BAIwADAL\r\n"
    "BgNVHQ8EBAMCBaAwSgYDVR0RBEMwQYILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxl\r\n"
    "LmNvbYIQbWFpbC5leGFtcGxlLmNvbYIPZnRwLmV4YW1wbGUuY29tMCwGCWCGSAGG\r\n"
    "+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTANBgkqhkiG9w0B\r\n"
    "AQsFAAOCAQEAn5fSk9UK+N4MDAFytzIpfUoSobiVvvNT//+dticgJyySyPThXeZ+\r\n"
    "+I+C6FSykkr0+wq4DZidygpHydS1/E2Dvlsa2XHQbgTyfiBdpEcbu6bVNeBRAtyP\r\n"
    "kWe0pO7/rha94dcFMDN88d4qMIragWh+yJk0rIofLxQe5qWounTYBetutz5dFOiJ\r\n"
    "lwvGeY1HTnElkxaXULtoz+QPcgidQX8sEKhHNwKiae5gj0YeWowVoAnaHhwYiRMa\r\n"
    "VdUKKD1CiSkFNaKSUW0ee8dpVr3rWtt+X1K0+B46lUPGUG5QtN33dtisqrY3X8q7\r\n"
    "g0NwwUKAWL9DE1uadKjJI+X1AL0ft6Nj4Q==\r\n"

    "-----END CERTIFICATE-----\r\n";


