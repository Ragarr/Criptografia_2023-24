import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from .certificate import Certificate
from .singleton import singleton

@singleton
class ElPapa:
    def __init__(self):
        self.__private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        self.__subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VA"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Vaticano"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Roma"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cristianismo"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Dios.com"),
        ])

        x509certificate = x509.CertificateBuilder().subject_name(
                self.__subject
            ).issuer_name(
                self.__subject
            ).public_key(
                self.__private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False,
            # Sign our certificate with our private key
            ).sign(self.__private_key, hashes.SHA256())
        
        self.__certificate = Certificate(x509certificate)

    @property
    def certificate(self):
        return self.__certificate

    @property
    def trusted_certs(self):
        return [self.__certificate]

    def info(self):
        return self.__subject
    

    def issueCertificate(self, csr) -> x509.Certificate:
        x509certificate = x509.CertificateBuilder().subject_name(
                csr.subject
            ).issuer_name(
                self.__subject
            ).public_key(
                csr.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.now(datetime.timezone.utc)
            ).not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
            ).sign(self.__private_key, hashes.SHA256())
        
        certificate = Certificate(x509certificate, self.__certificate)
        
        return certificate

if __name__ == '__main__':
    a = ElPapa()
    print(a.certificate)