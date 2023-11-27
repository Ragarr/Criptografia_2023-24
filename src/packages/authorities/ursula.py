import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from .elPapa import ElPapa

from .certificate import Certificate
from .singleton import singleton

@singleton
class Ursula:
    def __init__(self) -> None:
        self.__private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        self.__subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Berlin"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Berlin"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Mercedes"),
            x509.NameAttribute(NameOID.COMMON_NAME, "doishnewneitz.com"),
        ])
        
        csr = x509.CertificateSigningRequestBuilder().subject_name(
                self.__subject
            ).sign(self.__private_key, hashes.SHA256())
        
        elpapa = ElPapa()
        
        self.__certificate = elpapa.issueCertificate(csr)
        self.__trusted_certs = [self.__certificate] + elpapa.trusted_certs
        
    @property
    def trusted_certs(self):
        return self.__trusted_certs
    
    @property
    def certificate(self):
        return self.__certificate
    
    def issueCertificate(self, csr):
        certificate = x509.CertificateBuilder().subject_name(
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
        
        return Certificate(certificate, self.__certificate) 

    

    