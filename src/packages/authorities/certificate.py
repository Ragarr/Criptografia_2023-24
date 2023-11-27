from cryptography import x509

class Certificate:
    def __init__(self, certificate: x509.Certificate,  issuer_certificate = None) -> None:

        self.__issuer_certificate = issuer_certificate

        if issuer_certificate is None:
            self.__issuer_certificate = certificate

        self.__certificate = certificate


    @property
    def issuer_certificate(self) -> x509.Certificate:
        return self.__issuer_certificate

    @property
    def certificate(self) -> x509.Certificate:
        return self.__certificate
    
    def __str__(self) -> str:
        return f"\nCertificate: {str(self.__certificate)} - Issuer: {str(self.issuer_certificate)}"
    
    def __repr__(self) -> str:
        return self.__str__()