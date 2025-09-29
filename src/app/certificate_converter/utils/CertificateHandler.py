from pathlib import Path
from certificate_converter.utils.helpers import get_path
from certificate_converter.utils.helpers import write_bytes_to_file

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, PrivateFormat, Encoding, NoEncryption

from watchdog.events import FileSystemEventHandler, DirCreatedEvent, FileCreatedEvent
from datetime import timedelta, datetime

class P12Handler:
    _file_naming: str
    _file_path: str
    _p12_certificate: pkcs12

    def __init__(self, file_path: str | Path, passphrase: str = "") -> None:
        self._p12_certificate = None
        self.load(file_path, passphrase)

    def __get_key(self) -> bytes:
        return self._p12_certificate.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())

    def __get_cert(self) -> bytes:
        return self._p12_certificate.cert.certificate.public_bytes(Encoding.PEM)

    def __get_chain(self) -> bytes:
        chain = list[bytes]()
        for additional_certificate in self._p12_certificate.additional_certs:
            chain.append(additional_certificate.certificate.public_bytes(Encoding.PEM))
        return b''.join(chain)

    def write_pems(self):
        if self._p12_certificate is None:
            return
        write_bytes_to_file(F"{self._file_path}/{self._file_naming}.key", self.__get_key())
        write_bytes_to_file(F"{self._file_path}/{self._file_naming}.crt", self.__get_cert())
        write_bytes_to_file(F"{self._file_path}/{self._file_naming}-chain.crt", self.__get_chain())

    def load(self, file_path: Path | str, passphrase: bytes | str = "") -> bool:
        if type(passphrase) is str:
            passphrase = passphrase.encode()

        if len(passphrase) == 0:
            raise ValueError("Passphrase cannot be empty for PKCS#12 certificate")

        try:
            file_path = get_path(file_path, fail_on_nonexistence=True)
            self._file_path = str(file_path.parent)
            self._file_naming = file_path.stem
        except ValueError as err:
            print(err)
            return False

        try:
            with file_path.open("rb") as p12_file:
                p12 = pkcs12.load_pkcs12(p12_file.read(), password=passphrase)
                if p12 is None:
                    return False
                else:
                    self._p12_certificate = p12
                    return True
        except ValueError as err: # Invalid password = ValueError
            print(err)
            return False


class CertificateHandler(FileSystemEventHandler):

    files_written: list[Path] = list()
    default_passphrase: str = ""

    def get_passphrase(self, file: str | Path) -> str:
        file = get_path(file)
        if not file.exists():
            return self.default_passphrase
        else:
            with open(file, "r") as read_file:
                line = read_file.read()
                if line == "":
                    return self.default_passphrase
                return line

    def on_created(self, event: DirCreatedEvent | FileCreatedEvent) -> None:
        if type(event) is FileCreatedEvent:
            event_file = Path(event.src_path)
            if event_file in self.files_written:
                self.files_written.remove(event_file)
                return
            print(F"Detected new: {event.src_path} (Directory: {event.is_directory})")
            if not event.is_directory:
                match event_file.suffix:
                    case ".pfx" | ".p12":
                        try:
                            passphrase = self.get_passphrase(F"{event_file.parent}/{event_file.stem}.passphrase")
                            p12_handler = P12Handler(event.src_path, passphrase)
                            p12_handler.write_pems()
                        except ValueError as err:
                            print(err)
                    case ".passphrase":
                        try:
                            passphrase = self.get_passphrase(event_file)
                            p12_file = Path(F"{event_file.parent}/{event_file.stem}.pfx")
                            if not p12_file.exists():
                                p12_file = Path(F"{event_file.parent}/{event_file.stem}.p12")
                                if not p12_file.exists():
                                    return
                            p12_handler = P12Handler(p12_file, passphrase)
                            p12_handler.write_pems()
                        except ValueError as err:
                            print(err)


def generate_dummy_certificate(certificate_dir, passphrase):
    common_name = "example.com"
    issuer = "Issuer"
    validity_days = 3650 # 10 years
    dummy_file_path = F"{certificate_dir}/dummy.pfx"

    file = Path(dummy_file_path)
    if file.exists():
        print("Cannot generate dummy file because a file with that name already exists")
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]))
    builder = builder.issuer_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer)]))
    builder = builder.not_valid_before(datetime.today() - timedelta(days=1))
    builder = builder.not_valid_after(datetime.today() + timedelta(days=validity_days))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())

    cert = x509.load_pem_x509_certificate(cert.public_bytes(Encoding.PEM))
    encryption = (
        PrivateFormat.PKCS12.encryption_builder().
        kdf_rounds(50000).
        key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC).
        hmac_hash(hashes.SHA256()).build(passphrase.encode())
    )
    p12_cert = pkcs12.serialize_key_and_certificates(name=common_name.encode(),
                                                     key=private_key,
                                                     cert=cert,
                                                     cas=None,
                                                     encryption_algorithm=encryption)

    with open (dummy_file_path, "wb") as p12_file:
        p12_file.write(p12_cert)