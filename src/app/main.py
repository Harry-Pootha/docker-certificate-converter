import os
from pathlib import Path
from datetime import timedelta, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, PrivateFormat, Encoding, NoEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12Certificate, PKCS12KeyAndCertificates
from cryptography.x509 import Certificate

from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver
from watchdog.events import FileSystemEventHandler, DirCreatedEvent, FileCreatedEvent

sleep_delay: int = 5
certificate_dir: str = "/openssl-certs"
mode: str = "poll"
passphrase: str = "dummy"
generate: bool = False
ALLOWED_MODES = ["poll", "api", "event"]


def get_path(path: str | Path, fail_on_nonexistence: bool = False) -> Path:
    if not type(path) is Path:
        path = Path(path)
    if fail_on_nonexistence and not path.exists():
        raise ValueError(F"File {path} does not exist")
    return path


class CertificateHandler(FileSystemEventHandler):

    last_file_written: Path = None

    @staticmethod
    def read_p12_from_file(source: str | Path, key_passphrase: bytes | str) -> pkcs12:
        source = get_path(source, fail_on_nonexistence=True)

        if type(key_passphrase) is str:
            key_passphrase = key_passphrase.encode()

        try:
            with source.open("rb") as p12_file:
                return pkcs12.load_pkcs12(p12_file.read(), password=key_passphrase)
        except ValueError as err:
            print(err)
        return None

    def write_pem_file(self, content: bytes, dest: str | Path):
        dest = get_path(dest)
        self.last_file_written = dest
        with dest.open("ab") as dest_file:
            dest_file.write(content)

    def write_p12_key(self, p12: pkcs12, name: str) -> None:
        pem_key = p12.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        self.write_pem_file(pem_key, F"{name}.key")

    def write_p12_certificates(self, p12: pkcs12, name: str) -> None:
        pem_cert = p12.cert.certificate.public_bytes(Encoding.PEM)
        self.write_pem_file(pem_cert, F"{name}.crt")

        if len(p12.additional_certs) > 0:
            print(F"Found {len(p12.additional_certs)} additional certificates - assuming being CA chain")
        for count, additional_certificate in enumerate(p12.additional_certs):
            pem_additional_certificate = additional_certificate.certificate.public_bytes(Encoding.PEM)
            self.write_pem_file(pem_additional_certificate, F"{name}-chain.crt")
            # CertificateHandler.write_pem_file(pem_additional_certificate, F"{name}-{count:0>4}.crt")


    def on_created(self, event: DirCreatedEvent | FileCreatedEvent) -> None:
        global passphrase
        if type(event) is FileCreatedEvent:
            event_file = Path(event.src_path)
            if not self.last_file_written is None and event_file == self.last_file_written:
                return
            print(F"Detected new: {event.src_path} (Directory: {event.is_directory})")
            if not event.is_directory:
                if event_file.suffix == ".pfx" or event_file.suffix == ".p12":
                    try:
                        p12 = self.read_p12_from_file(event.src_path, passphrase)
                        if not p12 is None:
                            path = F"{event_file.parent}/{event_file.stem}"
                            self.write_p12_key(p12, path)
                            self.write_p12_certificates(p12, path)

                    except ValueError as err:
                        print(err)


def generate_dummy_certificate():
    global passphrase
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



def read_config():
    global sleep_delay
    global certificate_dir
    global mode
    global passphrase
    global generate

    try:
        certificate_dir = env_or_default("DATA_DIR", certificate_dir)
        sleep_delay = env_or_default("SLEEP_DELAY", sleep_delay)
        mode = env_or_default("MODE", mode).lower()
        passphrase = env_or_default("PASSPHRASE", passphrase)
        generate = env_or_default("GENERATE", generate)
    except TypeError as err:
        print("Invalid type for environment variable")
        raise err

def check_config():
    global sleep_delay
    global certificate_dir
    global mode
    global ALLOWED_MODES
    global passphrase
    global generate

    certificate_dir_path = Path(certificate_dir)

    if certificate_dir_path.exists():
        raise ValueError(F"{certificate_dir} does not exist")
    if not certificate_dir_path.is_dir():
        raise ValueError(F"{certificate_dir} is not a path")
    if not ALLOWED_MODES.__contains__(mode):
        raise ValueError(F"Invalid value for mode (is: {mode}) (allowed: {"|".join(ALLOWED_MODES)}")

def main():
    global sleep_delay
    global certificate_dir
    global mode
    global passphrase
    global generate

    try:
        read_config()
    except TypeError:
        exit(1)
    except ValueError:
        exit(1)

    if generate:
        generate_dummy_certificate()

    observer: Observer | PollingObserver = None
    match mode:
        case "api":
            print("API mode not implemented")
            exit(1)
        case "poll":
            observer = PollingObserver()
        case "event":
            observer = Observer()

    if observer is None:
        print("Error setting up observer")
        exit(1)

    certificate_handler = CertificateHandler()
    observer.schedule(certificate_handler, certificate_dir, recursive=True)
    observer.start()

    try:
        while observer.is_alive():
            observer.join(sleep_delay)
    finally:
        observer.stop()
        observer.join()

def env_or_default(key: str, default: str | int | bool) -> str | int | bool:
    try:
        value = os.environ[key]
        if value == "":
            return default

        match default:
            case str(default):
                return value
            case int(default):
                if not value.isdigit():
                    return default
                else:
                    return int(value)
            case bool(default):
                return value.lower() == "true"
            case _:
                raise TypeError

    except KeyError:
        return default



if __name__ == '__main__':
    main()