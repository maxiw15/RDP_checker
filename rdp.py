import socket
import struct
from OpenSSL import SSL
from datetime import datetime
import sys

SERVER = 1
DOMAIN = 2
FQDN_SERVER = 3
FQDN_DOMAIN = 4
PARENT = 5

CHALLENGE_REQUEST_BYTES = bytes(
    [78, 84, 76, 77, 83, 83, 80, 0, 1, 0, 0, 0, 7, 130, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
)


class Target:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.challenge = Challenge()
        self.certificate = Certificate()

    def fetch_challenge(self):
        """Подключение к серверу, получение NTLM-челленджа и сертификата."""
        challenge_data = bytearray(2048)

        # Создаем TLS-соединение с помощью pyOpenSSL
        context = SSL.Context(SSL.TLSv1_2_METHOD)
        context.set_verify(SSL.VERIFY_NONE, callback=lambda conn, cert, errno, depth, ok: True)

        connection = SSL.Connection(context, socket.create_connection((self.ip, self.port)))
        connection.set_tlsext_host_name(self.ip.encode())  # Указываем SNI
        connection.set_connect_state()

        try:
            # TLS Handshake
            connection.do_handshake()

            # Получаем сертификат
            cert = connection.get_peer_certificate()
            if cert:
                self.certificate.issuer = ", ".join(
                    [f"{name.decode()}={value.decode()}" for name, value in cert.get_issuer().get_components()])
                self.certificate.subject = ", ".join(
                    [f"{name.decode()}={value.decode()}" for name, value in cert.get_subject().get_components()])
                self.certificate.notAfter = self.format_date(cert.get_notAfter().decode())
                self.certificate.notBefore = self.format_date(cert.get_notBefore().decode())
                self.certificate.serial_number = cert.get_serial_number()
                self.certificate.version = cert.get_version() + 1  # Версия 0 => X.509v1, 1 => X.509v2, 2 => X.509v3
                self.certificate.signature_algorithm = cert.get_signature_algorithm().decode()

            # Отправляем запрос NLA и читаем ответ
            nla_request = bytearray(
                b"\x30\x37\xa0\x03\x02\x01\x60\xa1\x30\x30\x2e\x30\x2c\xa0\x2a\x04\x28") + CHALLENGE_REQUEST_BYTES + bytearray(
                b"\x00\x00\x0a\x00\x63\x45\x00\x00\x00\x0f")
            connection.sendall(nla_request)
            response_len = connection.recv_into(challenge_data)
            challenge_data = challenge_data[23:response_len]
            self.challenge.raw = bytes(challenge_data)

            if b"NTLMSSP\x00" in self.challenge.raw:
                self.challenge.raw = self.challenge.raw[self.challenge.raw.index(b"NTLMSSP\x00"):]
                self.challenge.decode()
            else:
                raise ValueError("Invalid NTLMSSP response.")
        except Exception as e:
            print("Ошибка при работе с TLS:", e)
        finally:
            connection.close()

    def display_info(self):
        """Вывод информации о NTLM-челлендже."""
        if self.challenge.raw:
            print("\nRemote Desktop Protocol:")
            print(f"  Имя сервера       :", self.challenge.server)
            print(f"  Имя домена        :", self.challenge.domain)
            print(f"  FQDN сервера      :", self.challenge.fqdn_server)
            print(f"  FQDN домена       :", self.challenge.fqdn_domain)
            print(f"  Родительский домен:", self.challenge.parent)
            print(f"  Версия OS         :", self.challenge.os_version)
            print(f"  OS                :", self.challenge.os_description)

    def certificate_info(self):
        print("\nСертификат сервера:")
        print(f"  Кем выдан         : {self.certificate.issuer}")
        print(f"  Кому выдан        : {self.certificate.subject}")
        print(f"  Действителен      : с {self.certificate.notBefore} по {self.certificate.notAfter}")
        print(f"  Серийный номер    : {self.certificate.serial_number}")
        print(f"  Версия            : X.509v{self.certificate.version}")
        print(f"  Алгоритм подписи  : {self.certificate.signature_algorithm}")

    @staticmethod
    def format_date(date_str):
        """Форматирует дату из формата ASN.1 в читаемый формат."""
        try:
            return datetime.strptime(date_str, "%Y%m%d%H%M%SZ").strftime("%d.%m.%Y %H:%M:%S")
        except ValueError:
            return date_str


class Challenge:
    def __init__(self):
        self.raw = b""
        self.server = ""
        self.domain = ""
        self.fqdn_server = ""
        self.fqdn_domain = ""
        self.parent = ""
        self.os_version = ""
        self.os_description = ""

    def decode(self):
        offset = struct.unpack("<H", self.raw[44:46])[0]
        data = self.raw[offset:]
        for i in range(5):
            data_type = struct.unpack("<H", data[0:2])[0]
            data_length = struct.unpack("<H", data[2:4])[0] + 4
            text = data[4:data_length].decode("utf-8").replace("\x00", "")

            if data_type == SERVER:
                self.server = text
            elif data_type == DOMAIN:
                self.domain = text
            elif data_type == FQDN_SERVER:
                self.fqdn_server = text
            elif data_type == FQDN_DOMAIN:
                self.fqdn_domain = text
            elif data_type == PARENT:
                self.parent = text

            data = data[data_length:]

        if offset > 48:
            major = int(self.raw[48])
            minor = int(self.raw[49])
            build = struct.unpack("<H", self.raw[50:52])[0]
            self.os_version = f"{major}.{minor}.{build}"

            version_key = f"{major}.{minor}"

            if version_key == "5.0":
                self.os_description = f"Windows 2000 (Build {build})"
            elif version_key == "5.1":
                self.os_description = f"Windows XP/Server 2003 (R2) (Build {build})"
            elif version_key == "5.2":
                self.os_description = f"Windows XP/Server 2003 (R2) (Build {build})"
            elif version_key == "6.0":
                self.os_description = f"Windows Vista/Server 2008 (Build {build})"
            elif version_key == "6.1":
                self.os_description = f"Windows 7/Server 2008 R2 (Build {build})"
            elif version_key == "6.2":
                self.os_description = f"Windows 8/Server 2012 (Build {build})"
            elif version_key == "6.3":
                self.os_description = f"Windows 8.1/Server 2012 R2 (Build {build})"
            elif version_key == "10.0":
                if build >= 22000:
                    self.os_description = f"Windows 11/Server 2022 (Build {build})"
                elif build >= 20348:
                    self.os_description = f"Windows 10/Server 2022 (Build {build})"
                elif build >= 17623:
                    self.os_description = f"Windows 10/Server 2019 (Build {build})"
                else:
                    self.os_description = f"Windows 10/Server 2016 (Build {build})"
            else:
                self.os_description = f"{major}.{minor}.{build}"


#TODO добавить версионность

class Certificate:
    def __init__(self):
        self.issuer = ""
        self.subject = ""
        self.notAfter = ""
        self.notBefore = ""
        self.serial_number = ""
        self.version = ""
        self.signature_algorithm = ""


def main(ip, port):
    target = Target(ip, port)

    try:
        target.fetch_challenge()
        target.display_info()
        target.certificate_info()
    except Exception as e:
        print("Ошибка:", e)


### Пример запуска python3 rdp.py 10.10.20.128 3389
if __name__ == "__main__":
    ip = sys.argv[1]
    port = int(sys.argv[2])
    main(ip, port)
