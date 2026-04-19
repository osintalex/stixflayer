# STIX 2.1 Cyber Observable Objects (SCOs) Test Suite
import json
import pytest

from stixflayer import (
    IPv4Address,
    IPv6Address,
    DomainName,
    URL,
    EmailAddress,
    MacAddr,
    AutonomousSystem,
    File,
    Software,
    Directory,
    Mutex,
    Process,
    NetworkTraffic,
    UserAccount,
    WindowsRegistryKey,
    X509Certificate,
)


class TestSCOConstruction:
    """Test SCO construction with required fields."""

    def test_ipv4_addr(self):
        ip = IPv4Address(value="192.0.2.1")
        assert ip.type == "ipv4-addr"
        assert ip.value == "192.0.2.1"

    def test_ipv6_addr(self):
        ip = IPv6Address(value="2001:db8::1")
        assert ip.type == "ipv6-addr"

    def test_domain_name(self):
        domain = DomainName(value="example.com")
        assert domain.type == "domain-name"
        assert domain.value == "example.com"

    def test_url(self):
        url = URL(value="https://example.com")
        assert url.type == "url"

    def test_email_address(self):
        email = EmailAddress(value="user@example.com")
        assert email.type == "email-address"

    def test_mac_addr(self):
        mac = MacAddr(value="00:11:22:33:44:55")
        assert mac.type == "mac-addr"

    def test_autonomous_system(self):
        asn = AutonomousSystem(number=15169)
        assert asn.type == "autonomous-system"
        assert asn.number == 15169

    def test_file(self):
        f = File(name="malware.exe")
        assert f.type == "file"
        assert f.name == "malware.exe"

    def test_software(self):
        s = Software(name="Firefox")
        assert s.type == "software"
        assert s.name == "Firefox"

    def test_directory(self):
        d = Directory(path="/Users/admin")
        assert d.type == "directory"
        assert d.path == "/Users/admin"

    def test_mutex(self):
        m = Mutex(name="Global\\MyMutex")
        assert m.type == "mutex"
        assert m.name == "Global\\MyMutex"

    def test_process(self):
        p = Process()
        assert p.type == "process"

    def test_network_traffic(self):
        nt = NetworkTraffic(protocols=["tcp", "http"])
        assert nt.type == "network-traffic"

    def test_user_account(self):
        ua = UserAccount(account_login="admin")
        assert ua.type == "user-account"
        assert ua.account_login == "admin"

    def test_windows_registry_key(self):
        wrk = WindowsRegistryKey(key="HKEY_LOCAL_MACHINE\\Software\\Test")
        assert wrk.type == "windows-registry-key"

    def test_x509_certificate(self):
        cert = X509Certificate(serial_number="1234567890")
        assert cert.type == "x509-certificate"
        assert cert.serial_number == "1234567890"


class TestSCOJson:
    """Test SCO JSON serialization."""

    def test_ipv4_to_json(self):
        ip = IPv4Address(value="1.1.1.1")
        data = json.loads(ip.to_json())
        assert data["type"] == "ipv4-addr"
        assert data["value"] == "1.1.1.1"

    def test_file_to_json(self):
        f = File(name="test.exe")
        data = json.loads(f.to_json())
        assert data["type"] == "file"
        assert data["name"] == "test.exe"


class TestTypeGetters:
    """Test type getters."""

    @pytest.mark.parametrize(
        "cls,expected_type",
        [
            (IPv4Address, "ipv4-addr"),
            (IPv6Address, "ipv6-addr"),
            (DomainName, "domain-name"),
            (File, "file"),
            (Software, "software"),
            (Mutex, "mutex"),
            (Process, "process"),
            (NetworkTraffic, "network-traffic"),
            (UserAccount, "user-account"),
            (X509Certificate, "x509-certificate"),
        ],
    )
    def test_type(self, cls, expected_type):
        if cls == Process:
            obj = cls()
        elif cls == NetworkTraffic:
            obj = cls(protocols=["tcp"])
        elif cls in [File, Software, Mutex]:
            obj = cls(name="test")
        elif cls == UserAccount:
            obj = cls(account_login="test")
        elif cls == X509Certificate:
            obj = cls(serial_number="123")
        else:
            obj = cls(value="test")
        assert obj.type == expected_type


class TestValueGetters:
    """Test value getters."""

    def test_ipv4_value(self):
        assert IPv4Address(value="192.168.1.1").value == "192.168.1.1"

    def test_ipv6_value(self):
        assert IPv6Address(value="::1").value == "::1"

    def test_domain_value(self):
        assert DomainName(value="example.com").value == "example.com"

    def test_email_value(self):
        assert EmailAddress(value="test@example.com").value == "test@example.com"

    def test_mac_value(self):
        assert MacAddr(value="aa:bb:cc:dd:ee:ff").value == "aa:bb:cc:dd:ee:ff"

    def test_as_number(self):
        assert AutonomousSystem(number=15169).number == 15169

    def test_file_name(self):
        assert File(name="malware.exe").name == "malware.exe"

    def test_software_name(self):
        assert Software(name="Firefox").name == "Firefox"

    def test_directory_path(self):
        assert Directory(path="/home/user").path == "/home/user"

    def test_mutex_name(self):
        assert Mutex(name="Global\\Mutex").name == "Global\\Mutex"

    def test_user_account_login(self):
        assert UserAccount(account_login="admin").account_login == "admin"

    def test_x509_serial(self):
        assert X509Certificate(serial_number="ABC123").serial_number == "ABC123"
