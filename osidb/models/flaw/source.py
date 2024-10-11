from django.db import models


class FlawSource(models.TextChoices):
    """
    Enum to indicate where a Flaw was first reported.

    Whether the source is public or private can be determined by calling the
    is_public() method on any Enum member.
    """

    ADOBE = "ADOBE"
    APPLE = "APPLE"
    ASF = "ASF"  # (APACHE, APACHEANNOUNCE)
    BIND = "BIND"
    BK = "BK"
    BUGTRAQ = "BUGTRAQ"
    BUGZILLA = "BUGZILLA"
    CERT = "CERT"
    CERTFI = "CERTIFI"
    CORELABS = "CORELABS"
    CUSTOMER = "CUSTOMER"
    CVE = "CVE"
    CVEORG = "CVEORG"
    DAILYDAVE = "DAILYDAVE"
    DEBIAN = "DEBIAN"
    DISTROS = "DISTROS"
    FEDORA = "FEDORA"
    FETCHMAIL = "FETCHMAIL"
    FREEDESKTOP = "FREEDESKTOP"  # FREEDESKTOP.ORG
    FREERADIUS = "FREERADIUS"
    FRSIRT = "FRSIRT"
    FULL_DISCLOSURE = "FULLDISCLOSURE"  # FULLDISC
    GAIM = "GAIM"
    GENTOO = "GENTOO"
    GENTOOBZ = "GENTOOBZ"
    GIT = "GIT"
    GNOME = "GNOME"
    GNUPG = "GNUPG"
    GOOGLE = "GOOGLE"
    HP = "HP"
    HW_VENDOR = "HW_VENDOR"  # HWVENDOR
    IBM = "IBM"
    IDEFENSE = "IDEFENSE"
    INTERNET = "INTERNET"
    ISC = "ISC"
    ISEC = "ISEC"
    IT = "IT"
    JBOSS = "JBOSS"
    JPCERT = "JPCERT"
    KERNELBUGZILLA = "KERNELBUGZILLA"
    KERNELSEC = "KERNELSEC"
    LKML = "LKML"
    LWN = "LWN"
    MACROMEDIA = "MACROMEDIA"
    MAGEIA = "MAGEIA"
    MAILINGLIST = "MAILINGLIST"
    MILW0RM = "MILW0RM"
    MIT = "MIT"
    MITRE = "MITRE"
    MOZILLA = "MOZILLA"
    MUTTDEV = "MUTTDEV"
    NETDEV = "NETDEV"
    NISCC = "NISCC"
    NOVALUE = ""
    NVD = "NVD"
    OCERT = "OCERT"
    OPENOFFICE = "OPENOFFICE"  # OPENOFFICE.ORG
    OPENSSL = "OPENSSL"
    OPENSUSE = "OPENSUSE"
    ORACLE = "ORACLE"
    OSS = "OSS"
    OSS_SECURITY = "OSSSECURITY"
    OSV = "OSV"
    PHP = "PHP"
    PIDGIN = "PIDGIN"
    POSTGRESQL = "POSTGRESQL"
    PRESS = "PRESS"
    REAL = "REAL"
    REDHAT = "REDHAT"
    RESEARCHER = "RESEARCHER"
    RT = "RT"
    SAMBA = "SAMBA"
    SECALERT = "SECALERT"
    SECUNIA = "SECUNIA"
    SECURITYFOCUS = "SECURITYFOCUS"
    SKO = "SKO"
    SQUID = "SQUID"
    SQUIRRELMAIL = "SQUIRRELMAIL"
    SUN = "SUN"
    SUNSOLVE = "SUNSOLVE"
    SUSE = "SUSE"
    TWITTER = "TWITTER"
    UBUNTU = "UBUNTU"
    UPSTREAM = "UPSTREAM"
    VENDOR_SEC = "VENDORSEC"
    VULNWATCH = "VULNWATCH"
    WIRESHARK = "WIRESHARK"
    XCHAT = "XCHAT"
    XEN = "XEN"
    XPDF = "XPDF"

    @property
    def private(self):
        return {
            # PRIVATE_SOURCES from SFM2
            self.ADOBE,
            self.APPLE,
            self.CERT,
            self.CUSTOMER,
            self.DISTROS,
            self.GOOGLE,
            self.HW_VENDOR,
            self.MOZILLA,
            self.OPENSSL,
            self.REDHAT,
            self.RESEARCHER,
            self.SECUNIA,
            self.UPSTREAM,
            self.XEN,
            self.VENDOR_SEC,
            self.SUN,
        }

    @property
    def ambiguous(self):
        return {
            self.DEBIAN,
            self.MAGEIA,
            self.GENTOO,
            self.SUSE,
            self.UBUNTU,
        }

    @property
    def public(self):
        return {
            self.ASF,
            self.BIND,
            self.BK,
            self.BUGTRAQ,
            self.BUGZILLA,
            self.CERTFI,
            self.CORELABS,
            self.CVE,
            self.DAILYDAVE,
            self.FEDORA,
            self.FETCHMAIL,
            self.FREEDESKTOP,
            self.FREERADIUS,
            self.FRSIRT,
            self.FULL_DISCLOSURE,
            self.GAIM,
            self.GENTOOBZ,
            self.GIT,
            self.GNOME,
            self.GNUPG,
            self.HP,
            self.IBM,
            self.IDEFENSE,
            self.INTERNET,
            self.ISC,
            self.ISEC,
            self.IT,
            self.JBOSS,
            self.JPCERT,
            self.KERNELBUGZILLA,
            self.KERNELSEC,
            self.LKML,
            self.LWN,
            self.MACROMEDIA,
            self.MAILINGLIST,
            self.MILW0RM,
            self.MIT,
            self.MITRE,
            self.MUTTDEV,
            self.NETDEV,
            self.NISCC,
            self.NOVALUE,
            self.OCERT,
            self.OPENOFFICE,
            self.OPENSUSE,
            self.ORACLE,
            self.OSS,
            self.OSS_SECURITY,
            self.PHP,
            self.PIDGIN,
            self.POSTGRESQL,
            self.PRESS,
            self.REAL,
            self.RT,
            self.SAMBA,
            self.SECALERT,
            self.SECURITYFOCUS,
            self.SKO,
            self.SQUID,
            self.SQUIRRELMAIL,
            self.SUNSOLVE,
            self.TWITTER,
            self.VULNWATCH,
            self.WIRESHARK,
            self.XCHAT,
            self.XPDF,
        }

    @property
    def allowed(self):
        return {
            self.ADOBE,
            self.APPLE,
            self.BUGTRAQ,
            self.CERT,
            self.CUSTOMER,
            self.CVE,
            self.DEBIAN,
            self.DISTROS,
            self.FULL_DISCLOSURE,
            self.GENTOO,
            self.GIT,
            self.GOOGLE,
            self.HW_VENDOR,
            self.INTERNET,
            self.LKML,
            self.MAGEIA,
            self.MOZILLA,
            self.OPENSSL,
            self.ORACLE,
            self.OSS_SECURITY,
            self.REDHAT,
            self.RESEARCHER,
            self.SECUNIA,
            self.SKO,
            self.SUN,
            self.SUSE,
            self.TWITTER,
            self.UBUNTU,
            self.UPSTREAM,
            self.VENDOR_SEC,
            self.XEN,
        }

    @property
    def from_snippet(self):
        return {
            self.CVEORG,
            self.NVD,
            self.OSV,
        }

    def is_private(self):
        """
        Returns True if the source is private, False otherwise.

        Note that the following sources can be both public and private:
        DEBIAN, MAGEIA, GENTOO, SUSE, UBUNTU
        """
        return self in (self.private | self.ambiguous)

    def is_public(self):
        """
        Returns True if the source is public, False otherwise.

        Note that the following sources can be both public and private:
        DEBIAN, MAGEIA, GENTOO, SUSE, UBUNTU
        """
        return self in (self.public | self.ambiguous)

    def is_allowed(self):
        """
        Returns True if the source is allowed (not historical), False otherwise.
        """
        return self in self.allowed

    def is_from_snippet(self):
        """
        Returns True if the source is Snippet, False otherwise.
        """
        return self in self.from_snippet
