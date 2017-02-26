import re, os
import itertools

import wifinetctl.subprocess_compat as subprocess
from pbkdf2 import PBKDF2
from wifinetctl.utils import ensure_file_exists
from wifinetctl.exceptions import ConnectionError

def configuration(interface, cell, passkey=None):
    """
    Returns a dictionary of configuration options for cell
    Asks for a password if necessary
    """
    if not cell.encrypted:
        return {
            'Description': 'Automatically generated profile by python-wifinetctl',
            'Interface': interface,
            'Connection': 'wireless',
            'ESSID': cell.ssid,
            'IP':'dhcp',
        }
    else:
        if cell.encryption_type.startswith('wpa'):
            if len(passkey) != 64:
                passkey = "\\\"" + PBKDF2(passkey, cell.ssid, 4096).hexread(32)

            return {
                'Description': 'Automatically generated profile by python-wifinetctl',
                'Interface': interface,
                'Connection': 'wireless',
                'Security': 'wpa',
                'ESSID': cell.ssid,
                'IP':'dhcp',
                'Key':passkey
            }
        elif cell.encryption_type == 'wep':
            # Pass key lengths in bytes for WEP depend on type of key and key length:
            #
            #       64bit   128bit   152bit   256bit
            # hex     10      26       32       58
            # ASCII    5      13       16       29
            #
            # (source: https://en.wikipedia.org/wiki/Wired_Equivalent_Privacy)
            #
            # ASCII keys need to be prefixed with an s: in the interfaces file in order to work with linux' wireless
            # tools

            ascii_lengths = (5, 13, 16, 29)
            if len(passkey) in ascii_lengths:
                # we got an ASCII passkey here (otherwise the key length wouldn't match), we'll need to prefix that
                # with s: in our config for the wireless tools to pick it up properly
                passkey = "\\\"" + passkey

            return {
                'Description': 'Automatically generated profile by python-wifinetctl',
                'Interface': interface,
                'Connection': 'wireless',
                'Security': 'wep',
                'ESSID': cell.ssid,
                'IP':'dhcp',
                'Key':passkey
            }
        else:
            raise NotImplementedError

class Scheme(object):
    """
    Saved and retrieve configuration for connecting to a wireless network.
    This class provides a Python interface to the /etc/netctl/profile files.
    """
    interfaces = '/etc/netctl/'
    def __init__(self, interface, name, options=None):
        self.interface = interface
        self.name = name
        self.options = options or {}

    def __str__(self):
        """
        Returns the representation of a scheme that you would need
        in the /etc/netctl/Profile file.
        """
        options = ''.join("\n{k}={v}".format(k=k, v=v) for k, v in self.options.items())
        return options + '\n'

    def __repr__(self):
        return 'Scheme(interface={interface!r}, name={name!r}, options={options!r}'.format(**vars(self))

    @classmethod
    def all(cls, interface):
        """
        Returns an list of saved schemes.
        """
        regexp = interface + "-(.{1,})"
        scheme_re = re.compile(regexp)
        AllSaved = []
        if os.path.isdir(cls.interfaces):
            return extract_schemes(interface, cls.interfaces, scheme_class=cls)
        else:
            raise IOError

    @classmethod
    def where(cls, interface, fn):
        return list(filter(fn, cls.all(interface)))

    @classmethod
    def find(cls, interface, name):
        """
        Returns a :class:'Scheme' or 'None' based on interface and name.
        """
        try:
            return cls.where(interface, lambda s: s.interface == interface and s.name == name)[0]
        except IndexError:
            return None

    @classmethod
    def for_cell(cls, interface, name, cell, passkey=None):
        """
        Intuits the configuration needed for a specific
        :class:`Cell` and creates a :class:`Scheme` for it.
        """
        return cls(interface, name, configuration(interface, cell, passkey))

    def delete(self):
        """
        Deletes the configuration from the :attr:`interfaces` file.
        """
        Wireless_File =  self.interfaces + self.interface + '-' + self.name
        os.remove(Wireless_File)

    def save(self):
        """
        Writes the configuration to the :attr:`interfaces` file.
        """
        Wireless_File = self.interfaces + self.interface + '-' + self.name
        assert not self.find(self.interface, self.name), "This scheme already exists"

        with open(Wireless_File, 'a') as f:
            f.write(str(self))

    @property
    def iface(self):
        return '{0}-{1}'.format(self.interface, self.name)

    def as_args(self):
        args = list(itertools.chain.from_iterable(
            ('-o', '{k}={v}'.format(k=k, v=v)) for k, v in self.options.items()))

        return [self.interface + '=' + self.iface] + args

    def activate(self):
        """
        Connects to the network as configured in this scheme.
        """

        Wireless_File = self.interfaces + self.interface + '-' + self.name
        if os.path.exists(Wireless_File):
            subprocess.check_output(['netctl', 'stop-all'], stderr=subprocess.STDOUT)
            subprocess.check_output(['ip', 'link', 'set', self.interface, 'down'], stderr=subprocess.STDOUT)
            try:
                ifconnect_output = subprocess.check_output(['netctl', 'start', self.interface + '-' + self.name], stderr=subprocess.STDOUT)
            except:
		ifconnect_status = subprocess.Popen(['systemctl', 'status', 'netctl@' + self.interface + '\\x2d' + self.name + '.service'], stdout=subprocess.PIPE)
                out,err = ifconnect_status.communicate()
                if 'WPA association/authentication failed for interface \'wlan0\'' in out:
                    print 'bad Password!!!!!!!!!!!!!!!!'
                    raise Exception('BadPassword')
                subprocess.check_output(['rm', Wireless_File], stderr=subprocess.STDOUT)
        else:
            tmp_Wireless_File = '/tmp/' + self.interface + '-' + self.name
            with open(tmp_Wireless_File, 'a') as f:
                f.write(str(self))
            subprocess.check_output(['netctl', 'stop-all'], stderr=subprocess.STDOUT)
            subprocess.check_output(['ip', 'link', 'set', self.interface, 'down'], stderr=subprocess.STDOUT)
            ifconnect_output = subprocess.check_output(['netctl', 'start', self.interface + '-' + self.name], stderr=subprocess.STDOUT)
        if 'ifconnect_output' in locals():
            print ifconnect_output
        else:
            print "failed to connect"

    def parse_ifup_output(self, output):
        matches = bound_ip_re.search(output)
        if matches:
            return Connection(scheme=self, ip_address=matches.group('ip_address'))
        else:
            raise ConnectionError("Failed to connect to %r" % self)


"""
    def delete(self):
        "
        Deletes the configuration from the :attr:`interfaces` file.
        "
        iface = "iface %s-%s inet dhcp" % (self.interface, self.name)
        content = ''
        with open(self.interfaces, 'r') as f:
            skip = False
            for line in f:
                if not line.strip():
                    skip = False
                elif line.strip() == iface:
                    skip = True
                if not skip:
                    content += line
        with open(self.interfaces, 'w') as f:
            f.write(content)
"""

scheme_re = re.compile(r'/etc/netctl/+(?P<interface>[^-]+)(?:-(?P<name>\S+))?')

def extract_schemes(interface, interfaces, scheme_class=Scheme):
    if os.path.isdir(interfaces):
        for FileName in os.listdir(interfaces):
            if os.path.exists(interfaces + FileName):
                if interface in FileName:
                    Wireless_File = interfaces + FileName
                    result = scheme_re.match(Wireless_File)
                    if result:
                        options = {}
                        interface, scheme = result.groups()
                        with open(Wireless_File, 'r') as f:
                            tmp = f.read()
                            lines = tmp.splitlines()
                            while lines:
                                line = lines.pop(0)
                                if "Description=" in line:
                                    m = re.search(r'=(.{1,})', line)
                                    options['Description'] = m.group(1)
                                    continue
                                if "Interface=" in line:
                                    m = re.search('=(.{1,})', line)
                                    options['Interface'] = m.group(1)
                                    continue
                                if "Connection=" in line:
                                    m = re.search('=(.{1,})', line)
                                    options['Connection'] = m.group(1)
                                    continue
                                if "Security=" in line:
                                    m = re.search('=(.{1,})', line)
                                    options['Security'] = m.group(1)
                                    continue
                                if "IP=" in line:
                                    m = re.search('=(.{1,})', line)
                                    options['IP'] = m.group(1)
                                    continue
                                if "ESSID=" in line:
                                    m = re.search('=(.{1,})', line)
                                    options['ESSID'] = m.group(1)
                                    continue
                                if "Key=" in line:
                                    m = re.search('Key=(.{1,})', line)
                                    options['Key'] = m.group(1)
                                    continue
                                continue
                            scheme = scheme_class(interface, scheme, options)

                            yield scheme
