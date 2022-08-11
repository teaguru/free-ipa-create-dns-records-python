# - Created using: https://github.com/nordnet/python-freeipa-json
# call: python3 ./idm-record.py <zone_name> <login> <passord> <Record name> <target ip or Hostname> <record type>
# example: python3 ./idm-record.py 'zone_name' 'ipa login' 'password' 'testrecord, '10.0.0.99', 'arecord'
# <record type> could be 'arecord' or 'cnamerecord'

from markupsafe import re
import requests
import json
import logging
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
zone_name = sys.argv[1]
ipa_login=sys.argv[2]
ipa_password=sys.argv[3]
ipa_url= 'ipa-url-here'

class ipa(object):
    def __init__(self, server, sslverify=False):
        self.server = server
        self.sslverify = sslverify
        self.log = logging.getLogger(__name__)
        self.session = requests.Session()

    def login(self, user, password):
        rv = None
        ipaurl = 'https://{0}/ipa/session/login_password'.format(self.server)
        header = {'referer': ipaurl, 'Content-Type':
                  'application/x-www-form-urlencoded', 'Accept': 'text/plain'}
        login = {'user': user, 'password': password}
        rv = self.session.post(ipaurl, headers=header, data=login,
                               verify=self.sslverify)

        if rv.status_code != 200:
            self.log.warning('Failed to log {0} in to {1}'.format(
                user,
                self.server)
            )
            rv = None
        else:
            self.log.info('Successfully logged in as {0}'.format(user))
            # set login_user for use when changing password for self
            self.login_user = user
        return rv

    def makeReq(self, pdict):
        results = None
        ipaurl = 'https://{0}/ipa'.format(self.server)
        session_url = '{0}/session/json'.format(ipaurl)
        header = {'referer': ipaurl, 'Content-Type': 'application/json', 'server_version': '2.237',
                  'Accept': 'application/json'}

        data = {'id': 0, 'method': pdict['method'], 'params':
                [pdict['item'], pdict['params']]}

        self.log.debug('Making {0} request to {1}'.format(pdict['method'], session_url))

        request = self.session.post(
                session_url, headers=header,
                data=json.dumps(data),
                verify=self.sslverify
        )
        results = request.json()

        return results

    def dnsrecord_del(self, idnsname):
        m = {'item': [zone_name], 'method': 'dnsrecord_del', 'params': {'del_all': True}}
        m['params']['idnsname'] = idnsname
        request = self.makeReq(m)
        if request and request.get('error'):
            print(request['error']['message'])
        else:
            print(request['result'])
            if request['result']['value'][0] == idnsname:
                print(idnsname, 'deleted')
                return True
            else:
                return False

    def dnsrecord_add(self, idnsname, target, type):
        m = {'item': [zone_name], 'method': 'dnsrecord_add', 'params':
        {'all': True, 'raw': False}}
        if type == 'cnamerecord':
            m['params']['cnamerecord'] = target
            m['params']['idnsname'] = idnsname
        elif type == 'arecord':
            m['params']['arecord'] = target
            m['params']['idnsname'] = idnsname
        else:
            print('Wrong record type - ', type)
            return(False)
        request = self.makeReq(m)
        if request and request.get('error'):
            if request['error']['message'] == 'no modifications to be performed':
                print(request['error']['message'])
                print(request['error'])
                print(idnsname, ' was not created')
                print(idnsname, ' record is already exist or nothing to change')
                return(True)
            else:
                print(request['error']['message'])
                print(idnsname, 'creation error')
                return False
        print(request['result']['result'])
        if request['result']['result']['idnsname'][0] == idnsname:
            print(idnsname, " created sucessfully")
            return True
        return False

    def dnsrecord_check(self, idnsname, target, type):
        m = {'item': [zone_name], 'method': 'dnsrecord_find', 'params': {}}
        m['params']['idnsname'] = idnsname
        request = self.makeReq(m)
        if request['result']['result'] == []:
            print("doesn't exist")
            self.dnsrecord_add(idnsname, target, type)
            return(True)
        result = request['result']['result'][0]
        if 'arecord' in result:
            bcp_type = 'arecord'
            bcp_target = result['arecord']
        elif 'cnamerecord' in result:
            bcp_type = 'cnamerecord'
            bcp_target = result['cnamerecord']
        else:
            print('already exist record of different type')
            return False

        print(result)
        if type in result:
            if result['idnsname'][0] == idnsname and result[type][0] == target:
                print('record exist and it is correct')
                return True
            else:
                print('should fix')

                self.dnsrecord_del(idnsname)
                print('we are here')
                if self.dnsrecord_add(idnsname, target, type):
                    print('ok, record changed sucessfuly')
                else:
                    self.dnsrecord_add(idnsname, bcp_target, bcp_type)
                    print('bcp restored')
        else:
            print('we should change a record')
            self.dnsrecord_del(idnsname)
            if self.dnsrecord_add(idnsname, target, type):
                    print('ok, record changed sucessfuly')
            else:
                self.dnsrecord_add(idnsname, bcp_target, bcp_type)
                print('bcp restored')

        return(request['result']['result'][0])
         
ipa = ipa('ipa_url')
ipa.login(ipa_login, ipa_password)
reply = ipa.dnsrecord_check(sys.argv[3], test.sys.argv[3], sys.argv[3])
print(reply)
