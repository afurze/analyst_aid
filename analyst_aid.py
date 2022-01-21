from datetime import datetime
import re
import requests
import vt


# https://docs.abuseipdb.com/#check-endpoint
def check_ip_abuse_ipdb(ipAddr):
    ABUSE_IPDB_BASE = 'https://api.abuseipdb.com/api/v2'

    # API key is registered to afurze@glacierbancorp.com
    ABUSE_IPDB_API_KEY = # Redacted

    headers = {
        'Key': ABUSE_IPDB_API_KEY,
        'Accept': 'application/json'
    }

    targetURL = ABUSE_IPDB_BASE + '/check?maxAgeInDays=90&ipAddress=' + ipAddr
    resp = requests.get(targetURL, headers=headers)

    print('------------------------------------------------------------------')
    print('Abuse IPDB Report:')
    # Check we got a good result
    if resp.status_code == 200:
        data = resp.json()['data']
        print('IP Address:\t\t' + data['ipAddress'])
        print('Whitelisted:\t\t' + str(data['isWhitelisted']))
        print('Hostnames:\t\t')
        for x in range(len(data['hostnames'])):
            print('\t' + data['hostnames'][x])
        print('Abuse Confidence Score:\t' + str(data['abuseConfidenceScore']))
        print('Country:\t\t' + data['countryCode'])
        if data['usageType'] is not None:
            print('Usage Type:\t\t' + data['usageType'])
        print('Domain:\t\t\t' + data['domain'])
        print('Reports:\t\t' + str(data['totalReports']))
        if data['lastReportedAt'] is not None:
            print('Last Reported:\t\t' + data['lastReportedAt'])

    else:
        print('Error occurred.')
    print('------------------------------------------------------------------')


# Use VirusTotal 'vt' library to make API calls easier
# https://developers.virustotal.com/reference/ip-object
def check_ip_vt(ipAddr):
    client = vt.Client() # Redacted

    print('------------------------------------------------------------------')
    print('Virus Total Report:')

    report = client.get('/ip_addresses/' + ipAddr).json()['data']['attributes']

    print('IP Address:\t\t' + ipAddr)
    lastModified = datetime.utcfromtimestamp(report['last_modification_date']).strftime('%Y-%m-%d')
    print('Last VT Update:\t\t' + lastModified)

    stats = report['last_analysis_stats']
    print('Harmless:\t\t' + str(stats['harmless']))
    print('Malicious:\t\t' + str(stats['malicious']))
    print('Suspicious:\t\t' + str(stats['suspicious']))
    print('Undetected:\t\t' + str(stats['undetected']))

    resolutions = client.get('/ip_addresses/' + ipAddr + '/resolutions')
    resolutions = resolutions.json()['data']
    for item in resolutions:
        print('Host:\t\t\t' + item['attributes']['host_name'])

    print('------------------------------------------------------------------')
    client.close()


def main():
    print('               .---. .---.')
    print('               :     : o   :    me want cookie!')
    print('           _..-:   o :     :-.._    /')
    print('       .-\'\'  \'  `---\' `---\' \"   ``-.')
    print('     .\'   \"   \'  \"  .    \"  . \'  \"  `.')
    print('    :   \'.---.,,.,...,.,.,.,..---.  \' ;')
    print('    `. \" `.                     .\' \" .\'')
    print('     `.  \'`.                   .\' \' .\'')
    print('      `.    `-._           _.-\' \"  .\'  .----.')
    print('        `. \"    \'\"--...--\"\'  . \' .\'  .\'  o   `.')
    print('        .\'`-._\'    \" .     \" _.-\'`. :       o  :')
    print('      .\'      ```--.....--\'\'\'    \' `:_ o       :')
    print('    .\'    \"     \'         \"     \"   ; `.;\";\";\";\'')
    print('   ;         \'       \"       \'     . ; .\' ; ; ;')
    print('  ;     \'         \'       \'   \"    .\'      .-\'')
    print('  \'  \"     \"   \'      \"           \"    _.-\'')

    print('NOM NOM NOM, me Cookie Monster!')

    targetIP = input('Give Cookie Monster tasty IP: ')

    # Check input is a valid IPv4 address
    while not re.match('(?:[0-9]{1,3}\.){3}[0-9]{1,3}', targetIP):
        print("Invalid address.")
        targetIP = input('Give Cookie Monster tasty IP: ')

    check_ip_abuse_ipdb(targetIP)
    check_ip_vt(targetIP)


if __name__ == '__main__':
    main()
