import base64
from argparse import ArgumentParser
import sys


def main(argv):
   parser = ArgumentParser()
   parser.add_argument('--filename', metavar='FILENAME', type=str, required=True, help="Path to original MOHA.exe")
   parser.add_argument('--backup', metavar='BACKUP_FILENAME', type=str, default='', help="Path where to make a backup of the original file")
   parser.add_argument('--domain', metavar='DOMAIN', type=str, required=True, help="6-character domain to replace ea.com with")
   parser.add_argument('--publickey', metavar='PUBLICKEY_HEX', type=str, required=True, help="1024-bit public key of the desired host's issuer certificate in hex format")
   args = parser.parse_args(argv[1:])

   # To turn off cert validation, patch these bytes:
   # MOHA.exe:
   # patch1 = ("85ED 0F 84 2F 09 00 00 5C5210 0F 85 25 09 00 00", "85ED 90 90 90 90 90 90 5C5210 90 90 90 90 90 90")
   # MOHAServer.exe:
   # patch1 = ("85ED 0F 84 2F 09 00 00 395C2410 0F 85 25 09 00 00", "85ED 90 90 90 90 90 90 395C2410 90 90 90 90 90 90")
   # patch2 = ("85C0 0F 84 6D000000", "85C0 90 E9 6D000000")
   # patch3 = ("85F6 B8 01 00 00 00 7F 17", "85F6 90 90 31 C0 40 75 17")
   # patch4 = ("81 E1 EE 0F 00 00", "33 C9 90 90 90 90")

   oldDomain = "ea.com"
   newDomain = args.domain

   if len(newDomain) != len(oldDomain):
      print("Domain must be {} characters long".format(len(oldDomain)))
      return 1

   oldKey = """
9275A15B080240B89B402FD59C71C4515871D8F02D937FD30C8B1C7DF92A0486
F190D1310ACBD8D41412903B356A0651494CC575EE0A462980F0D53A51BA5D6A
1937334368252DFEDF9526367C4364F156170EF167D5695420FB3A55935DD497
BC3AD58FD244C59AFFCD0C31DB9D947CA66666FB4BA75EF8644E28B1A6B87395
"""
   oldKeyStr = oldKey.replace('\n', '')
   newKeyStr = args.publickey.replace(' ', '').replace('\n', '').replace(':', '').upper()

   if len(newKeyStr) != 256:
      print("Publickey must be 1024 bits long, is {}".format(len(newKeyStr) * 8 / 2))
      return 1

   oldKey = base64.b16decode(oldKeyStr)
   newKey = base64.b16decode(newKeyStr)
   oldDomain = oldDomain.encode('utf-8')
   newDomain = newDomain.encode('utf-8')

   with open(args.filename, "rb") as fp:
      content = fp.read()

   if args.backup:
      with open(args.backup, "wb") as fp:
         fp.write(content)

   if not oldKey in content or not oldDomain in content:
      print("Unable to patch this executable")
      return 1

   content = content.replace(oldKey, newKey)
   content = content.replace(oldDomain, newDomain)

   with open(args.filename, "wb") as fp:
      fp.write(content)

   print("Done processing")

if __name__ == '__main__':
   sys.exit(main(sys.argv))
