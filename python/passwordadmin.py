from Crypto.PublicKey import RSA
import json
import uuid
import base64
import sys
import hashlib
import getpass

data_dir = "data/password.json"
public_key_dir = "public"
private_key_dir = "private"
cipher_dir = "data/cipher.json"

cipher_data = json.load(open(cipher_dir, 'r'), 'utf-8')
cipher_list = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512
}


def generate_key(passpharse):
    encode_passpharse = passpharse
    for step in cipher_data["way"]:
        encode_passpharse = cipher_list[step](encode_passpharse).digest()
    r = RSA.generate(2048)
    data_f = open(data_dir, 'w')
    data_f.write('{}')
    data_f.close()
    pub_f = open(public_key_dir, 'w')
    pub_f.write(r.exportKey("OpenSSH"))
    pub_f.close()
    pri_f = open(private_key_dir, 'w')
    pri_f.write(r.exportKey("PEM", encode_passpharse))
    pri_f.close()


def save_password(domain, username, password):
    jsondata = json.load(open(data_dir), 'utf-8')
    pub_key = RSA.importKey(open(public_key_dir))

    encript_data = base64.encodestring(pub_key.encrypt(password, uuid.uuid4().hex)[0])
    if domain not in jsondata:
        jsondata[domain] = {}
    if username not in jsondata[domain]:
        jsondata[domain][username] = []
    if (not jsondata[domain][username]) or (encript_data != jsondata[domain][username][-1]):
        jsondata[domain][username].append(encript_data)
    json.dump(jsondata, open(data_dir, 'w'), 'utf-8')


def get_password(domain, username, passpharse, passwdindex=-1):
    jsondata = json.load(open(data_dir), 'utf-8')
    encode_passpharse = passpharse
    for step in cipher_data["way"]:
        encode_passpharse = cipher_list[step](encode_passpharse).digest()

    pri_key = RSA.importKey(open(private_key_dir), encode_passpharse)

    if domain not in jsondata or jsondata[domain] == {}:
        print "domain not found"
        return ""
    if username not in jsondata[domain] or jsondata[domain][username] == []:
        print "username not found"
        return ""
    else:
        return pri_key.decrypt(base64.decodestring(jsondata[domain][username][passwdindex]))


def get_all_password(domain, passpharse, passwdindex=-1):
    jsondata = json.load(open(data_dir), 'utf-8')
    encode_passpharse = passpharse
    for step in cipher_data["way"]:
        encode_passpharse = cipher_list[step](encode_passpharse).digest()

    pri_key = RSA.importKey(open(private_key_dir), encode_passpharse)
    if domain not in jsondata or jsondata[domain] == {}:
        print "domain not found"
        return {}
    else:
        return {
            k: pri_key.decrypt(base64.decodestring(v[passwdindex])) for k, v in jsondata[domain].iteritems()
        }


def get_domains():
    jsondata = json.load(open(data_dir), 'utf-8')
    return jsondata.keys()


def main():
    if len(sys.argv) > 1:
        args = sys.argv[1]
    else:
        args = ""

    if args == "--save" or args == "-s":
        domain = raw_input("input website domain:")
        username = raw_input("input user name:")
        password = getpass.getpass("input user password:")
        save_password(domain, username, password)
    elif args == "--list" or args == "-l":
        print ','.join(get_domains())
    elif args == "--forget" or args == "-f":
        domain = raw_input("input website domain:")
        username = raw_input("input user name:")
        passpharse = getpass.getpass('input private key passpharse:')
        print get_password(domain, username, passpharse)
    elif args == "--forgetall" or args == "-fa":
        domain = raw_input("input website domain:")
        passpharse = getpass.getpass('input private key passpharse:')
        print '\n'.join(["%s: %s" % (k, v) for k, v in get_all_password(domain, passpharse).iteritems()])
    elif args == "--generate" or args == "-g":
        ok_str = raw_input("generate was drop password table(y/n)")
        ok_str = ok_str.lower()
        if ok_str == 'y':
            password = getpass.getpass("input private key passpharse:")
            password_repeat = getpass.getpass("input private key passpharse again:")
            if password == password_repeat:
                generate_key(password)
            else:
                print "your password do not match"
    else:
        print "usage: passwordadmin --[save|list|forget|forgetall|generate] or passwordadmin -[s|l|f|fa|g]"


if __name__ == '__main__':
    main()