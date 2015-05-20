__author__ = 'ricardo.moreira@acad.pucrs.br'

import base64
from Crypto.Cipher import AES

#
# tasks
#

task_1 = {
    'task': 'decrypt',
    'mode': AES.MODE_CBC,
    'key': '140b41b22a29beb4061bda66b6747e14',
    'buffer': '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee'
              '2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'
}

task_2 = {
    'task': 'decrypt',
    'mode': AES.MODE_CBC,
    'key': '140b41b22a29beb4061bda66b6747e14',
    'buffer': '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48'
              'e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'
}

task_3 = {
    'task': 'decrypt',
    'mode': AES.MODE_CTR,
    'key': '36f18357be4dbd77f050515c73fcf9f2',
    'buffer': '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc3'
              '88d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'

}

task_4 = {
    'task': 'decrypt',
    'mode': AES.MODE_CTR,
    'key': '36f18357be4dbd77f050515c73fcf9f2',
    'buffer': '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa'
              '0e311bde9d4e01726d3184c34451'
}

task_5 = {
    'task': 'encrypt',
    'mode': AES.MODE_CTR,
    'key': '36f18357be4dbd77f050515c73fcf9f2',
    'buffer': '5468697320697320612073656e74656e636520746f20626520656e63727970746564207573696e67204145532061'
              '6e6420435452206d6f64652e'
}

task_6 = {
    'task': 'encrypt',
    'mode': AES.MODE_CBC,
    'key': '140b41b22a29beb4061bda66b6747e14',
    'buffer': '4e657874205468757273646179206f6e65206f66207468652062657374207465616d7320696e2074686520776f726c64207'
              '7696c6c2066616365206120626967206368616c6c656e676520696e20746865204c696265727461646f726573206461'
              '20416d6572696361204368616d70696f6e736869702e'
}


def aes_decrypt(key, mode, iv, cipher):
    if mode == AES.MODE_CTR:
        import Crypto.Util.Counter
        ctr = Crypto.Util.Counter.new(128, initial_value=long(iv.encode("hex"), 16))
        aes = AES.new(key, mode, counter=ctr)
    else:
        aes = AES.new(key, mode, iv)

    plain = aes.decrypt(cipher)
    return plain


def aes_encrypt(key, mode, plain):
    if mode == AES.MODE_CTR:
        import Crypto.Util.Counter
        ctr = Crypto.Util.Counter.new(128, initial_value=long(iv.encode("hex"), 16))
        aes = AES.new(key, mode, counter=ctr)
        _plain = plain
    else:
        # CBC requires padding, default block size = 16
        aes = AES.new(key, mode, iv)
        npad = 16 - (len(plain) % 16)
        pad = chr(npad)*npad
        plain_padded = plain + pad
        _plain = plain_padded

    print ' plain: |', _plain, '|'
    cipher = aes.encrypt(_plain)
    return cipher


def hex2ascii(buffer):
    return base64.b16decode(buffer.upper())


if __name__ == '__main__':
    tasks = [task_1, task_2, task_3, task_4, task_5, task_6]
    for t in tasks:
        print '=> task', t['task'], 'mode', t['mode'], 'key', t['key']
        print ' buffer:', t['buffer']

        key = hex2ascii(t['key'])
        buffer_in = hex2ascii(t['buffer'])

        if t['task'] == 'decrypt':
            iv = buffer_in[:16]
            buffer = buffer_in[16:]
            plain = aes_decrypt(key, t['mode'], iv, buffer)
            print ' decrypted:', plain, 'hex:', plain.encode("hex")

        if t['task'] == 'encrypt':
            plain = buffer_in
            print ' plain:', plain
            cipher = aes_encrypt(key, t['mode'], plain)
            print ' encrypted:', cipher.encode("hex")