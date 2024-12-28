from gmssl import sm2, func

def generate_SM2_key():
    crypt = sm2.CryptSM2(private_key=None, public_key=None)
    private_key = func.random_hex(crypt.para_len)
    public_key = crypt._kg(int(private_key, 16), crypt.ecc_table['g'])

    return private_key, public_key

if __name__ == '__main__':
    private_key, public_key = generate_SM2_key()
    print('生成的SM2私钥为:', private_key)
    print('对应的SM2公钥为:', public_key)