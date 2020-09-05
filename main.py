import sympy as sp

alpha26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
alpha29 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ.!?"

#alphameme = "ABCDEFGHIJKLMNOPQRSTUVWXYZ?!@"


def encrypt(plaintext, a, alpha):
    if len(plaintext) % 2 == 1:
        plaintext += "X"
    p = stringToMatrix(plaintext, alpha)
    c = a * p
    return matrixToString(c, alpha)


def decrypt(ciphertext, a, alpha):
    #det = a.det()
    #inverseDet = inverse(det, len(alpha))
    #inverseA = a ** -1 * det * inverseDet
    inverseA = a.inv_mod(len(alpha))
    inverseA = inverseA.applyfunc(lambda x: x % len(alpha))
    return encrypt(ciphertext, inverseA, alpha)


def crack(plaintext, ciphertext, alpha):
    #plaintext = plaintext[0:4]
    #ciphertext = ciphertext[0:4]
    plainM = sp.Matrix([[alpha.index(plaintext[0]),
                         alpha.index(plaintext[2])],
                        [alpha.index(plaintext[1]),
                         alpha.index(plaintext[3])]])
    cipherM = sp.Matrix(
        [[alpha.index(ciphertext[0]),
          alpha.index(ciphertext[2])],
         [alpha.index(ciphertext[1]),
          alpha.index(ciphertext[3])]])
    a = cipherM * plainM.inv_mod(len(alpha))
    return a.applyfunc(lambda x: x % len(alpha))


def inverse(a, b):
    for i in range(1, b):
        if (i * a) % b == 1:
            return i
    return None


def stringToMatrix(string, alpha):
    row1 = []
    row2 = []
    for i in range(len(string)):
        if i % 2 == 0:
            row1.append(alpha.index(string[i]))
        else:
            row2.append(alpha.index(string[i]))
    return sp.Matrix([row1, row2])


def matrixToString(m, alpha):
    string = ""
    for j in range(m.cols):
        for k in m.col(j):
            string += alpha[k % len(alpha)]
    return string


def crackPasswords():

    alpha = ""
    for i in range(33, 94):
        alpha += chr(i)

    usernames = []
    passwords = []

    infile = open("passwords-v4.txt", "r")
    for line in infile.readlines():
        line = line.strip()
        (w1, w2) = line.split()
        usernames.append(w1)
        passwords.append(w2)
    infile.close()

    commonPasswords = []

    infile = open("common-passwords.txt", "r")
    for line in infile.readlines():
        line = line.strip()
        (w1) = line.split()
        w1 = w1[0]
        containsDigit = any(char.isdigit() for char in w1)
        if len(w1) > 6 and not containsDigit:
            commonPasswords.append(w1)
    infile.close()

    for pw in passwords:
        print(usernames[passwords.index(pw)])
        for common in commonPasswords:
            common = common.upper()
            try:
                matrix = crack(common, pw, alpha)
                if encrypt(common, matrix,
                           alpha) == pw[0:len(common) + (len(common) % 2)]:
                    return matrix, usernames[passwords.index(pw)], decrypt(
                        pw, matrix, alpha)
            except ValueError:
                pass


def decryptAll(matrix):

    alpha = ""
    for i in range(33, 94):
        alpha += chr(i)

    usernames = []
    passwords = []

    infile = open("passwords-v4.txt", "r")
    for line in infile.readlines():
        line = line.strip()
        (w1, w2) = line.split()
        usernames.append(w1)
        passwords.append(w2)
    infile.close()

    commonPasswords = []

    infile = open("common-passwords.txt", "r")
    for line in infile.readlines():
        line = line.strip()
        (w1) = line.split()
        w1 = w1[0]
        containsDigit = any(char.isdigit() for char in w1)
        if len(w1) > 6 and not containsDigit:
            commonPasswords.append(w1)
    infile.close()

    for i in range(len(passwords)):
        print(usernames[i], decrypt(passwords[i], matrix, alpha))


#print(encrypt("IAMGOD", sp.Matrix([[1, 3], [5, 6]]), alpha26))
#print(decrypt("IOESXK", sp.Matrix([[1, 3], [5, 6]]), alpha26))
#print(crack("HILL", "QPVK", alpha26))

#print(crackPasswords())
#print(decryptAll(sp.Matrix([[32, 17],[27, 13]])))
#encryptionMatrix = sp.Matrix([[32, 17],[27, 13]])
#commonPassword = {"2018kgatesma": "LACROSSE!*$X"}
#recognizablePasswordUsernames = {"2018emoar": "MAXIMUS89X", "2018sbaek": "GENESIS*3X"}

plaintext = "YAYSECONDQUARTER"
print("plaintext:", plaintext)
print("hill 2x2 encode:",
      encrypt(plaintext, sp.Matrix([[9, 14], [22, 7]]), alpha29))
print(
    "hill 2x2 decode:",
    decrypt(
        encrypt(plaintext, sp.Matrix([[9, 14], [22, 7]]), alpha29),
        sp.Matrix([[9, 14], [22, 7]]), alpha29))
print(
    "hill 2x2 crack:",
    crack(plaintext, encrypt(plaintext, sp.Matrix([[9, 14], [22, 7]]),
                             alpha29), alpha29))

print(encrypt("ANIKETH", sp.Matrix([[3, 13], [11, 7]]), alpha29))
