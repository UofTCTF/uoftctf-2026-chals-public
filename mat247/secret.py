from Crypto.Random import random
import numpy as np
import galois

def gen_commuting_matrix(A):
    GF = galois.GF(202184226278391025014930169562408816719)
    s = GF([[0]*12 for i in range(12)])
    for i in range(12):
        s += np.linalg.matrix_power(A, i)*random.randrange(202184226278391025014930169562408816719)
    return s
        
