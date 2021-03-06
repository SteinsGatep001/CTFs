# coding:utf-8
import sys
from pwn import *

def normalize(x):
    x = long(x)
    while True:
        bl = x.bit_length()
        if bl < 9:
            return int(x)
        x ^= 0x11b << (bl-9)


def add(a, b):
    #print 'add',a,b
    return a ^ b


def summ(g):
    s = 0
    for i in g:
        s = add(s, i)
    return s


def mul(a, b):
    #print 'mul',a,b
    x = 0
    y = a
    while b:
        if b & 1:
            x ^= y
        y = normalize(y << 1)
        b >>= 1
    return x


sheet = [[mul(i, j)for j in range(256)]for i in range(256)]
inv_sheet = [0]+[sheet[i].index(1) for i in range(1, 256)]


def div(a, b):
    assert b != 0
    return mul(a, inv_sheet[b])


def matmul(A, B):
    assert len(A[0]) == len(B)
    m = len(A)
    k = len(A[0])
    n = len(B[0])
    return [[summ(mul(A[i][l], B[l][j])for l in range(k))for j in range(n)]for i in range(m)]


our_mat = [
    [2, 3, 1, 1],
    [1, 2, 3, 1],
    [1, 1, 2, 3],
    [3, 1, 1, 2]]


def transpose(M):
    m = len(M)
    n = len(M[0])
    return [[M[j][i] for j in range(m)]for i in range(n)]


def det(m):
    #print 'det',m
    if len(m) == 1:
        return m[0][0]
    # if len(m)==2: return m[0][0]*m[1][1]-m[1][0]*m[0][1]
    n = len(m)
    return summ(mul(cofactor(m, 0, i), m[0][i]) for i in range(n))


def cofactor(m, r, c):
    n = len(m)
    return det([[m[i][j] for j in range(n) if j != c]for i in range(n) if i != r])


def invmat(M):
    n = len(M)
    M1 = [[cofactor(M, i, j) for j in range(n)]for i in range(n)]
    #print 'M1',M1
    d = det(M)
    assert d != 0
    dinv = inv_sheet[d]
    return [[mul(M1[i][j], dinv)for i in range(n)]for j in range(n)]


imat = invmat(our_mat)
#print imat

sig_table = [0x66, 0x38, 0x63, 0x34, 0x39, 0x30, 0x35, 0x36, 0x65, 0x34, 0x63, 0x63, 0x66, 0x39, 0x61,
             0x31, 0x31, 0x65, 0x30, 0x39, 0x30, 0x65, 0x61, 0x66, 0x34, 0x37, 0x31, 0x66, 0x34, 0x31, 0x38, 0x64]

byte_3920 = [0, 0, 0, 0, 0, 0, 2, 3, 9, 0xB, 0xD, 0xE, 4, 6, 0x12, 0x16, 0x1A, 0x1C, 6, 5, 0x1B, 0x1D, 0x17, 0x12, 8, 0xC, 0x24, 0x2C, 0x34, 0x38, 0xA, 0xF, 0x2D, 0x27, 0x39, 0x36, 0xC, 0xA, 0x36, 0x3A, 0x2E, 0x24, 0xE, 9, 0x3F, 0x31, 0x23, 0x2A, 0x10, 0x18, 0x48, 0x58, 0x68, 0x70, 0x12, 0x1B, 0x41, 0x53, 0x65, 0x7E, 0x14, 0x1E, 0x5A, 0x4E, 0x72, 0x6C, 0x16, 0x1D, 0x53, 0x45, 0x7F, 0x62, 0x18, 0x14, 0x6C, 0x74, 0x5C, 0x48, 0x1A, 0x17, 0x65, 0x7F, 0x51, 0x46, 0x1C, 0x12, 0x7E, 0x62, 0x46, 0x54, 0x1E, 0x11, 0x77, 0x69, 0x4B, 0x5A, 0x20, 0x30, 0x90, 0xB0, 0xD0, 0xE0, 0x22, 0x33, 0x99, 0xBB, 0xDD, 0xEE, 0x24, 0x36, 0x82, 0xA6, 0xCA, 0xFC, 0x26, 0x35, 0x8B, 0xAD, 0xC7, 0xF2, 0x28, 0x3C, 0xB4, 0x9C, 0xE4, 0xD8, 0x2A, 0x3F, 0xBD, 0x97, 0xE9, 0xD6, 0x2C, 0x3A, 0xA6, 0x8A, 0xFE, 0xC4, 0x2E, 0x39, 0xAF, 0x81, 0xF3, 0xCA, 0x30, 0x28, 0xD8, 0xE8, 0xB8, 0x90, 0x32, 0x2B, 0xD1, 0xE3, 0xB5, 0x9E, 0x34, 0x2E, 0xCA, 0xFE, 0xA2, 0x8C, 0x36, 0x2D, 0xC3, 0xF5, 0xAF, 0x82, 0x38, 0x24, 0xFC, 0xC4, 0x8C, 0xA8, 0x3A, 0x27, 0xF5, 0xCF, 0x81, 0xA6, 0x3C, 0x22, 0xEE, 0xD2, 0x96, 0xB4, 0x3E, 0x21, 0xE7, 0xD9, 0x9B, 0xBA, 0x40, 0x60, 0x3B, 0x7B, 0xBB, 0xDB, 0x42, 0x63, 0x32, 0x70, 0xB6, 0xD5, 0x44, 0x66, 0x29, 0x6D, 0xA1, 0xC7, 0x46, 0x65, 0x20, 0x66, 0xAC, 0xC9, 0x48, 0x6C, 0x1F, 0x57, 0x8F, 0xE3, 0x4A, 0x6F, 0x16, 0x5C, 0x82, 0xED, 0x4C, 0x6A, 0xD, 0x41, 0x95, 0xFF, 0x4E, 0x69, 4, 0x4A, 0x98, 0xF1, 0x50, 0x78, 0x73, 0x23, 0xD3, 0xAB, 0x52, 0x7B, 0x7A, 0x28, 0xDE, 0xA5, 0x54, 0x7E, 0x61, 0x35, 0xC9, 0xB7, 0x56, 0x7D, 0x68, 0x3E, 0xC4, 0xB9, 0x58, 0x74, 0x57, 0xF, 0xE7, 0x93, 0x5A, 0x77, 0x5E, 4, 0xEA, 0x9D, 0x5C, 0x72, 0x45, 0x19, 0xFD, 0x8F, 0x5E, 0x71, 0x4C, 0x12, 0xF0, 0x81, 0x60, 0x50, 0xAB, 0xCB, 0x6B, 0x3B, 0x62, 0x53, 0xA2, 0xC0, 0x66, 0x35, 0x64, 0x56, 0xB9, 0xDD, 0x71, 0x27, 0x66, 0x55, 0xB0, 0xD6, 0x7C, 0x29, 0x68, 0x5C, 0x8F, 0xE7, 0x5F, 3, 0x6A, 0x5F, 0x86, 0xEC, 0x52, 0xD, 0x6C, 0x5A, 0x9D, 0xF1, 0x45, 0x1F, 0x6E, 0x59, 0x94, 0xFA, 0x48, 0x11, 0x70, 0x48, 0xE3, 0x93, 3, 0x4B, 0x72, 0x4B, 0xEA, 0x98, 0xE, 0x45, 0x74, 0x4E, 0xF1, 0x85, 0x19, 0x57, 0x76, 0x4D, 0xF8, 0x8E, 0x14, 0x59, 0x78, 0x44, 0xC7, 0xBF, 0x37, 0x73, 0x7A, 0x47, 0xCE, 0xB4, 0x3A, 0x7D, 0x7C, 0x42, 0xD5, 0xA9, 0x2D, 0x6F, 0x7E, 0x41, 0xDC, 0xA2, 0x20, 0x61, 0x80, 0xC0, 0x76, 0xF6, 0x6D, 0xAD, 0x82, 0xC3, 0x7F, 0xFD, 0x60, 0xA3, 0x84, 0xC6, 0x64, 0xE0, 0x77, 0xB1, 0x86, 0xC5, 0x6D, 0xEB, 0x7A, 0xBF, 0x88, 0xCC, 0x52, 0xDA, 0x59, 0x95, 0x8A, 0xCF, 0x5B, 0xD1, 0x54, 0x9B, 0x8C, 0xCA, 0x40, 0xCC, 0x43, 0x89, 0x8E, 0xC9, 0x49, 0xC7, 0x4E, 0x87, 0x90, 0xD8, 0x3E, 0xAE, 5, 0xDD, 0x92, 0xDB, 0x37, 0xA5, 8, 0xD3, 0x94, 0xDE, 0x2C, 0xB8, 0x1F, 0xC1, 0x96, 0xDD, 0x25, 0xB3, 0x12, 0xCF, 0x98, 0xD4, 0x1A, 0x82, 0x31, 0xE5, 0x9A, 0xD7, 0x13, 0x89, 0x3C, 0xEB, 0x9C, 0xD2, 8, 0x94, 0x2B, 0xF9, 0x9E, 0xD1, 1, 0x9F, 0x26, 0xF7, 0xA0, 0xF0, 0xE6, 0x46, 0xBD, 0x4D, 0xA2, 0xF3, 0xEF, 0x4D, 0xB0, 0x43, 0xA4, 0xF6, 0xF4, 0x50, 0xA7, 0x51, 0xA6, 0xF5, 0xFD, 0x5B, 0xAA, 0x5F, 0xA8, 0xFC, 0xC2, 0x6A, 0x89, 0x75, 0xAA, 0xFF, 0xCB, 0x61, 0x84, 0x7B, 0xAC, 0xFA, 0xD0, 0x7C, 0x93, 0x69, 0xAE, 0xF9, 0xD9, 0x77, 0x9E, 0x67, 0xB0, 0xE8, 0xAE, 0x1E, 0xD5, 0x3D, 0xB2, 0xEB, 0xA7, 0x15, 0xD8, 0x33, 0xB4, 0xEE, 0xBC, 8, 0xCF, 0x21, 0xB6, 0xED, 0xB5, 3, 0xC2, 0x2F, 0xB8, 0xE4, 0x8A, 0x32, 0xE1, 5, 0xBA, 0xE7, 0x83, 0x39, 0xEC, 0xB, 0xBC, 0xE2, 0x98, 0x24, 0xFB, 0x19, 0xBE, 0xE1, 0x91, 0x2F, 0xF6, 0x17, 0xC0, 0xA0, 0x4D, 0x8D, 0xD6, 0x76, 0xC2, 0xA3, 0x44, 0x86, 0xDB, 0x78, 0xC4, 0xA6, 0x5F, 0x9B, 0xCC, 0x6A, 0xC6, 0xA5, 0x56, 0x90, 0xC1, 0x64, 0xC8, 0xAC, 0x69, 0xA1, 0xE2, 0x4E, 0xCA, 0xAF, 0x60, 0xAA, 0xEF, 0x40, 0xCC, 0xAA, 0x7B, 0xB7, 0xF8, 0x52, 0xCE, 0xA9, 0x72, 0xBC, 0xF5, 0x5C, 0xD0, 0xB8, 5, 0xD5, 0xBE, 6, 0xD2, 0xBB, 0xC, 0xDE, 0xB3, 8, 0xD4, 0xBE, 0x17, 0xC3, 0xA4, 0x1A, 0xD6, 0xBD, 0x1E, 0xC8, 0xA9, 0x14, 0xD8, 0xB4, 0x21, 0xF9, 0x8A, 0x3E, 0xDA, 0xB7, 0x28, 0xF2, 0x87, 0x30, 0xDC, 0xB2, 0x33, 0xEF, 0x90, 0x22, 0xDE, 0xB1, 0x3A, 0xE4, 0x9D, 0x2C, 0xE0, 0x90, 0xDD, 0x3D, 6, 0x96, 0xE2, 0x93, 0xD4, 0x36, 0xB, 0x98, 0xE4, 0x96, 0xCF, 0x2B, 0x1C, 0x8A, 0xE6, 0x95, 0xC6, 0x20, 0x11, 0x84, 0xE8, 0x9C, 0xF9, 0x11, 0x32, 0xAE, 0xEA, 0x9F, 0xF0, 0x1A, 0x3F, 0xA0, 0xEC, 0x9A, 0xEB, 7, 0x28, 0xB2, 0xEE, 0x99, 0xE2, 0xC, 0x25, 0xBC, 0xF0, 0x88, 0x95, 0x65, 0x6E, 0xE6, 0xF2, 0x8B, 0x9C, 0x6E, 0x63, 0xE8, 0xF4, 0x8E, 0x87, 0x73, 0x74, 0xFA, 0xF6, 0x8D, 0x8E, 0x78, 0x79, 0xF4, 0xF8, 0x84, 0xB1, 0x49, 0x5A, 0xDE, 0xFA, 0x87, 0xB8, 0x42, 0x57, 0xD0, 0xFC, 0x82, 0xA3, 0x5F, 0x40, 0xC2, 0xFE, 0x81, 0xAA, 0x54, 0x4D, 0xCC, 0x1B, 0x9B, 0xEC, 0xF7, 0xDA, 0x41, 0x19, 0x98, 0xE5, 0xFC, 0xD7, 0x4F, 0x1F, 0x9D, 0xFE, 0xE1, 0xC0, 0x5D, 0x1D, 0x9E, 0xF7, 0xEA, 0xCD, 0x53, 0x13, 0x97, 0xC8, 0xDB, 0xEE, 0x79, 0x11, 0x94, 0xC1, 0xD0, 0xE3, 0x77, 0x17, 0x91, 0xDA, 0xCD, 0xF4, 0x65, 0x15, 0x92, 0xD3, 0xC6, 0xF9, 0x6B, 0xB, 0x83, 0xA4, 0xAF, 0xB2, 0x31, 9, 0x80, 0xAD, 0xA4, 0xBF, 0x3F, 0xF, 0x85, 0xB6, 0xB9, 0xA8, 0x2D, 0xD, 0x86, 0xBF, 0xB2, 0xA5, 0x23, 3, 0x8F, 0x80, 0x83, 0x86, 9, 1, 0x8C, 0x89, 0x88, 0x8B, 7, 7, 0x89, 0x92, 0x95, 0x9C, 0x15, 5, 0x8A, 0x9B, 0x9E, 0x91, 0x1B, 0x3B, 0xAB, 0x7C, 0x47, 0xA, 0xA1, 0x39, 0xA8, 0x75, 0x4C, 7, 0xAF, 0x3F, 0xAD, 0x6E, 0x51, 0x10, 0xBD, 0x3D, 0xAE, 0x67, 0x5A, 0x1D, 0xB3, 0x33, 0xA7, 0x58, 0x6B, 0x3E, 0x99, 0x31, 0xA4, 0x51, 0x60, 0x33, 0x97, 0x37, 0xA1, 0x4A, 0x7D, 0x24, 0x85, 0x35, 0xA2, 0x43, 0x76, 0x29, 0x8B, 0x2B, 0xB3, 0x34, 0x1F, 0x62, 0xD1, 0x29, 0xB0, 0x3D, 0x14, 0x6F, 0xDF, 0x2F, 0xB5, 0x26, 9, 0x78, 0xCD, 0x2D, 0xB6, 0x2F, 2, 0x75, 0xC3, 0x23, 0xBF, 0x10, 0x33, 0x56, 0xE9, 0x21, 0xBC, 0x19, 0x38, 0x5B, 0xE7, 0x27, 0xB9, 2, 0x25, 0x4C, 0xF5, 0x25, 0xBA, 0xB, 0x2E, 0x41, 0xFB, 0x5B, 0xFB, 0xD7, 0x8C, 0x61, 0x9A, 0x59, 0xF8, 0xDE, 0x87, 0x6C, 0x94, 0x5F, 0xFD, 0xC5, 0x9A, 0x7B, 0x86, 0x5D, 0xFE, 0xCC, 0x91, 0x76, 0x88, 0x53, 0xF7, 0xF3, 0xA0, 0x55, 0xA2, 0x51, 0xF4, 0xFA, 0xAB, 0x58, 0xAC, 0x57, 0xF1, 0xE1, 0xB6, 0x4F, 0xBE, 0x55, 0xF2, 0xE8, 0xBD, 0x42, 0xB0, 0x4B, 0xE3, 0x9F, 0xD4, 9, 0xEA, 0x49, 0xE0, 0x96, 0xDF, 4, 0xE4, 0x4F, 0xE5, 0x8D, 0xC2, 0x13, 0xF6, 0x4D, 0xE6, 0x84, 0xC9, 0x1E, 0xF8, 0x43, 0xEF, 0xBB, 0xF8, 0x3D, 0xD2, 0x41, 0xEC, 0xB2, 0xF3, 0x30, 0xDC, 0x47, 0xE9, 0xA9, 0xEE, 0x27, 0xCE, 0x45, 0xEA, 0xA0, 0xE5, 0x2A, 0xC0, 0x7B, 0xCB, 0x47, 0x3C, 0xB1, 0x7A, 0x79, 0xC8, 0x4E, 0x37, 0xBC, 0x74, 0x7F, 0xCD, 0x55, 0x2A, 0xAB, 0x66, 0x7D, 0xCE, 0x5C, 0x21, 0xA6, 0x68, 0x73, 0xC7, 0x63, 0x10, 0x85, 0x42, 0x71, 0xC4, 0x6A, 0x1B, 0x88, 0x4C, 0x77, 0xC1, 0x71, 6, 0x9F, 0x5E, 0x75, 0xC2, 0x78, 0xD, 0x92, 0x50, 0x6B, 0xD3, 0xF, 0x64, 0xD9, 0xA, 0x69, 0xD0, 6, 0x6F, 0xD4, 4, 0x6F, 0xD5, 0x1D, 0x72, 0xC3, 0x16, 0x6D, 0xD6, 0x14, 0x79, 0xCE, 0x18, 0x63, 0xDF, 0x2B, 0x48, 0xED, 0x32, 0x61, 0xDC, 0x22, 0x43, 0xE0, 0x3C, 0x67, 0xD9, 0x39, 0x5E, 0xF7, 0x2E, 0x65, 0xDA, 0x30, 0x55, 0xFA, 0x20, 0x9B, 0x5B, 0x9A, 1, 0xB7, 0xEC, 0x99, 0x58, 0x93, 0xA, 0xBA, 0xE2, 0x9F, 0x5D, 0x88, 0x17, 0xAD, 0xF0, 0x9D, 0x5E, 0x81, 0x1C, 0xA0, 0xFE, 0x93, 0x57, 0xBE, 0x2D, 0x83, 0xD4, 0x91, 0x54, 0xB7, 0x26, 0x8E, 0xDA, 0x97, 0x51, 0xAC, 0x3B, 0x99, 0xC8, 0x95, 0x52, 0xA5, 0x30, 0x94, 0xC6, 0x8B, 0x43, 0xD2, 0x59, 0xDF, 0x9C, 0x89, 0x40, 0xDB, 0x52, 0xD2, 0x92, 0x8F, 0x45, 0xC0, 0x4F, 0xC5, 0x80, 0x8D, 0x46, 0xC9, 0x44, 0xC8, 0x8E, 0x83, 0x4F, 0xF6, 0x75, 0xEB, 0xA4, 0x81, 0x4C, 0xFF, 0x7E, 0xE6, 0xAA, 0x87, 0x49, 0xE4, 0x63, 0xF1, 0xB8, 0x85, 0x4A, 0xED, 0x68, 0xFC, 0xB6, 0xBB, 0x6B, 0xA, 0xB1, 0x67, 0xC, 0xB9, 0x68, 3, 0xBA, 0x6A, 2, 0xBF, 0x6D, 0x18, 0xA7, 0x7D, 0x10, 0xBD, 0x6E, 0x11, 0xAC, 0x70, 0x1E, 0xB3, 0x67, 0x2E, 0x9D, 0x53, 0x34, 0xB1, 0x64, 0x27, 0x96, 0x5E, 0x3A, 0xB7, 0x61, 0x3C, 0x8B, 0x49, 0x28, 0xB5, 0x62, 0x35, 0x80, 0x44, 0x26, 0xAB, 0x73, 0x42, 0xE9, 0xF, 0x7C, 0xA9, 0x70, 0x4B, 0xE2, 2, 0x72, 0xAF, 0x75, 0x50, 0xFF, 0x15, 0x60, 0xAD, 0x76, 0x59, 0xF4, 0x18, 0x6E, 0xA3, 0x7F, 0x66, 0xC5, 0x3B, 0x44, 0xA1, 0x7C, 0x6F, 0xCE, 0x36, 0x4A, 0xA7, 0x79, 0x74, 0xD3, 0x21, 0x58, 0xA5, 0x7A, 0x7D, 0xD8, 0x2C, 0x56, 0xDB, 0x3B, 0xA1, 0x7A, 0xC, 0x37, 0xD9, 0x38, 0xA8, 0x71, 1, 0x39, 0xDF, 0x3D, 0xB3, 0x6C, 0x16, 0x2B, 0xDD, 0x3E, 0xBA, 0x67, 0x1B, 0x25, 0xD3, 0x37, 0x85, 0x56, 0x38, 0xF, 0xD1, 0x34, 0x8C, 0x5D, 0x35, 1, 0xD7, 0x31, 0x97, 0x40, 0x22, 0x13, 0xD5, 0x32, 0x9E, 0x4B, 0x2F, 0x1D, 0xCB, 0x23, 0xE9, 0x22, 0x64, 0x47, 0xC9, 0x20, 0xE0, 0x29, 0x69, 0x49, 0xCF, 0x25, 0xFB, 0x34, 0x7E, 0x5B, 0xCD, 0x26, 0xF2, 0x3F, 0x73, 0x55, 0xC3, 0x2F, 0xCD, 0xE, 0x50, 0x7F, 0xC1, 0x2C, 0xC4, 5, 0x5D, 0x71, 0xC7, 0x29, 0xDF, 0x18, 0x4A, 0x63, 0xC5, 0x2A, 0xD6, 0x13, 0x47, 0x6D, 0xFB, 0xB, 0x31, 0xCA, 0xDC, 0xD7, 0xF9, 8, 0x38, 0xC1, 0xD1, 0xD9, 0xFF, 0xD, 0x23, 0xDC, 0xC6, 0xCB, 0xFD, 0xE, 0x2A, 0xD7, 0xCB, 0xC5, 0xF3, 7, 0x15, 0xE6, 0xE8, 0xEF, 0xF1, 4, 0x1C, 0xED, 0xE5, 0xE1, 0xF7, 1, 7, 0xF0, 0xF2, 0xF3, 0xF5, 2, 0xE, 0xFB, 0xFF, 0xFD, 0xEB, 0x13, 0x79, 0x92, 0xB4, 0xA7, 0xE9, 0x10, 0x70, 0x99, 0xB9, 0xA9, 0xEF, 0x15, 0x6B, 0x84, 0xAE, 0xBB, 0xED, 0x16, 0x62, 0x8F, 0xA3, 0xB5, 0xE3, 0x1F, 0x5D, 0xBE, 0x80, 0x9F, 0xE1, 0x1C, 0x54, 0xB5, 0x8D, 0x91, 0xE7, 0x19, 0x4F, 0xA8, 0x9A, 0x83, 0xE5, 0x1A, 0x46, 0xA3, 0x97, 0x8D]


byte_36e4 = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 1, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 4, 0xC7, 0x23, 0xC3, 0x18, 0x96, 5, 0x9A, 7, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 9, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 2, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0xC, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0xB, 0xDB, 0xE0, 0x32, 0x3A, 0xA, 0x49, 6, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 8, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 3, 0xF6, 0xE, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0xD, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0xF, 0xB0, 0x54, 0xBB, 0x16]


byte_4004 = [0x34, 0x63, 0x38, 0x66, 0x36, 0x35, 0x30, 0x39, 0x63, 0x63, 0x34, 0x65, 0x31, 0x61, 0x39, 0x66, 7, 0xA4, 0xD7, 0x75, 0x31, 0x91, 0xE7, 0x4C, 0x52, 0xF2, 0xD3, 0x29, 0x63, 0x93, 0xEA, 0x4F, 0x83, 0x5F, 0xB, 0xF0, 0xB2, 0xCE, 0xEC, 0xBC, 0xE0, 0x3C, 0x3F, 0x95, 0x83, 0xAF, 0xD5, 0xDA, 0xD4, 0xB3, 0x72, 0xF7, 0x66, 0x7D, 0x9E, 0x4B, 0x86, 0x41, 0xA1, 0xDE, 5, 0xEE, 0x74, 4, 0x26, 0xD8, 0x5A, 0x6D, 0x40, 0xA5, 0xC4, 0x26, 0xC6, 0xE4, 0x65, 0xF8, 0xC3, 0xA, 0x11, 0xFC, 0x96, 0xF6, 0x3D, 0xFF, 0xD6, 0x53, 0xF9, 0xD9, 0x10, 0xB7, 0x9C, 0x21, 0xD3, 0xBD, 0x8D, 0xDD, 0x57, 0x90, 0x47, 0x82, 0x81, 0xC3, 0xBE, 0x5B, 0x91, 0x74, 0x22, 0x7A, 0x42, 0xC9, 0xAF, 0xA7, 0xB, 0xBC, 0x9A, 0xBB, 0x8A, 0x7F, 0x24, 0xE0, 0x1B, 0xB, 6, 0x9A, 0x59, 0xC2, 0xA9, 0x3D, 0x2C, 0x77, 0xBF, 0xE8, 0xA6, 8, 0x9B, 8, 0xBD, 3, 0x9D, 0x92, 0xE4, 0xC1, 0x34, 0xAF, 0x55, 0x1E, 0xC7, 0xEB, 0xF3, 0x16, 0x5C, 0xE3, 0x4E, 0x15, 0xC1, 0x71, 0xAA, 0xD4, 0xF5, 0xDE, 0x48, 0xB2, 0x8F, 0x3B, 0xBB, 0xA4, 0xD3, 0xD8, 0xF5, 0xB1, 0x12, 0xA9, 0x5F, 0x65, 0xE7, 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ]

byte_4008 = [0x39, 0x30, 0x65, 0x31, 0x66, 0x61, 0x65, 0x30, 0x66, 0x31, 0x37, 0x34, 0x64, 0x38, 0x31, 0x34, 0x21, 0x73, 0x62, 0xF7, 0x47, 0x12, 7, 0xC7, 0x21, 0x23, 0x30, 0xF3, 0x45, 0x1B, 1, 0xC7, 0xE7, 0x1D, 0xCD, 0x89, 0xA0, 0xF, 0xCA, 0x4E, 0x81, 0x2C, 0xFA, 0xBD, 0xC4, 0x37, 0xFB, 0x7A, 0x3D, 1, 0x57, 0x82, 0x9D, 0xE, 0x9D, 0xCC, 0x1C, 0x22, 0x67, 0x71, 0xD8, 0x15, 0x9C, 0xB, 0x16, 0x60, 0xE, 0x54, 0x8B, 0x6E, 0x93, 0x98, 0x97, 0x4C, 0xF4, 0xE9, 0x4F, 0x59, 0x68, 0xE2, 0x8E, 0xE4, 0xC5, 1, 5, 0x8A, 0x56, 0x99, 0x92, 0xC6, 0xA2, 0x70, 0xDD, 0x9F, 0xCA, 0x92, 0xC1, 0x25, 0x1E, 0x55, 0xC4, 0xAF, 0x48, 0xCC, 0x56, 0x69, 0xEA, 0xBC, 0x8B, 0xF6, 0x20, 0x2E, 0xF0, 0x18, 0x5C, 0xA2, 0x34, 0xB7, 0x14, 0x6E, 0x62, 0xDE, 0xFE, 0xD2, 0xE9, 0x28, 0xDE, 0xFC, 0x40, 6, 0x68, 0x3F, 0x74, 0xB1, 0x7C, 0x51, 0x16, 0x6F, 0x82, 0x83, 0xFF, 0x47, 0x5C, 0x7F, 0x92, 0x10, 0xC8, 0x6E, 0xE6, 0xA1, 0xB4, 0x3F, 0xF0, 0xCE, 0x36, 0xBC, 0xF, 0x89, 0x6A, 0xC3, 0xBC, 0x66, 0x6F, 0x5A, 0x5A, 0xC7, 0xDB, 0x65, 0xAA, 9, 0xED, 0xD9, 0xA5, 0x80, 0x87, 0x1A, 0xFF, 0xFF, 0xFF, 0xFF, 2, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]


def rev_replace_2(v2):
    # verified
    v = [0]*16
    v[36-36] = v2[0]
    v[40-36] = v2[1]
    v[44-36] = v2[2]
    v[48-36] = v2[3]
    v[37-36] = v2[4]
    v[41-36] = v2[5]
    v[45-36] = v2[6]
    v[49-36] = v2[7]
    v[38-36] = v2[8]
    v[42-36] = v2[9]
    v[46-36] = v2[10]
    v[50-36] = v2[11]
    v[39-36] = v2[12]
    v[43-36] = v2[13]
    v[47-36] = v2[14]
    v[51-36] = v2[15]
    return v


def rev_replace_1(out):
    putbuffer = [0]*16
    putbuffer[0] = out[0]
    putbuffer[1] = out[40-36]
    putbuffer[2] = out[44-36]
    putbuffer[3] = out[48-36]
    putbuffer[4] = out[37-36]
    putbuffer[5] = out[41-36]
    putbuffer[6] = out[45-36]
    putbuffer[7] = out[49-36]
    putbuffer[8] = out[38-36]
    putbuffer[9] = out[42-36]
    putbuffer[10] = out[46-36]
    putbuffer[11] = out[50-36]
    putbuffer[12] = out[39-36]
    putbuffer[13] = out[43-36]
    putbuffer[14] = out[47-36]
    putbuffer[15] = out[51-36]
    buf = ''
    for i in range(len(putbuffer)):
        putbuffer[i] = chr(putbuffer[i])
        buf += putbuffer[i]
    return buf


def dec_extra(enc_file, sig_table):
    size = len(enc_file)
    output = [0]*size
    result = ""
    for i in range(0, size):
        real_index = i + 16
        output[i] = chr(ord(enc_file[i]) ^ sig_table[real_index % 32])
        result += output[i]
    return result


def dec_all(sig_table, enc_file):
    f = open(enc_file, "rb")
    enc_data = f.read()
    f.close()

    startpos = 0

    fout = open("output.jpg", "wb")
    # extra_data = dec_extra( enc_data, sig_table)
    # fwrite(extra)

    loop = 0
    while True:
        print "startpos is %d/%d" % (startpos, len(enc_data))
        cnt = sig_table[loop & 0x1f]
        decrypted_data = [0]*cnt

        if cnt & 1 == 0:
            v30 = byte_4004
        else:
            v30 = byte_4008

        # reverse all
        data_buffer = enc_data[startpos: startpos+16]
        data = rev_replace_2(data_buffer)

        #############
        for i in range(len(data)):
            data[i] = ord(data[i])

        data = dec_xor_sub_132c(data, v30, 0x28)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 0x24)
        data = dec_sub_162C(data)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 0x20)
        data = dec_sub_162C(data)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 0x1C)
        data = dec_sub_162C(data)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 0x18)
        data = dec_sub_162C(data)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 0x14)
        data = dec_sub_162C(data)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 0x10)
        data = dec_sub_162C(data)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 0xC)
        data = dec_sub_162C(data)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 8)
        data = dec_sub_162C(data)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 4)
        data = dec_sub_162C(data)
        data = dec_rotate(data)
        data = dec_sub_13B0(data)
        data = dec_xor_sub_132c(data, v30, 0)

        #############
        buf_final = rev_replace_1(data)
        print 'buf_final:', repr(buf_final)

        extra_data = dec_extra(enc_data[startpos+16: startpos+cnt], sig_table)
        # fout.write(enc_data[startpos:startpos+16])
        fout.write(buf_final)
        fout.write(extra_data)

        startpos += cnt
        loop += 1

        if startpos >= len(enc_data):
            break

    fout.close()


def test_byte_3920():
    '''
    result[0] = result_12 ^ result_8 ^ byte_3920[6 * result_0] ^ byte_3920[6 * result_4 + 1]
    result[4] = result_12 ^ byte_3920[6 * result_4] ^ result_0 ^ byte_3920[6 * result_8 + 1]
    result[8] = result_0 ^  result_4 ^ byte_3920[6 * result_8] ^ byte_3920[6 * result_12 + 1]
    result[12] = result_8 ^ result_4 ^ byte_3920[6 * result_0 + 1] ^ byte_3920[6 * result_12]
    '''
    A = 11
    B = 22
    C = 33
    D = 44
    '''
    result0: 1^34 = 35
    result1: 
    '''
    print C ^ D ^ byte_3920[6 * A] ^ byte_3920[6 * B + 1]
    print A ^ D ^ byte_3920[6 * B] ^ byte_3920[6 * C + 1]
    print A ^ B ^ byte_3920[6 * C] ^ byte_3920[6 * D + 1]
    print B ^ C ^ byte_3920[6 * D] ^ byte_3920[6 * A + 1]


def test_sub_162C_blk(A, B, C, D):
    return (C ^ D ^ byte_3920[6 * A] ^ byte_3920[6 * B + 1],
            A ^ D ^ byte_3920[6 * B] ^ byte_3920[6 * C + 1],
            A ^ B ^ byte_3920[6 * C] ^ byte_3920[6 * D + 1],
            B ^ C ^ byte_3920[6 * D] ^ byte_3920[6 * A + 1])


def test_sub_162C(l):
    l = [test_sub_162C_blk(l[i], l[i+4], l[i+8], l[i+12])for i in range(4)]
    return [l[j][i] for i in range(4) for j in range(4)]


def dec_sub_162C(input):
    l = [[input[i*4+j] for j in range(4)]for i in range(4)]
    ll = matmul(imat, l)
    return [ll[i][j] for i in range(4) for j in range(4)]


def dec_beautiful_xor(a1, a2, a3, a4):
    for A in range(0, 255):
        for B in range(0, 255):
            for C in range(0, 255):
                D = a1 ^ a2 ^ a3 ^ a4 ^ A ^ B ^ C
                if a1 == C ^ D ^ byte_3920[6 * A] ^ byte_3920[6 * B + 1] and a2 == A ^ D ^ byte_3920[6 * B] ^ byte_3920[6 * C + 1] and a3 == A ^ B ^ byte_3920[6 * C] ^ byte_3920[6 * D + 1] and a4 == B ^ C ^ byte_3920[6 * D] ^ byte_3920[6 * A + 1]:
                    return A, B, C, D


def dec_xor_sub_132c(input, keylist, offset):
    input[0] ^= keylist[offset*4+3]
    input[1] ^= keylist[(offset+1) * 4+3]
    input[2] ^= keylist[(offset+2) * 4+3]
    input[3] ^= keylist[(offset+3) * 4+3]
    input[4] ^= keylist[offset*4 + 2]
    input[5] ^= keylist[(offset+1) * 4 + 2]
    input[6] ^= keylist[(offset+2) * 4 + 2]
    input[7] ^= keylist[(offset+3) * 4 + 2]
    input[8] ^= keylist[offset*4 + 1]
    input[9] ^= keylist[(offset+1) * 4 + 1]
    input[10] ^= keylist[(offset+2) * 4 + 1]
    input[11] ^= keylist[(offset+3) * 4 + 1]
    input[12] ^= keylist[offset*4 + 0]
    input[13] ^= keylist[(offset+1) * 4 + 0]
    input[14] ^= keylist[(offset+2) * 4 + 0]
    input[15] ^= keylist[(offset+3) * 4 + 0]
    return input


def dec_rotate(input):
    temp = input[7]
    input[7] = input[6]
    input[6] = input[5]
    input[5] = input[4]
    input[4] = temp

    temp = input[8]
    input[8] = input[10]
    input[10] = temp

    temp = input[9]
    input[9] = input[11]
    input[11] = temp

    temp = input[13]
    input[13] = input[14]
    input[14] = input[15]
    input[15] = input[12]
    input[12] = temp

    return input


def dec_sub_13B0(input):
    output = [0] * 16
    index = 0
    for i in input:
        for j in range(0, 0x100):
            if i == byte_36e4[(j & 0xf0) + (j & 0xf)]:
                output[index] = j
                index += 1
                break

    return output


def test_combination():
    '''
    A^B
    A^C
    A^D
    B^C
    B^D
    C^D
    A^B^C
    A^B^D
    A^C^D
    B^C^D
    A^B^C^D
    '''
    import itertools
    for i in itertools.combinations('ABCD', 2):
        print "^".join(i)


if __name__ == "__main__":
    #print dec_sub_162C(test_sub_162C(range(16)))
    # test_byte_3920()
    # dec_beautiful_xor(33,104,43,114)
    dec_all(sig_table, "flag.jpg.lock")
    # for i in range(0xff):
    #     print i, byte_3920[i*6], byte_3920[i*6+1],  i^byte_3920[i*6] ,i^byte_3920[i*6+1],byte_3920[i*6]^byte_3920[i*6+1]
