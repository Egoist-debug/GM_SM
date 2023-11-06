# 数字格式转化
def int2str( num ) :
    out = ""
    out = out + chr( num//65536 ) + chr( (num%65536)//256 ) + chr( num%256 )
    return out

def str2hex( string ):
    out = ""
    for i in range ( 0 , len(string) ):
        out = out + " " + hex(ord( string[i] ))
    return out

# 字符串异或运算，后面分别是字符串与、或、非运算
def strxor( message , key , len ):
    out = ""
    for i in range ( 0 , len ):
        ch = ord(message[i]) ^ ord(key[i])
        out = out + chr(ch)
    return out

def strand( message , key , len ):
    out = ""
    for i in range ( 0 , len ):
        ch = ord(message[i]) & ord(key[i])
        out = out + chr(ch)
    return out

def stror( message , key , len ):
    out = ""
    for i in range ( 0 , len ):
        ch = ord(message[i]) | ord(key[i])
        out = out + chr(ch)
    return out

def strnot( string , len ) :
    out = ""
    for i in range ( 0 , len ) :
        ch = ~ord(string[i])
        out = out + chr(ch)
    return out

# 字符串按比特向左移位
def strldc( string , bit ):
    byte = bit // 8
    bit = bit % 8
    out = ""
    if bit == 0 :
        out = string[byte:] + string[:byte]
    else :
        reg = string[byte:] + string[:byte+1]
        for i in range (0,len(reg)-1):
            out = out + chr(((ord(reg[i])*(2**bit))+(ord(reg[i+1])//(2**(8-bit))))%256)
        out = out[:len(string)]
    return out

# 4字节模加运算
def stradd_4( str1 , str2 ) :
    out = ""
    num1 = ord(str1[0])*16777216+ord(str1[1])*65536+ord(str1[2])*256+ord(str1[3])
    num2 = ord(str2[0])*16777216+ord(str2[1])*65536+ord(str2[2])*256+ord(str2[3])
    add = (num1 + num2)%4294967296
    out = out + chr(add//1677216) + chr((add%1677216)//65536) + chr((add%65536)//256) + chr(add%256)
    return out

def functionFF( A , B , C , j ) :
    if j < 16 :
        FF = strxor( A , strxor( B , C , 4 ) , 4 )
    if j > 15 :
        FF = stror( stror( strand(A,B,4) , strand(A,C,4) , 4 ) , strand(B,C,4) , 4)
    return FF

def functionGG( A , B , C , j ) :
    if j<16 :
        GG = strxor( A , strxor( B , C , 4 ) , 4 )
    if j > 15 :
        GG = stror( strand(A,B,4) , strand(strnot(A,4),C,4) , 4 )
    return GG

def functionP( string , mode ) :
    out = ''
    if mode == 0 :
        out = strxor( string , strxor( strldc(string,9) , strldc(string,17) , 4 ) , 4 )
    if mode == 1 :
        out = strxor( string , strxor( strldc(string,15) , strldc(string,23) , 4 ) , 4 )
    return out

def functionCF( V , B ) :
    for i in range (0,68) :
        # 消息扩展过程
        P = strxor( strxor( B[0:4] , B[28:32] , 4 ) , strldc( B[42:46] , 15 ) , 4)
        Badd = strxor( P , strxor( B[40:44] , strldc(B[12:16],7) , 4 ) , 4 )
        out1 = strxor( B[0:4] , B[16:20] , 4 )
        out = B[0:4]
        B = B[0:60] + Badd
        # 状态更新过程
        if i < 64 :
            if i < 16 :
                SS1 = strldc( stradd_4( strldc( V[0:4] , 12 ) , stradd_4( V[16:20] , strldc(T0_15,i%32) ) ) , 7 )
            else :
                SS1 = strldc( stradd_4( strldc( V[0:4] , 12 ) , stradd_4( V[16:20] , strldc(T16_63,i%32) ) ) , 7 )
        SS2 = strxor( SS1 , strldc( V[0:4] , 12 ) , 4 )
        TT1 = stradd_4( stradd_4( functionFF( V[0:4] , V[4:8] , V[8:12] , i ) , V[12:16] ) , stradd_4( SS2 , out1 ) )
        TT2 = stradd_4( stradd_4( functionGG( V[16:20] , V[20:24] , V[24:28] , i ) , V[28:32] ) , stradd_4( SS1 , out ) )
        V = strxor( V , TT1 + V[0:4] + strldc(V[4:8],9) + V[8:12] + functionP(TT2,0) + V[16:20] + strldc(V[20:24],19) + V[24:28] , 32 )
    return V

IV = "\x73\x80\x16\x6f\x49\x14\xb2\xb9\x17\x24\x42\xd7\xda\x8a\x06\x00\xa9\x6f\x30\xbc\x16\x31\x38\xaa\xe3\x8d\xee\x4d\xb0\xfb\x0e\x4e"
T0_15 = "\x79\xcc\x45\x19"
T16_63 = "\x7a\x87\x9d\x8a"
plain = input( "请输入杂凑函数明文：" )
l = int2str( len(plain)*8 )
plain = plain + "\x80"
k = 56 - (len(plain)%64) - 1
plain = plain + "\x00"*k
plain = plain + l
print( "plain :" , str2hex(plain) )
for i in range ( 0 , len(plain)//64-1 ) :
    IV = functionCF( IV , plain[64*l:64*l+64] )
hash_value = IV
print( " hash :" , str2hex(hash_value) )
