# SM2
import Crypto.Util.number as number
import Crypto.Random as Rand
from SM3 import SM3

# 设置默认的椭圆曲线参数
SM2_p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
SM2_Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
SM2_G = (SM2_Gx, SM2_Gy)


PARA_SIZE = 32  # 参数长度（字节）
HASH_SIZE = 32  # sm3输出256位（32字节）
KEY_LEN = 128  # 默认密钥位数

# ECC 椭圆曲线类


class ECC(object):
    def __init__(self, p, a, b, G, n, h=None):
        self.p = p
        self.a = a
        self.b = b
        self.G = G
        self.n = n
        if h:
            self.h = h
        self.O = (-1, -1)

    # 椭圆曲线上的加法
    # 输入：两个点P1，P2
    # 输出：P1+P2
    # 仅输入P1，返回P1+P1
    def add(self, P1, P2=None):
        x1, y1 = P1
        if P2 == None or P1 == P2:
            # 处理无穷远点
            if P1 == self.O:
                return self.O
            # 计算斜率
            l = (3 * x1 * x1 + self.a) * number.inverse(2 * P1[1], self.p) % self.p
            # 计算x3
            x3 = (l * l - 2 * x1) % self.p
            # 计算y3
            y3 = (l * (x1 - x3) - P1[1]) % self.p
            return (x3, y3)
        else:
            x2, y2 = P2
            # 处理无穷远点
            if P1 == self.O:
                return P2
            if P2 == self.O:
                return P1
            if x1 == x2:
                return self.O
            # 计算斜率
            l = (y2 - y1) * number.inverse(x2 - x1, self.p) % self.p
            # 计算x3
            x3 = (l * l - x1 - x2) % self.p
            # 计算y3
            y3 = (l * (x1 - x3) - y1) % self.p
            return (x3, y3)

    # 椭圆曲线上的倍乘
    # 输入：点P，倍数k
    # 输出：kP
    def mul(self, P, k):
        # 判断k是否为整数
        assert type(k) is int and k >= 0, "k must be an integer"
        # 处理无穷远点
        if k % self.n == 0 or P == self.O:
            return self.O
        # 二进制分解
        Q = self.O
        while k:
            if k & 1:
                Q = self.add(Q, P)
            k >>= 1
            P = self.add(P, P)
        return Q

    # 椭圆曲线上的点的求逆
    # 输入：点P
    # 输出：-P
    def inverse(self, P):
        x, y = P
        return (x, -y % self.p)

    # 椭圆曲线上的点的判断
    # 输入：点P
    # 输出：True/False
    def is_on_curve(self, P):
        if P == self.O:
            return True
        x, y = P
        return (y * y - x * x * x - self.a * x - self.b) % self.p == 0

    # 判断是否为无穷远点
    # 输入：点P
    # 输出：True/False
    def is_O(self, P):
        return P == self.O

    # 判断是否为Fp中的元素
    # 输入：多个元素
    # 输出：True/False（均为Fp中的元素/存在不是Fp中的元素）
    def is_in_Fp(self, *args):
        for arg in args:
            if arg < 0 or arg >= self.p:
                return False
        return True

    # 生成密钥对
    # 输入：无
    # 输出：公钥P，私钥d
    def gen_keypair(self):
        d = Rand.random.randint(1, self.n - 1)
        P = self.mul(self.G, d)
        return P, d

    # 公钥验证
    # 输入：公钥P
    # 输出：True/False
    def verify_key(self, P):
        # 格式出错
        if P and len(P) == 2 and type(P[0]) == int and type(P[1]) == int:
            pass
        else:
            self.error = "格式有误"
            return False
        # 其他问题
        if not self.is_on_curve(P):
            self.error = "不在椭圆曲线上"
            return False
        if self.mul(P, self.n) != self.O:
            self.error = "不是循环群"
            return False
        if self.is_O(P):
            self.error = "是无穷远点"
            return False
        if self.is_O(self.mul(P, self.n)):
            self.error = "不是循环子群"
            return False
        return True

    # 确认目前已有的密钥对，若没有则生成
    # 输入：无
    # 输出：无
    def confirm_keypair(self):
        if (
            not hasattr(self, "pk")
            or not self.pk_valid(self.pk)
            or self.pk != self.mul(self.sk, self.G)
        ):
            while True:
                d, P = self.gen_keypair()
                if self.pk_valid(P):  # 确保公钥通过验证
                    self.sk, self.pk = d, P
                    return


# SM2 加密解密类
class SM2(ECC):
    # 初始化，使用默认参数
    def __init__(
        self,
        p=SM2_p,
        a=SM2_a,
        b=SM2_b,
        n=SM2_n,
        G=(SM2_Gx, SM2_Gy),
        h=None,
        ID=None,
        sk=None,
        pk=None,
        genkeypair=True,  # 是否自动生成密钥对
    ):
        if not h:
            h = 1
        super().__init__(p, a, b, G, n, h)
