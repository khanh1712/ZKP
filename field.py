# inverse modulo using extended Euclidean algorithm
def inverseMod(d, n):
    t, newt = 0, 1
    r, newr = n, d
    if d < 0:
        return inverseMod(n + d, n)
    else:
        while(newr != 0):
            q = r // newr
            r, newr = newr, (r % newr)
            t, newt = newt, (t - q*newt)
        if r > 1:
            print("not in vertible")
        else:
            if (t < 0):
                t += n
            return int(t)

class Curve(object):
    def __init__(self, a, b, p, n, x_g, y_g):
        self.a = a
        self.b = b
        self.p = p
        self.n = n
        self.g = Point(self, x_g, y_g)

    # equal operator
    def __eq__(self, other) -> bool:
        if isinstance(other, Curve):
            return self.a == other.a and self.b == other.b and self.p == other.p and self.g.x == other.g.x and self.g.y == other.g.y 
        else:
            return False
    # not equal operator
    def __ne__(self, other) -> bool:
        return not self.__eq__(other)
    
class Point(object):
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
    # equal operator
    def __eq__(self, other) -> bool:
        if isinstance(other, Point):
            return self.curve == other.curve and self.x == other.x and self.y == other.y
        else:
            return False
    # not equal operator
    def __ne__(self, other) -> bool:
        return not self.__eq__(other)
    # addition
    def __add__(self, other):
        #add Infinity
        if isinstance(other, Infinity):
            return self
        elif isinstance(other, Point):
            # different curve
            if self.curve != other.curve:
                raise ValueError("Cannot add points belonging to different curves")
            else:
                # add -P
                if self.x == other.x and self.y != other.y:
                    return Infinity(self.curve)
                else:
                    # calculate lambda using known coefficients
                    a = self.curve.a
                    p = self.curve.p
                    x1 = self.x
                    y1 = self.y
                    x2 = other.x
                    y2 = other.y
                    if self.x == other.x and self.y == other.y:
                        l = ((3*x1*x1 + a) * inverseMod(2*y1, p)) % p 
                    else:
                        l = ((y2-y1) * inverseMod(x2-x1, p)) % p
                    # calculate result based on lambda
                    x3 = (l*l - x1 - x2) % p
                    y3 = -(l*(x3-x1) + y1) % p
                    return Point(self.curve, x3, y3)
        else:
            raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))
    # substraction
    def __sub__(self, other):
        if isinstance(other, Infinity):
            return self
        elif isinstance(other, Point):
            other = Point(other.curve, other.x, -other.y)
            return self.__add__(other)
        else:
            raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))
    # multiplication
    def __mul__(self, k):
        # k is the number multiply with P
        if isinstance(k, int):
            if k % self.curve.n == 0:
                return Infinity(self.curve)
            if k < 0:
                temp = Point(self.curve, self.x, -self.y)
            else:
                temp = self
            # multiplication is defined by making successive addition
            # transform k into binary form 
            # if bit = 1 then we add temp to the result
            # double temp for each bit
            result = Infinity(self.curve)
            for bit in reversed([int(i) for i in bin(abs(k))[2:]]):
                if bit == 1:
                    result += temp
                temp += temp
            return result
        else:
            raise TypeError("Unsupported operand type(s) for *: '%s' and '%s'" % (k.__class__.__name__,
                                                                                  self.__class__.__name__))


    def __rmul__(self, k):
        return self.__mul__(k)
    
    def display(self):
        print(self.x, self.y)

class Infinity(object):
    def __init__(self, curve, x = None, y = None):
        self.curve = curve
        self.x = x
        self.y = y

    def __eq__(self, other) -> bool:
        if isinstance(other, Infinity):
            return self.curve == other.curve
        else:
            return False
        
    def __ne__(self, other) -> bool:
        return not self.__eq__(other)
    
    def __add__(self, other):
        if isinstance(other, Infinity):
            return Infinity(self.curve)
        elif isinstance(other, Point):
            return other
        else:
            raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))
        
    def __mul__(self, k):
        if isinstance(k, int):
            return Infinity(self.curve)
        else:
            raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (k.__class__.__name__,
                                                                                  self.__class__.__name__))
    
    def __sub__(self, other):
        if isinstance(other, Infinity):
            return Infinity(self.curve)
        elif isinstance(other, Point):
            return other
        else:
            raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))

def getPoint(read: str):
    x = ""
    y = ""
    for i in range(len(read)):
        if read[i].isdigit() == True:
            x += read[i]
        elif read[i] == ",":
            temp = i + 2
            break
    while True:
        if read[temp].isdigit() == False:
            break
        else:
            y += read[temp]
            temp +=1

    return (int(x), int(y))

