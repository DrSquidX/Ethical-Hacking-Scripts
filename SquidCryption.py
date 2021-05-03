import random
class SquidCrypt:
    class SquidCryptError:
        class InvalidKeyException(Exception):
            def __init__(self, msg="Key is invalid!"):
                self.msg = msg
                super().__init__(self.msg)
        class InvalidSessionException(Exception):
            def __init__(self, msg="There was a previous error, that made the current task undoable."):
                self.msg = msg
                super().__init__(self.msg)
    def __init__(self, key):
        self.key = key
        self.competent = False
        self.letter_list = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
                            'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                            'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
                            'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
                            'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        if len(self.key) != 52:
            raise self.SquidCryptError.InvalidKeyException
        else:
            self.competent = True
            self.interpret_letters()
    def generate_key(self=None):
        ls = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
              'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
              'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
              'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
              'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
        random.shuffle(ls)
        key = ""
        for i in ls:
            key += i
        return key
    def interpret_letters(self):
        self.items = list(self.key)
        self.encrytions = self.build_encryptionlist()
    def build_encryptionlist(self):
        if self.competent:
            self.items.reverse()
            encrytions = []
            item = 0
            for i in self.letter_list:
                encrytions.append(f"{self.items[item]} {i}")
                item += 1
            self.items.reverse()
            return encrytions
        else:
            raise self.SquidCryptError.InvalidSessionException
    def encrypt(self, string):
        if self.competent:
            result = ""
            items = 0
            for i in string:
                for item in self.encrytions:
                    if i.strip() in item.split()[1]:
                        result += item.split()[0]
                        try:
                            result += str(self.encrytions[items + 1].split()[0])
                        except:
                            result += str(self.encrytions[0].split()[0])
                        items += 1
                        break
            result = list(result)
            result.reverse()
            final = ""
            for i in result:
                final += i
            return final
        else:
            raise self.SquidCryptError.InvalidSessionException
    def decrypt(self, string):
        items = 0
        if self.competent:
            result = ""
            for i in string:
                for item in self.encrytions:
                    if i.strip() in item.split()[0]:
                        if items == 2:
                            items = 0
                        else:
                            result += item.split()[1]
                        items += 1
                        break
            result = list(result)
            result.reverse()
            final = ""
            for i in result:
                final += i
            final = list(final)
            result = ""
            item = 0
            for i in final:
                if item == len(final)-1:
                    pass
                else:
                    result += i
                item += 1
            return result
        else:
            raise self.SquidCryptError.InvalidSessionException
