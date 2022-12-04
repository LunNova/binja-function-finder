from io import StringIO


# TODO: Handle backreferences properly (failing unit test)

class Symbol(object):
    __slots__ = ('builder', 'stack', 'names')

    def __init__(self):
        self.builder = StringIO()
        self.stack = []
        self.names = []

    def __get_literal_string(self, mangled, start):
        """
        :type mangled: str
        """
        next_at = mangled.find('@', start)
        if next_at > 0 and next_at != start:
            # print(start)
            # print(next_at)
            # print(mangled[start:next_at])
            r = mangled[start:next_at]
            self.names.append(r)
            return next_at + 1, r
        raise Exception("No @ found")

    def __get_number(self, mangled, start):
        c = mangled[start]
        start += 1
        sign = False
        if c == '?':
            sign = True
            c = mangled[start]
            start += 1
        ordinal = ord(c)
        if ord('0') <= ordinal <= ord('9'):
            number = (ordinal - ord('0')) + 1
        elif ord('A') <= ordinal <= ord('P'):
            number = 0
            while ord('A') <= ordinal <= ord('P'):
                number *= 16
                number += ordinal - ord('A')
                c = mangled[start]
                start += 1
                ordinal = ord(c)
            if c != '@':
                raise Exception("number should end with @, ended with '" + c + "'")
        else:
            raise NotImplemented

        if sign:
            return start, '-' + str(number)
        return start, str(number)

    def __get_args(self, mangled, start):
        args = []
        i = start
        while mangled[i] != '@':
            # print("Argument for '" + mangled[i:] + "'")
            s = Symbol()
            old_i = i
            i = s.demangle_datatype(mangled, i)
            result = s.builder.getvalue()
            if not result or len(result) == 0:
                raise Exception("Empty argument for '" + mangled[old_i:] + "' in '" + mangled + "'")
            args.append(result)
        return i + 1, args

    def __get_template_name(self, mangled, start):
        start, name = self.__get_literal_string(mangled, start)
        start, args = self.__get_args(mangled, start)
        # TODO swap names stack out?
        if args and len(args) > 0:
            return start, name + "<" + ", ".join(args) + ">"
        return start, name

    def __demangle_class_name(self, mangled, start):
        i = start
        c = mangled[i]
        while c != '@':
            # print(c)
            # print(mangled[i:])
            if c in ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9'):
                referenced = ord(c) - ord('0')
                self.stack.append(self.names[referenced])
                i += 1
            elif c == '?':
                i += 1
                c = mangled[i]
                i += 1
                if c == '$':
                    i, name = self.__get_template_name(mangled, i)
                    self.names.append(name)
                    self.stack.append(name)
                elif c == '?':
                    raise NotImplemented
                else:
                    raise NotImplemented
            else:
                i, name = self.__get_literal_string(mangled, i)
                self.stack.append(name)
            c = mangled[i]
        i += 1

        # print(self.names)
        # print(self.stack)
        self.builder.write("::".join(reversed(self.stack)))
        self.stack = []

        return i

    def demangle(self, mangled, start):
        start = self.__demangle_modifier(mangled, 1)
        return self.demangle_datatype(mangled, start)

    def demangle_datatype(self, mangled, start):
        """
        :type self.builder: StringIO
        """

        c = mangled[start]
        start += 1
        if c == '_':
            start = self.__demangle_extended(mangled, start)
        elif c == 'C':
            self.builder.write("signed char")
        elif c == 'D':
            self.builder.write("char")
        elif c == 'E':
            self.builder.write("unsigned char")
        elif c == 'F':
            self.builder.write("short")
        elif c == 'G':
            self.builder.write('unsigned short')
        elif c == 'H':
            self.builder.write('int')
        elif c == 'I':
            self.builder.write('unsigned int')
        elif c == 'J':
            self.builder.write('long')
        elif c == 'K':
            self.builder.write('unsigned long')
        elif c == 'M':
            self.builder.write('float')
        elif c == 'N':
            self.builder.write('double')
        elif c == 'O':
            self.builder.write('long double')
        elif c == 'X':
            self.builder.write('void')
        elif c == 'Z':
            self.builder.write('...')
        elif c == 'T':
            self.builder.write('union ')
            start = self.__demangle_class_name(mangled, start)
        elif c == 'U':
            self.builder.write('struct ')
            start = self.__demangle_class_name(mangled, start)
        elif c == 'V':
            self.builder.write('class ')
            start = self.__demangle_class_name(mangled, start)
        elif c == 'Y':
            self.builder.write('cointerface ')
            start = self.__demangle_class_name(mangled, start)
        elif c == '$':
            c = mangled[start]
            start += 1
            if c == '0':
                start, result = self.__get_number(mangled, start)
                self.builder.write(result)
            else:
                raise NotImplemented
        else:
            raise NotImplemented

        return start
        # i = start
        # while i < len(mangled):
        #     c = mangled[i]
        #     i += 1
        #     if c == '_':
        #         i = self.__demangle_extended(mangled, start)
        # return i

    def __demangle_modifier(self, mangled, start):
        modifier = mangled[start]
        start += 1
        if modifier == 'A':
            pass
        elif modifier == 'B':
            self.builder.write("const ")
        elif modifier == 'C':
            self.builder.write("volatile ")
        elif modifier == 'D':
            self.builder.write("const volatile")
        else:
            raise Exception("Unknown modifier " + modifier + " in " + mangled)
        return start

    def __demangle_extended(self, mangled, start):
        c = mangled[start]
        start += 1
        if c == 'D':
            self.builder.write("__int8")
        elif c == 'E':
            self.builder.write("unsigned __int8")
        elif c == 'F':
            self.builder.write("__int16")
        elif c == 'G':
            self.builder.write('unsigned __int16')
        elif c == 'H':
            self.builder.write('__int32')
        elif c == 'I':
            self.builder.write('unsigned __int32')
        elif c == 'J':
            self.builder.write('__int64')
        elif c == 'K':
            self.builder.write('unsigned __int64')
        elif c == 'L':
            self.builder.write('__int128')
        elif c == 'M':
            self.builder.write('unsigned __int128')
        elif c == 'N':
            self.builder.write('bool')
        elif c == 'W':
            self.builder.write('whcar_t')
        return start


def unmangle(mangled, ignore_errors=False):
    """
    :type mangled: str
    :type ignore_errors: bool
    """
    if len(mangled) < 1 or mangled[0] != '?':
        return mangled

    result = Symbol()
    try:
        result.demangle(mangled, 1)
    except Exception as e:
        if ignore_errors:
            print("Can't unmangle '" + mangled + "'")
            return mangled
        else:
            raise
    return result.builder.getvalue()


import unittest


class TestUnmangle(unittest.TestCase):
    def test_simple_generic(self):
        self.assertEqual("class a::b<class c::d>",
                         unmangle("?AV?$b@Vd@c@@@a@@"))

    def test_generic_class(self):
        self.assertEqual("class UdpLibrary::UdpLinkedList<class UdpLibrary::UdpConnection>",
                         unmangle("?AV?$UdpLinkedList@VUdpConnection@UdpLibrary@@@UdpLibrary@@"))

    def test_negative1_type_parameter(self):
        self.assertEqual("class SoeUtil::List<struct GameCore::GameClientInputManagerInternals::GameController, -1>",
                         unmangle("?AV?$List@UGameController@GameClientInputManagerInternals@GameCore@@$0?0@SoeUtil@@"))

    def test_std_simple(self):
        self.assertEqual("struct std::integral_constant<bool, 0>", unmangle("?AU?$integral_constant@_N$0A@@std@@"))
        self.assertEqual("struct std::integral_constant<bool, 1>", unmangle("?AU?$integral_constant@_N$00@std@@"))
        self.assertEqual("union std::_Align_type<double, 16>", unmangle("?AT?$_Align_type@N$0BA@@std@@"))

    def test_standard_backreference(self):
        self.assertEqual("", unmangle(
            "?AV?$_Compressed_pair@U?$_Wrap_alloc@V?$allocator@_W@std@@@std@@V?$_String_val@U?$_Simple_types@_W@std@@@2@$00@std@@"))


if __name__ == '__main__':
    unittest.main()
