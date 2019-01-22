import sys
from RestrictedPython import compile_restricted
from RestrictedPython import safe_builtins

class DynamicCode:

    @staticmethod
    def check_code(code):
        '''
            Checks dynamic code syntax and runs it with an example.

            returns tuple (result, message)
                result - the code passed or not
                message - error message when result is False
        '''

        func = "def test(identity, value, times, prev_value): \n"
        end = "test(\"XXXXX\", \"20\", \"4\", \"10\")"
        code = func + code + "\n" + end

        try:
            c = compile_restricted(code, "dyncode", 'exec')
            exec(c, {'__builtins__': safe_builtins}, {})
            return (True, )
        except Exception as e:
            return (False, e)
