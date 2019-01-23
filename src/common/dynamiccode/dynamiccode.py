import sys
from RestrictedPython import compile_restricted
from RestrictedPython import safe_builtins

class DynamicCode:

    @staticmethod
    def run_dynamic(identity, value, times, prev_value, code):
        '''
            Runs dynamic code with the given values, returns boolean result
        '''

        result = DynamicCode.run(identity, value, times, prev_value, code)
        return True if result[0] and result[1] else False

    @staticmethod
    def check_code(code):
        '''
            Checks dynamic code syntax and runs it with an example.

            returns tuple (result, message)
                result - the code passed or not
                message - error message when result is False
        '''

        result = DynamicCode.run(12345678, 20, 2, 10, code)
        return result

    @staticmethod
    def run(identity, value, times, prev_value, code):
        '''
            Runs code on safe sandbox
        '''

        func = "def test(identity, value, times, prev_value): \n"
        end = "r = test(%d, %d, %d, %d)" % (identity, value, times, prev_value)
        code = func + code + "\n" + end

        try:
            loc = {}
            c = compile_restricted(code, "dyncode", 'exec')
            exec(c, {'__builtins__': safe_builtins}, loc)
            return (True, loc['r'])
        except Exception as e:
            return (False, e)
