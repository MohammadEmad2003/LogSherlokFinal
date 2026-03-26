import sys
from io import StringIO
class Capture(StringIO):
    def write(self, string):
        pass # test
