import sys
import os

class getArgv():
    def __init__(self, arg):
        self.result=None
        if arg in sys.argv:
            if( len( sys.argv ) > sys.argv.index(arg)+1 ):
                self.result=sys.argv[ sys.argv.index(arg)+1 ]
            else:
                self.result=None

        if arg == '--fairchains-path':
            if self.result == None or not os.path.isdir(self.result):
                self.result='/home/'+os.environ.get('USER')+'/.fairchains/'
            elif self.result[-1:] != '/':
                self.result=self.result+'/'
