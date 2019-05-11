import sys, cmd, os

#del __builtins__.__dict__['eval']

intro = """
Welcome to My Python Interpreter
===================================================================================
"""
def execute(command):
 
       exec(command, globals())
 
class Jail(cmd.Cmd):
 
    prompt     = '>>> '
    filtered    = ''
#'\'|.|input|if|else|eval|exit|import|quit|exec|code|const|vars|str|chr|ord|local|global|join|format|replace|translate|try|except|with|content|frame|back'.split('|')
    def do_EOF(self, line):
 
        sys.exit()
 
    def emptyline(self):
 
        return cmd.Cmd.emptyline(self)
 
    def default(self, line):
        sys.stdout.write('\x00')
 
    def postcmd(self, stop, line):
 
        if any(f in line for f in self.filtered):
 
            print("You are a big hacker !!!")
 
            print("Go away")
 
        else:
 
           try:
 
                execute(line)
 
           except NameError:
 
                print("NameError: name '%s' is not defined" % line)
 
           except Exception:
                print("Error: %s" % line)
        return cmd.Cmd.postcmd(self, stop, line)
 
 
try:
    t = Jail()
#    del __builtins__.__dict__['__import__']
    t.cmdloop(intro)
 
except KeyboardInterrupt:
    print("\rSee you next time !")
