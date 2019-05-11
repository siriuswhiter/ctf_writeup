def make_secure():
    UNSAFE = ['open',
              'file',
              'execfile',
              'compile',
              'reload',
              '__import__',
              'eval',
              'input']
    for func in UNSAFE:
        del __builtins__.__dict__[func]

from re import findall
# Remove dangerous builtins
make_secure()
print 'Go Ahead, Expoit me >;D'
while True:
    try:
        # Read user input until the first whitespace character
        inp = findall('S+', raw_input())[0]
        a = None
        # Set a to the result from executing the user input
        exec 'a=' + inp
        print 'Return Value:', a
    except Exception, e:
        print 'Exception:',e
