modname = 'umit.inventory.agent.modules.TestModule'

"""
for modname in modnames:
      exec('import %s' % modname)

      for modname in modnames:
            mod = sys.modules[modname]
              for k in mod.__dict__:
                      if k[:2] != '__':
                                print modname, k, mod.__dict__[k]
"""
import sys
exec('import %s' % modname)

mod = sys.modules[modname]
mod_class = mod.__dict__['TestModule']

class Temp:

    def items(x=1, y =3, z = 4):
        return []

obj = mod_class(Temp(), None)
print obj.get_name()
