'''
Created on 20/4/2015

@author: sahid
'''
import unittest
from mdlaccesscontrol import *

class ClsAccessControlTester(unittest.TestCase):
    #Casos Frontera
    s0 = "M3ñ0$d8"
    s1 = "C@d3ñA_ca%a(|3&E$" 
    s3 = ""
    
    #Cadena de caracteres válida
    s4 = "pa$$w0rD"
    
    #def testClsAccessControl(self):
        #aClsAccessControl = clsAccessControl(object)
       
    #def testClsAccessControlEncript(self):
     #    aClsAccessControl = clsAccessControl(object)
     #    mensajeEncriptado = aClsAccessControl.encript(s4)
        
    def testClsAccessControlCheck_password(self):
        s4 = "pa$$w0rD"
        aClsAccessControl = clsAccessControl()
        mensajeEncriptado = aClsAccessControl.encript(s4)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,s4),"Deberia ser true")