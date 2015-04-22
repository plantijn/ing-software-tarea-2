'''
Created on 20/4/2015

@author: sahid
'''
import unittest
from mdlaccesscontrol import *

class ClsAccessControlTester(unittest.TestCase):

    #def testClsAccessControl(self):
        #aClsAccessControl = clsAccessControl(object)
       
    #def testClsAccessControlEncript(self):
     #    aClsAccessControl = clsAccessControl(object)
     #    mensajeEncriptado = aClsAccessControl.encript(s4)
        
    def testClsAccessControlCheck_password(self):
        
        #Casos Esquina
        
        s0 = "M3Ã±0$d8" #Longitud 7
        s1 = "C@d3Ã±A_ca%a(|3&E$" #longitud 17
        s2 = "" #longitud 0
        s3 = "pa$$w0rD" #longitud 8
        s4 = "169rhÃ¡Ã©Ã­Ã±}Ã�!Qzp0"  #longitud 16
        s5 = "|2E4$7()" #longitud 8
        s6 = "Ã±p890dfWn.z<%Ã©o#" #longitud 16

        aClsAccessControl = clsAccessControl()
        mensajeEncriptado = aClsAccessControl.encript(s0)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,s0),"Las contraseÃ±as difieren en longitud o en contenido")
