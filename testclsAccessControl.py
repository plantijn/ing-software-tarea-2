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
        
        #Casos Esquina
        
        s0 = "M3ñ0$d8" #Longitud 7
        s1 = "C@d3ñA_ca%a(|3&E$" #longitud 17
        s3 = "" #longitud 0
        s4 = "pa$$w0rD" #longitud 8
        s5 = "169rháéíñ}Á!Qzp0"  #longitud 16
        s6 = "|2E4$7()" #longitud 8
        s7 = "ñp890dfWn.z<%éo#" #longitud 16
        
        aClsAccessControl = clsAccessControl()
        mensajeEncriptado = aClsAccessControl.encript(s0)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,s0),"Las contraseñas difieren en longitud o en contenido")