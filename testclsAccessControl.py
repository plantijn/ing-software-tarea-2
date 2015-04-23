'''
Created on 20/4/2015

@author: sahid
'''
import unittest
from mdlaccesscontrol import *

class ClsAccessControlTester(unittest.TestCase):

       
    def testClsAccessControlCheck_passwordFalse(self):
        aClsAccessControl = clsAccessControl()

        #Caso A:    8 caracteres distinto contenido
        mensajeEncriptado = aClsAccessControl.encript(s5)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,s7),"Las contraseñas difieren en contenido")
        
        #Caso B:    16 caracteres distinto contenido
        mensajeEncriptado = aClsAccessControl.encript(s6)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,s8),"Las contraseñas difieren en contenido")
        
        #Caso C:    7 caracteres mismo contenido
        mensajeEncriptado = aClsAccessControl.encript(s0)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,s0),"Las contraseñas estan fuera del rango")
        
        #Caso D:    7 caracteres distinto contenido
        mensajeEncriptado = aClsAccessControl.encript(s0)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,s2),"Las contraseñas estan fuera del rango y difieren en contenido")
        
        #Caso E:    17 caracteres mismo contenido
        mensajeEncriptado = aClsAccessControl.encript(s1)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,s1),"Las contraseÃ±as estan fuera del rango")
        
        #Caso F:    17 caracteres distinto contenido
        mensajeEncriptado = aClsAccessControl.encript(s1)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,s3),"Las contraseÃ±as difieren en contenido y en rango")
        
        #Caso G:    0 caracteres
        mensajeEncriptado = aClsAccessControl.encript(s4)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,s4),"Las contraseñas no poseen caracteres")
      
    def testClsAccessControlCheck_passwordTrue(self):
        aClsAccessControl = clsAccessControl()
        
        #Casos Frontera
        
        #Caso H:     8 caracteres mismo contenido
        mensajeEncriptado = aClsAccessControl.encript(s5)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,s5),"Las contraseñas deben coincidir")
        
        #Caso I:    16 caracteres mismo contenido
        mensajeEncriptado = aClsAccessControl.encript(s8)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,s8),"Las contraseñas deben coincidir")

        
        #Casos válidos
        
        #Caso I:    12 caracteres mismo contenido
        mensajeEncriptado = aClsAccessControl.encript(s9)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,s9),"Las contraseñas deben coincidir")
 
#CASOS      
s0 = "M3A0$d8"              #Longitud 7
s1 = "C@d3Ã±Aca%a(|3&E$"    #longitud 17
s2 = "sR_r@5!"              #longitud 7
s3 = "Pf47]d2<0o|1Rfa+l"    #longitud 17
s4 = ""                     #longitud 0
s5 = "pa$$w0rD"             #longitud 8
s6 = "169rh!Añg5wxQzp0"     #longitud 16
s7 = "|2E4$7()"             #longitud 8
s8 = "Ã±p890dfWn.z<%o#"     #longitud 16
s9 = "1ng.$ofTw@re"         #longitud 12 caracteres
  