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
        
        #Caso J:    12 caracteres mismo contenido
        mensajeEncriptado = aClsAccessControl.encript(s9)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,s9),"Las contraseñas deben coincidir")
 
#CASOS      

c0 = ""         #longitud 0 

c1 = "M3A0$d8"  #Longitud 7    caracteres válidos
c2 = "_ko8E{}"  #longitud 7    caracteres inválidos
c3 = "#.LpeW@"  #longitud 7    sin dígitos
c4 = "$s@kpf*"  #longitud 7    sin digitos ni mayusculas
c5 = "fToesQp"  #longitud 7    sin digitos ni caracteres especiales
c6 = "d#6fo@3"  #longitud 7    sin mayúsculas
c7 = "irj120k"  #longitud 7    sin mayusculas ni caracteres especiales
c8 = "1F09ir2"  #longitud 7    sin caracteres especiales
c9 = "fpeosnq"  #longitud 7    sin los requisitos minimos

c19= "pa$$w0rD"  #longitud 8    caracteres válidos
c20 = "_ko8E{?}"  #longitud 8    caracteres inválidos
c21 = "#.LpeWr@"  #longitud 8    sin dígitos
c22 = "$s@kp.f*"  #longitud 8    sin digitos ni mayusculas
c23 = "fToesQhp"  #longitud 8    sin digitos ni caracteres especiales
c24 = "d#6fo@.3"  #longitud 8    sin mayúsculas
c25 = "irj1290k"  #longitud 8    sin mayusculas ni caracteres especiales
c26 = "1F09irA2"  #longitud 8    sin caracteres especiales
c27 = "fpeosrnq"  #longitud 8    sin los requisitos minimos
                              
c28 = "16.9rh@Ag5wxQzp0"  #longitud 16    caracteres válidos
c29 = "_k?¡[ñ]<z]>o8E{}"  #longitud 16    caracteres inválidos
c30 = "#.LpeWo@lEdff@#*"  #longitud 16    sin dígitos
c31 = "$s@kpf#.*rthq+f*"  #longitud 16    sin digitos ni mayusculas
c32 = "fToesQpUGndpwder"  #longitud 16    sin digitos ni caracteres especiales
c33 = "d#6fo@3$.+*t34do"  #longitud 16    sin mayúsculas
c34 = "irj120k720fnsl0j"  #longitud 16    sin mayusculas ni caracteres especiales
c35 = "1F09ir2UNdpw3450"  #longitud 16    sin caracteres especiales
c36 = "fpeosnqjdoengosq"  #longitud 16    sin los requisitos minimos