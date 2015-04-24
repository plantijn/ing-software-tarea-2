'''
Created on 20/4/2015

@author: sahid
'''
import unittest
from mdlaccesscontrol import *

class ClsAccessControlTester(unittest.TestCase):

    def testClsAccessControlCheck_passwordEncriptFalse(self):
        aClsAccessControl = clsAccessControl() 
        c0 = ""         #longitud 0
        mensajeEncriptado = ClsAccessControl.encript(c0)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c0))
    
        c1 = "M3A0$d8"  #Longitud 7    caracteres válidos
        mensajeEncriptado = aClsAccessControl.encript(c1)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c1))
        
        c2 = "_ko8E{}"  #longitud 7    caracteres inválidos
        mensajeEncriptado = aClsAccessControl.encript(c2)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c2))
        
        c3 = "#.LpeW@"  #longitud 7    sin dígitos
        mensajeEncriptado = aClsAccessControl.encript(c3)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c3))
        
        c4 = "$s@kpf*"  #longitud 7    sin digitos ni mayusculas
        mensajeEncriptado = aClsAccessControl.encript(c4)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c4))
        
        c5 = "fToesQp"  #longitud 7    sin digitos ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c5)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c5))
        
        c6 = "d#6fo@3"  #longitud 7    sin mayúsculas
        mensajeEncriptado = aClsAccessControl.encript(c6)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c6))
        c7 = "irj120k"  #longitud 7    sin mayusculas ni caracteres especiales
        c8 = "1F09ir2"  #longitud 7    sin caracteres especiales
        c9 = "fpeosnq"  #longitud 7    sin los requisitos minimos
        
        c10 = "C*@d$.3Aca#a3aE+$"    #longitud 17    caracteres válidos
        c11 = "(-:cpsm09JK\?|{=]"    #longitud 17    caracteres inválidos
        c12 = "#.LpeW@+lnkzA.@yl"    #longitud 17    sin dígitos
        c13 = "k*sdj+fwei..weh@#"    #longitud 17    sin digitos ni mayusculas
        c14 = "MJiqJwieALniDGRou"    #longitud 17    sin digitos ni caracteres especiales
        c15 = "@#$+zj*ic71c22x.."    #longitud 17    sin mayúsculas
        c16 = "i3u48712384uioiqm"    #longitud 17    sin mayusculas ni caracteres especiales
        c17 = "JFFefn93kNJK43672"    #longitud 17    sin caracteres especiales
        c18 = "00000000000000000"    #longitud 17    sin los requisitos minimos    
        
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
        
        c37 = "pa$$w0rD."  #longitud 9    caracteres válidos
        c38 = "_ko8E{?}¬"  #longitud 9    caracteres inválidos
        c39 = "#.LpeWr@t"  #longitud 9    sin dígitos
        c40 = "$s@kp.f*p"  #longitud 9    sin digitos ni mayusculas
        c41 = "fToesQhpI"  #longitud 9    sin digitos ni caracteres especiales
        c42 = "d#6fo@.3q"  #longitud 9    sin mayúsculas
        c43 = "irj1290k1"  #longitud 9    sin mayusculas ni caracteres especiales
        c44 = "1F09irA20"  #longitud 9    sin caracteres especiales
        c45 = "fpeosrnql"  #longitud 9    sin los requisitos minimos
    
        c46 = "16.9rh@AgwxQzp0"  #longitud 15    caracteres válidos
        c47 = "_k?¡[ñ]<z]o8E{}"  #longitud 15    caracteres inválidos
        c48 = "#.LpWo@lEdff@#*"  #longitud 15    sin dígitos
        c49 = "$s@kp#.*rthq+f*"  #longitud 15    sin digitos ni mayusculas
        c50 = "fToesQpUGndpder"  #longitud 15    sin digitos ni caracteres especiales
        c51 = "d#6o@3$.+*t34do"  #longitud 15    sin mayúsculas
        c52 = "ir120k720fnsl0j"  #longitud 15    sin mayusculas ni caracteres especiales
        c53 = "1F09ir2UNdpw350"  #longitud 15    sin caracteres especiales
        c54 = "fpeosnqjdengosq"  #longitud 15    sin los requisitos minimos
    
    #def testClsAccessControlCheck_passwordTrue(self):
