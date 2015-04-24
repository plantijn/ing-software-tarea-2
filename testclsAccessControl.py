'''
Created on 20/4/2015

@author: Sahid Reyes 10-10603 y Carlos Plantijn 10-10572
'''
import unittest
from mdlaccesscontrol import *

class ClsAccessControlTester(unittest.TestCase):

    def testClsAccessControlEncriptFalse(self):
        aClsAccessControl = clsAccessControl() 
     
        #Caso malicia
        c0 = ""         #longitud 0
        self.assertEqual("", aClsAccessControl.encript(c0))
       
        #Casos esquina
        c1 = "M3A0$d8"  #longitud 7    caracteres v�lidos
        self.assertEqual("", aClsAccessControl.encript(c1))
        
        c2 = "_ko8E{}"  #longitud 7    caracteres inv�lidos
        self.assertEqual("", aClsAccessControl.encript(c2))
        
        c3 = "#.LpeW@"  #longitud 7    sin d�gitos
        self.assertEqual("", aClsAccessControl.encript(c3))
        
        c4 = "$s@kpf*"  #longitud 7    sin d�gitos ni may�sculas
        self.assertEqual("", aClsAccessControl.encript(c4))
        
        c5 = "fToesQp"  #longitud 7    sin d�gitos ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c5))
        
        c6 = "d#6fo@3"  #longitud 7    sin may�sculas
        self.assertEqual("", aClsAccessControl.encript(c6))
        
        c7 = "irj120k"  #longitud 7    sin may�sculas ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c7))
        
        c8 = "1F09ir2"  #longitud 7    sin caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c8))
        
        c9 = "fpeosnq"  #longitud 7    sin los requisitos m�nimos
        self.assertEqual("", aClsAccessControl.encript(c9))
        
        c10 = "C*@d$.3Aca#a3aE+$"    #longitud 17    caracteres v�lidos
        self.assertEqual("", aClsAccessControl.encript(c10))
        
        c11 = "(-:cpsm09JK\?|{=]"    #longitud 17    caracteres inv�lidos
        self.assertEqual("", aClsAccessControl.encript(c11))
        
        c12 = "#.LpeW@+lnkzA.@yl"    #longitud 17    sin d�gitos
        self.assertEqual("", aClsAccessControl.encript(c12))
        
        c13 = "k*sdj+fwei..weh@#"    #longitud 17    sin d�gitos ni may�sculas
        self.assertEqual("", aClsAccessControl.encript(c13))
        
        c14 = "MJiqJwieALniDGRou"    #longitud 17    sin d�gitos ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c14))
        
        c15 = "@#$+zj*ic71c22x.."    #longitud 17    sin may�sculas
        self.assertEqual("", aClsAccessControl.encript(c15))
        
        c16 = "i3u48712384uioiqm"    #longitud 17    sin may�sculas ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c16))
        
        c17 = "JFFefn93kNJK43672"    #longitud 17    sin caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c17))
        
        c18 = "00000000000000000"    #longitud 17    sin los requisitos m�nimos    
        self.assertEqual("", aClsAccessControl.encript(c18))    
        
        c20 = "_ko8E{?}"  #longitud 8    caracteres inv�lidos
        self.assertEqual("", aClsAccessControl.encript(c20))
        
        c21 = "#.LpeWr@"  #longitud 8    sin d�gitos
        self.assertEqual("", aClsAccessControl.encript(c21))
        
        c22 = "$s@kp.f*"  #longitud 8    sin d�gitos ni may�sculas
        self.assertEqual("", aClsAccessControl.encript(c22))
        
        c23 = "fToesQhp"  #longitud 8    sin d�gitos ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c23))
        
        c24 = "d#6fo@.3"  #longitud 8    sin may�sculas
        self.assertEqual("", aClsAccessControl.encript(c24))
        
        c25 = "irj1290k"  #longitud 8    sin may�sculas ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c25))
        
        c26 = "1F09irA2"  #longitud 8    sin caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c26))
        
        c27 = "fpeosrnq"  #longitud 8    sin los requisitos m�nimos
        self.assertEqual("", aClsAccessControl.encript(c27))
                                  
               
        c29 = "_k?¡[ñ]<z]>o8E{}"  #longitud 16    caracteres inv�lidos
        self.assertEqual("", aClsAccessControl.encript(c29))
        
        c30 = "#.LpeWo@lEdff@#*"  #longitud 16    sin d�gitos
        self.assertEqual("", aClsAccessControl.encript(c30))
        
        c31 = "$s@kpf#.*rthq+f*"  #longitud 16    sin d�gitos ni may�sculas
        self.assertEqual("", aClsAccessControl.encript(c31))
        
        c32 = "fToesQpUGndpwder"  #longitud 16    sin d�gitos ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c32))
        
        c33 = "d#6fo@3$.+*t34do"  #longitud 16    sin may�sculas
        self.assertEqual("", aClsAccessControl.encript(c33))
        
        c34 = "irj120k720fnsl0j"  #longitud 16    sin may�sculas ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c34))
        
        c35 = "1F09ir2UNdpw3450"  #longitud 16    sin caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c35))
        
        c36 = "fpeosnqjdoengosq"  #longitud 16    sin los requisitos m�nimos
        self.assertEqual("", aClsAccessControl.encript(c36))
                
        c38 = "_ko8E{?}¬"  #longitud 9    caracteres inv�lidos
        self.assertEqual("", aClsAccessControl.encript(c38))
        
        c39 = "#.LpeWr@t"  #longitud 9    sin d�gitos
        self.assertEqual("", aClsAccessControl.encript(c39))
        
        c40 = "$s@kp.f*p"  #longitud 9    sin d�gitos ni may�sculas
        self.assertEqual("", aClsAccessControl.encript(c40))
        
        c41 = "fToesQhpI"  #longitud 9    sin d�gitos ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c41))
        
        c42 = "d#6fo@.3q"  #longitud 9    sin may�sculas
        self.assertEqual("", aClsAccessControl.encript(c42))
        
        c43 = "irj1290k1"  #longitud 9    sin may�sculas ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c43))
        
        c44 = "1F09irA20"  #longitud 9    sin caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c44))
        
        c45 = "fpeosrnql"  #longitud 9    sin los requisitos m�nimos
        self.assertEqual("", aClsAccessControl.encript(c45))
        
        c47 = "_k?¡[ñ]<z]o8E{}"  #longitud 15    caracteres inv�lidos
        self.assertEqual("", aClsAccessControl.encript(c47))
        
        c48 = "#.LpWo@lEdff@#*"  #longitud 15    sin d�gitos
        self.assertEqual("", aClsAccessControl.encript(c48))
        
        c49 = "$s@kp#.*rthq+f*"  #longitud 15    sin d�gitos ni may�sculas
        self.assertEqual("", aClsAccessControl.encript(c49))
        
        c50 = "fToesQpUGndpder"  #longitud 15    sin d�gitos ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c50))
        
        c51 = "d#6o@3$.+*t34do"  #longitud 15    sin may�sculas
        self.assertEqual("", aClsAccessControl.encript(c51)) 
        
        c52 = "ir120k720fnsl0j"  #longitud 15    sin may�sculas ni caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c52))
        
        c53 = "1F09ir2UNdpw350"  #longitud 15    sin caracteres especiales
        self.assertEqual("", aClsAccessControl.encript(c53))
        
        c54 = "fpeosnqjdengosq"  #longitud 15    sin los requisitos m�nimos
        self.assertEqual("", aClsAccessControl.encript(c54))
    
    def testClsAccessControlEncriptTrue(self): 
        aClsAccessControl = clsAccessControl() 
        
        #Casos
        c19= "pa$$w0rD"  #longitud 8    caracteres v�lidos
        self.assertNotEqual("", aClsAccessControl.encript(c19))
        
        c28 = "16.9rh@Ag5wxQzp0"  #longitud 16    caracteres v�lidos
        self.assertNotEqual("", aClsAccessControl.encript(c28))   
        
        c37 = "pa$$w0rD."  #longitud 9    caracteres v�lidos
        self.assertNotEqual("", aClsAccessControl.encript(c37))
        
        c46 = "16.9rh@AgwxQzp0"  #longitud 15    caracteres v�lidos
        self.assertNotEqual("", aClsAccessControl.encript(c46))
        
    def testClsAccessControlCheck_passwordEncriptFalse(self):
        aClsAccessControl = clsAccessControl() 
        c0 = ""         #longitud 0
        mensajeEncriptado = aClsAccessControl.encript(c0)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c0))
    
        c1 = "M3A0$d8"  #Longitud 7    caracteres vÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c1)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c1))
        
        c2 = "_ko8E{}"  #longitud 7    caracteres invÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c2)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c2))
        
        c3 = "#.LpeW@"  #longitud 7    sin dÃ­gitos
        mensajeEncriptado = aClsAccessControl.encript(c3)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c3))
        
        c4 = "$s@kpf*"  #longitud 7    sin digitos ni mayusculas
        mensajeEncriptado = aClsAccessControl.encript(c4)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c4))
        
        c5 = "fToesQp"  #longitud 7    sin digitos ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c5)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c5))
        
        c6 = "d#6fo@3"  #longitud 7    sin mayÃºsculas
        mensajeEncriptado = aClsAccessControl.encript(c6)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c6))
        
        c7 = "irj120k"  #longitud 7    sin mayusculas ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c7)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c7))
        
        c8 = "1F09ir2"  #longitud 7    sin caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c8)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c8))
        
        c9 = "fpeosnq"  #longitud 7    sin los requisitos minimos
        mensajeEncriptado = aClsAccessControl.encript(c9)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c9))
        
        c10 = "C*@d$.3Aca#a3aE+$"    #longitud 17    caracteres vÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c10)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c10))
        
        c11 = "(-:cpsm09JK\?|{=]"    #longitud 17    caracteres invÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c11)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c11))
        
        c12 = "#.LpeW@+lnkzA.@yl"    #longitud 17    sin dÃ­gitos
        mensajeEncriptado = aClsAccessControl.encript(c12)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c12))
        
        c13 = "k*sdj+fwei..weh@#"    #longitud 17    sin digitos ni mayusculas
        mensajeEncriptado = aClsAccessControl.encript(c13)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c13))    
        
        c14 = "MJiqJwieALniDGRou"    #longitud 17    sin digitos ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c14)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c14))
        
        c15 = "@#$+zj*ic71c22x.."    #longitud 17    sin mayÃºsculas
        mensajeEncriptado = aClsAccessControl.encript(c15)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c15))        
        
        c16 = "i3u48712384uioiqm"    #longitud 17    sin mayusculas ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c16)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c16))
                
        c17 = "JFFefn93kNJK43672"    #longitud 17    sin caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c17)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c17))
                
        c18 = "00000000000000000"    #longitud 17    sin los requisitos minimos    
        mensajeEncriptado = aClsAccessControl.encript(c18)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c18))            

        c20 = "_ko8E{?}"  #longitud 8    caracteres invÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c20)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c20))
                
        c21 = "#.LpeWr@"  #longitud 8    sin dÃ­gitos
        mensajeEncriptado = aClsAccessControl.encript(c21)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c21))
                
        c22 = "$s@kp.f*"  #longitud 8    sin digitos ni mayusculas
        mensajeEncriptado = aClsAccessControl.encript(c22)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c22))
                
        c23 = "fToesQhp"  #longitud 8    sin digitos ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c23)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c23))        
        
        c24 = "d#6fo@.3"  #longitud 8    sin mayÃºsculas
        mensajeEncriptado = aClsAccessControl.encript(c24)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c24))
        
        c25 = "irj1290k"  #longitud 8    sin mayusculas ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c25)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c25))
                
        c26 = "1F09irA2"  #longitud 8    sin caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c26)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c26))
                
        c27 = "fpeosrnq"  #longitud 8    sin los requisitos minimos
        mensajeEncriptado = aClsAccessControl.encript(c27)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c27))
            
        c29 = "_k?Â¡[Ã±]<z]>o8E{}"  #longitud 16    caracteres invÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c29)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c29))
                
        c30 = "#.LpeWo@lEdff@#*"  #longitud 16    sin dÃ­gitos
        mensajeEncriptado = aClsAccessControl.encript(c30)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c30))
                
        c31 = "$s@kpf#.*rthq+f*"  #longitud 16    sin digitos ni mayusculas
        mensajeEncriptado = aClsAccessControl.encript(c31)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c31))
                
        c32 = "fToesQpUGndpwder"  #longitud 16    sin digitos ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c32)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c32))
                
        c33 = "d#6fo@3$.+*t34do"  #longitud 16    sin mayÃºsculas
        mensajeEncriptado = aClsAccessControl.encript(c33)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c33))
                
        c34 = "irj120k720fnsl0j"  #longitud 16    sin mayusculas ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c34)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c34))
                
        c35 = "1F09ir2UNdpw3450"  #longitud 16    sin caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c35)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c35))
                
        c36 = "fpeosnqjdoengosq"  #longitud 16    sin los requisitos minimos
        mensajeEncriptado = aClsAccessControl.encript(c36)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c36))
                         
        c38 = "_ko8E{?}Â¬"  #longitud 9    caracteres invÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c38)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c38))
        
        c39 = "#.LpeWr@t"  #longitud 9    sin dÃ­gitos
        mensajeEncriptado = aClsAccessControl.encript(c39)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c39))
        
        c40 = "$s@kp.f*p"  #longitud 9    sin digitos ni mayusculas
        mensajeEncriptado = aClsAccessControl.encript(c40)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c40))
        
        c41 = "fToesQhpI"  #longitud 9    sin digitos ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c41)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c41))
                
        c42 = "d#6fo@.3q"  #longitud 9    sin mayÃºsculas
        mensajeEncriptado = aClsAccessControl.encript(c42)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c42))
                
        c43 = "irj1290k1"  #longitud 9    sin mayusculas ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c43)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c43))
                
        c44 = "1F09irA20"  #longitud 9    sin caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c44)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c44))
                
        c45 = "fpeosrnql"  #longitud 9    sin los requisitos minimos
        mensajeEncriptado = aClsAccessControl.encript(c45)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c45))     
       
        c47 = "_k?Â¡[Ã±]<z]o8E{}"  #longitud 15    caracteres invÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c47)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c47))        
        
        c48 = "#.LpWo@lEdff@#*"  #longitud 15    sin dÃ­gitos
        mensajeEncriptado = aClsAccessControl.encript(c48)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c48))        
        
        c49 = "$s@kp#.*rthq+f*"  #longitud 15    sin digitos ni mayusculas
        mensajeEncriptado = aClsAccessControl.encript(c49)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c49)) 
               
        c50 = "fToesQpUGndpder"  #longitud 15    sin digitos ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c50)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c50))
                
        c51 = "d#6o@3$.+*t34do"  #longitud 15    sin mayÃºsculas
        mensajeEncriptado = aClsAccessControl.encript(c51)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c51))
                
        c52 = "ir120k720fnsl0j"  #longitud 15    sin mayusculas ni caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c52)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c52))
                
        c53 = "1F09ir2UNdpw350"  #longitud 15    sin caracteres especiales
        mensajeEncriptado = aClsAccessControl.encript(c53)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c53))
                
        c54 = "fpeosnqjdengosq"  #longitud 15    sin los requisitos minimos
        mensajeEncriptado = aClsAccessControl.encript(c54)
        self.assertFalse(aClsAccessControl.check_password(mensajeEncriptado,c54))
            
    def testClsAccessControlCheck_passwordTrue(self):
        aClsAccessControl = clsAccessControl() 
        
        c19= "pa$$w0rD"  #longitud 8    caracteres vÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c19)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,c19))
       
        c28 = "16.9rh@Ag5wxQzp0"  #longitud 16    caracteres vÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c28)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,c28))
        
        c37 = "pa$$w0rD."  #longitud 9    caracteres vÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c37)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,c37))
       
        c46 = "16.9rh@AgwxQzp0"  #longitud 15    caracteres vÃ¡lidos
        mensajeEncriptado = aClsAccessControl.encript(c46)
        self.assertTrue(aClsAccessControl.check_password(mensajeEncriptado,c46))