# -*- coding: utf-8 -*-. 
'''
Created on 24/9/2014

@author: Jean Carlos, Sahid Reyes 10-10603 y Carlos Plantijn 10-10572

'''
import uuid
import hashlib
import re

class clsAccessControl(object):
    
    def __init__(self):
        ohast=''
        self.expressionRegular = ('(([a-z]|[A-Z]|\d|[@.#$+*])*[@.#$+*]([a-z]|[A-Z]|\d|[@.#$+*])*[A-Z]([a-z]|[A-Z]|\d|[@.#$+*])*\d([a-z]|[A-Z]|\d|[@.#$+*])*)|'
                                  '(([a-z]|[A-Z]|\d|[@.#$+*])*[@.#$+*]([a-z]|[A-Z]|\d|[@.#$+*])*\d([a-z]|[A-Z]|\d|[@.#$+*])*[A-Z]([a-z]|[A-Z]|\d|[@.#$+*])*)|'
                                  '(([a-z]|[A-Z]|\d|[@.#$+*])*[A-Z]([a-z]|[A-Z]|\d|[@.#$+*])*[@.#$+*]([a-z]|[A-Z]|\d|[@.#$+*])*\d([a-z]|[A-Z]|\d|[@.#$+*])*)|'
                                  '(([a-z]|[A-Z]|\d|[@.#$+*])*[A-Z]([a-z]|[A-Z]|\d|[@.#$+*])*\d([a-z]|[A-Z]|\d|[@.#$+*])*[@.#$+*]([a-z]|[A-Z]|\d|[@.#$+*])*)|'
                                  '(([a-z]|[A-Z]|\d|[@.#$+*])*\d([a-z]|[A-Z]|\d|[@.#$+*])*[@.#$+*]([a-z]|[A-Z]|\d|[@.#$+*])*[A-Z]([a-z]|[A-Z]|\d|[@.#$+*])*)|'
                                  '(([a-z]|[A-Z]|\d|[@.#$+*])*\d([a-z]|[A-Z]|\d|[@.#$+*])*[A-Z]([a-z]|[A-Z]|\d|[@.#$+*])*[@.#$+*]([a-z]|[A-Z]|\d|[@.#$+*])*)')
    def encript(self, value):
        # Verificar la longitud del password
        oHash=""
        olength_password=self.length_password(value)
        if olength_password>=8 and olength_password<=16:
            validPassword= re.search(self.expressionRegular, value)
            if validPassword:
            # uuid es usado para generar numeros random
                salt = uuid.uuid4().hex
            # hash
                oHash= hashlib.sha256(salt.encode() + value.encode()).hexdigest() + ':' + salt
                return oHash
            else:
                #print('El password no posee los caracteres correspondientes')
                return oHash
        else:
            #print('El Password debe contener entre 8 y 16 caracteres')
            return oHash   
    
    def check_password(self, oPassworkEncript, oCheckPassword):
        # Verificar la longitud del password
        olength_password=self.length_password(oCheckPassword)        
        if olength_password>=8 and olength_password<=16:
            validPassword= re.search(self.expressionRegular,oCheckPassword) 
            if validPassword:
                # uuid es usado para generar numeros random
                oPassworkEncript, salt = oPassworkEncript.split(':')
                return oPassworkEncript == hashlib.sha256(salt.encode() + oCheckPassword.encode()).hexdigest()
            else:
                #print('El password no posee los caracteres correspondientes')
                return False
        else:
            #print('El Password no posee la cantidad de caracteres requerida')
            return False
    
    def length_password(self, user_password):
        # uuid es usado para generar numeros random
        return len(user_password)

#Para encriptar un passwork  
#oPassword = input('Por favor ingrese su password: ')
#Se crea un objeto tipo clsAccessControl
#oAccessControl=clsAccessControl()
#oPassworkEncript = oAccessControl.encript(oPassword)
#print('El Password almacenado en la memoria es: ' + oPassworkEncript)
#if oPassworkEncript:
    #Para validar el passwork introducido
 #   oCheckPassword = input('Para verificar su password, ingreselo nuevamente: ')
  #  if oAccessControl.check_password(oPassworkEncript, oCheckPassword):
   #     print('Ha introducido el password correcto')
    #else:
     #   print('El password es diferente')


