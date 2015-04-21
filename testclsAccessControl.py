'''
Created on 20/4/2015

@author: sahid
'''
import unittest
from mdlaccesscontrol import *

class ClsAccessControlTester(unittest.TestCase):
    
    #def testClsAccessControl(self):
        #aClsAccessControl = clsAccessControl(object)
       
    def testClsAccessControlEncript(self):
        aClsAccessControl = clsAccessControl(object)
        
        
    def testClsAccessControlCheck_password(self):
        aClsAccessControl = clsAccessControl(object)
        aClsAccessControl.check_password()