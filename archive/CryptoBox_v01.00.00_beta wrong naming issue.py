# __________/\\\\\\\\\________________________________________________________________________/\\\\\\\\\\\\\__________________________________
#  _______/\\\////////________________________________________________________________________\/\\\/////////\\\________________________________
#   _____/\\\/____________________________/\\\__/\\\___/\\\\\\\\\______/\\\____________________\/\\\_______\/\\\________________________________
#    ____/\\\______________/\\/\\\\\\\____\//\\\/\\\___/\\\/////\\\__/\\\\\\\\\\\_____/\\\\\____\/\\\\\\\\\\\\\\______/\\\\\_____/\\\____/\\\____
#     ___\/\\\_____________\/\\\/////\\\____\//\\\\\___\/\\\\\\\\\\__\////\\\////____/\\\///\\\__\/\\\/////////\\\___/\\\///\\\__\///\\\/\\\/_____
#      ___\//\\\____________\/\\\___\///______\//\\\____\/\\\//////______\/\\\_______/\\\__\//\\\_\/\\\_______\/\\\__/\\\__\//\\\___\///\\\/_______
#       ____\///\\\__________\/\\\__________/\\_/\\\_____\/\\\____________\/\\\_/\\__\//\\\__/\\\__\/\\\_______\/\\\_\//\\\__/\\\_____/\\\/\\\______
#        ______\////\\\\\\\\\_\/\\\_________\//\\\\/______\/\\\____________\//\\\\\____\///\\\\\/___\/\\\\\\\\\\\\\/___\///\\\\\/____/\\\/\///\\\____
#         _________\/////////__\///___________\////________\///______________\/////_______\/////_____\/////////////_______\/////_____\///____\///_____
#          ____________________________________________________________________________________________________________________________________________
#           ____/\\\\\_____/\\\____________________________________/\\\\\\______________________________________________________________________________
#            ___\/\\\\\\___\/\\\___________________________________\////\\\______________________________________________________________________________
#             ___\/\\\/\\\__\/\\\__/\\\___/\\\\\\\\____________________\/\\\______________________________________________________________________________
#              ___\/\\\//\\\_\/\\\_\///___/\\\////\\\_____/\\\\\\\\_____\/\\\______________________________________________________________________________
#               ___\/\\\\//\\\\/\\\__/\\\_\//\\\\\\\\\___/\\\/////\\\____\/\\\______________________________________________________________________________
#                ___\/\\\_\//\\\/\\\_\/\\\__\///////\\\__/\\\\\\\\\\\_____\/\\\______________________________________________________________________________
#                 ___\/\\\__\//\\\\\\_\/\\\__/\\_____\\\_\//\\///////______\/\\\______________________________________________________________________________
#                  ___\/\\\___\//\\\\\_\/\\\_\//\\\\\\\\___\//\\\\\\\\\\__/\\\\\\\\\___________________________________________________________________________
#                   ___\///_____\/////__\///___\////////_____\//////////__\/////////____________________________________________________________________________
# _____________________________________________________________________________________________________________________________________________________________

#   Initial version was built in July 2016                                       #
#                                                                                #
#   Version Number Defination:                                                   #
#   v01.00.00 20170306                                                           #
#    -- -- --                                                                    #
#     |  |  |                                                                    #
#     |  |  +------     GUI Updates                                              #
#     |  +---------     Crypto Function Updates                                  #
#     +------------     Published Version (Major Change)                         #
#                                                                                #
# _______________________________________________________________________________#
#
#   DES operation works very well on v00.09.09.x 201610xx
#   v00.09.09 has been added new buttons:
#   01. TDES algorithm has been added !!! Works well !!!
#   02. AES  algorithm has been added !!! Works well !!!
#   03. Random number generator has been added !!! Works well !!!
#   04. Added a Exit button to quit program !!! Works well !!!
#   05. Added algo_tab (x6). SHA and RSA are not completed xxx - (RSA is not correct - 20161219)
#       RSA calculation is correct - 20170301
#   06. Adding the menu bar.............(No idea so far how to do so :( )
#   07. DES/TDES function is corrected !!!
#   08. Adding length counter after key and iv fileds..............(No idea :( )
#   09. Adding fileopen function for RSA key-file and data-file import
#   10. Adding Hash function and GUI...........all done except HMAC operation
#   11. Scrollbar has not been added due to lack of knowledge............
#   12. Incorrect key length error message is removed in DES/TDES - solved!!!
#   13. "Use output as the key" function is added!!!
#   14. Correct all fonts !!!
#   15. Digital clock and counter for 120PIN have been completed !!!
#   16. RSA datainput and dataoutput text box works well !!!
#   17. RSA calculation is fully solved !!!!!!! 20170301
#   18. David gave me a suggestion on using RSA.construct((n, e, d)) to import keys
#   19. RSA.construct() is being used correctly!!! 20170301
# ________________________________________________________________________________#
#   GUI import
# from Tkinter import *
from Tkinter import *
# fomr Tkinter import Tk # ?? does it have Tk? or ttk?
from tkMessageBox import *
from tkFileDialog import *

#   Crypto import
from Crypto.Cipher import DES, DES3, AES
from Crypto.Hash import SHA, SHA224, SHA256, SHA384, SHA512, MD4, MD5, HMAC
from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from binascii import a2b_base64
from OpenSSL import SSL
# from crcmod import predefined
from Crypto import Random
from datetime import date
#from pyasn1_modules import pem, rfc2459
#from pyasn1.codec.der import decoder

import os
import tkFont
import tkMessageBox
import socket
import string
import select
import Tkinter as tk
import ttk
import binascii
import time
#import tkHyperlinkManager
import webbrowser


key_pub_filename = ''
key_pri_filename = ''
input_filename = ''
p120_butt_clicked = 0


def update_timeText():
    # Get the current time, note you can change the format as you wish
    current = time.strftime("%Y/%m/%d  %H:%M:%S")
    # Update the timeText Label box with the current time
    realtime.configure(text=current)
    # Call the update_timeText() function after 1 second
    root.after(100, update_timeText)



'''
def author(): showinfo('Author','UL-TS Australia\n' 'Nigel Z.\n')
def about():
    about_window = Toplevel(root)
    about_window.geometry("250x50+100+1000")
    about_label = Label(about_window, text='CryptoBox\n Version 00.01.02\n Copyright 2016  Nigel Z.  All rights reserved.')
    about_label.pack(fill=X)
'''
root = tk.Tk()
root.title('CryptoBox v00.10.15.x20170305')
root.geometry("540x480+20+20")    #("560x480+0+0") for Linux; ("530+470+20+20") for Windows
algo_tab = ttk.Notebook(root)
frame_1_TDES = ttk.Frame(algo_tab)
frame_2_AES = ttk.Frame(algo_tab)
frame_3_1_RSA = ttk.Frame(algo_tab)
frame_3_2_RSA = ttk.Frame(algo_tab)
frame_3_3_RSA = ttk.Frame(algo_tab)
frame_4_HASH = ttk.Frame(algo_tab)
frame_5_XOR = ttk.Frame(algo_tab)
frame_6_RNG = ttk.Frame(algo_tab)
frame_7_120 = ttk.Frame(algo_tab)
frame_8_ABT = ttk.Frame(algo_tab)
algo_tab.add(frame_1_TDES, text='TDES\n')
algo_tab.add(frame_2_AES, text='AES\n')
algo_tab.add(frame_3_1_RSA, text='RSA\nGen.')
algo_tab.add(frame_3_2_RSA, text='RSA\nImport.')
algo_tab.add(frame_3_3_RSA, text='RSA\nCrypto.')
algo_tab.add(frame_4_HASH, text='HASH\n')
algo_tab.add(frame_5_XOR, text='XOR\n')
algo_tab.add(frame_6_RNG, text='RNG\n')
algo_tab.add(frame_7_120, text='120PINs\n')
algo_tab.add(frame_8_ABT, text='About\n...')
algo_tab.pack()
algo_SLC_TDES = IntVar()
operation_SLC_DES = IntVar()
operation_SLC_TDES = IntVar()
operation_SLC_AES = IntVar()
operation_SLC_RSA = IntVar()
operation_SLC_HASH = IntVar()
operation_SLC_HASH_hmac = IntVar()
# Enc_Dec_SLC_DES = IntVar()
# Enc_Dec_SLC_TDES = IntVar()
# Enc_Dec_SLC_AES = IntVar()
MODE_SLC_TDES = IntVar()
MODE_SLC_AES = IntVar()
KEY_IMPORT_METHOD = IntVar()

global temp_d, temp_e, temp_n

# Create a timeText Label (a text box)
realtime = tk.Label(root, text="", font=("Helvetica", 20))
realtime.pack(side=LEFT)
# Creat a Exit button
exit_button = tk.Button(root, text="Exit", width=10, command=quit)
exit_button.pack(side=RIGHT)

abt_msg = '''
The CryptoBox is a UL-TS cryptographic calculator developed internally.\n
It supports multiple algorithms include single DES, triple TDES, AES, RSA,\n
HASH, as well as exclusive OR operation, random number generator,and \n
other non-cryptographic features.\n\n\n
Please contact the developer if you have any suggestion or feedback\n
on the current CryptoBox.\n\n\n
Thank you for using CryptoBox!
'''

class MenuBar(Frame):
    def __init__(self):
        Frame.__int__(self)
        self.menubar = Menu(self)
        menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(lable="About", menu=menu)
        menu.add_command(label="Copyright")




class CryptoBox(tk.Tk):
    #   GUI interface definition

    #   Crypto function - DES
    def execution_TDES(self):
        #   algo & operation Judgment
        selection_Algo = algo_SLC_TDES.get()
        selection_EorD = operation_SLC_TDES.get()
        key_raw_xDES = self.key_textbox_TDES.get()
        key_len_check = (len(key_raw_xDES))/2
        print 'key len:', key_len_check
        '''
        if key_len_check != 8 or key_len_check != 16 or key_len_check != 24:
            self.output_textbox_TDES.delete(1.0, END)
            self.output_textbox_TDES.insert(1.0, "TDES Key length is not correct!")
        else:
            pass
        '''

        hkey_xDES = key_raw_xDES.replace(' ', '').decode('hex')
        print "\nDES/TDES key:      ", hkey_xDES.encode('hex')
        # print hkey_xDES.encode('hex')
        # print "\nhkey value",hkey_xDES
        # print hkey_xDES
        iv_raw_xDES = self.iv_textbox_TDES.get()
        hiv_xDES = iv_raw_xDES.replace(' ', '').decode('hex')
        print "initial iv:        ", hiv_xDES.encode('hex')
        # print hiv_xDES.encode('hex')
        input_raw_xDES = self.input_textbox_TDES.get()
        # print des_inpD
        h_in_data_xDES = input_raw_xDES.replace(' ', '').decode('hex')
        print "initial input data:", h_in_data_xDES.encode('hex')
        # print h_in_data_xDES.encode('hex')
        print "selection_EorD value:", selection_EorD
        # print selection_EorD
        if selection_Algo == 0:  # non DES/TDES algo
            self.output_textbox_TDES.delete(1.0, END)
            self.output_textbox_TDES.insert(1.0, "Please select an algorithm")
        elif selection_Algo == 1:  # DES algo
            key_len = (len(key_raw_xDES))/2
            print "key_len:", key_len
            '''
            if key_len != "16":
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, "Please enter correct key")
            #   'Enc/Dec' Judgment, and execute!!!
            '''
            if selection_EorD == 0 or key_len != 8:
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, "Key length or Operation is not correct")
            elif selection_EorD == 1 and key_len == 8:  # Enc operation
                #   'mode' Judgment - single DES does't need a mode selection
                #   ECB as a default mode
                mode = DES.MODE_ECB
                obj = DES.new(hkey_xDES, mode, hiv_xDES)
                #   Encryption !!
                output_raw_e = obj.encrypt(h_in_data_xDES)
                h_out_data_e = output_raw_e.encode('hex')
                print "DES (enc) result:", h_out_data_e
                # print h_out_data_e
                # print output_raw_e
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, h_out_data_e)
            elif selection_EorD == 2 and key_len == 8:  # Dec operation
                #   'mode' Judgment - single DES does't need a mode selection
                #   ECB as a default mode
                mode = DES.MODE_ECB
                obj = DES.new(hkey_xDES, mode, hiv_xDES)
                #   Decryption !!
                output_raw_d = obj.decrypt(h_in_data_xDES)
                h_out_data_d = output_raw_d.encode('hex')
                print "DES (dec)result:", h_out_data_d
                # print h_out_data_d
                # print output_raw_d
                # return pt.encode('hex')
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, h_out_data_d)
            else:
                print "\nUnknow error. Please send this error to nigel.zhai@ul.com"
                # else: pass
        elif selection_Algo == 2:  # TDES algo
            key_len = (len(key_raw_xDES))/2
            print "DES key length:", key_len
            mode_judge = MODE_SLC_TDES.get()
            if mode_judge == 1:
                mode = DES.MODE_ECB
            elif mode_judge == 2:
                mode = DES.MODE_CBC
            elif mode_judge == 3:
                mode = DES.MODE_CFB
            elif mode_judge == 4:
                mode = DES.MODE_OFB
            else:
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0,
                                                "Select a correct mode. Otherwise send this error to nigel.zhai@ul.com")
            # mode = MODE_SLC_TDES.get()  #   DES.MODE_ECB, DES.MODE_CBC, DES.MODE_OFB
            print "TDES mode is:", mode
            #   'Enc/Dec' Judgment, and execute!!!
            if selection_EorD == 0:
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, "Please select an operation")
            elif selection_EorD == 1 :  # Enc operation
                #   'mode' Judgment - single DES does't need a mode selection
                #   ECB as a default mode
                # mode = DES.MODE_ECB
                obj = DES3.new(hkey_xDES, mode, hiv_xDES)
                #   Encryption !!
                output_raw_e = obj.encrypt(h_in_data_xDES)
                h_out_data_e = output_raw_e.encode('hex')
                print "TDES (enc) result:", h_out_data_e
                # print h_out_data_e
                # print output_raw_e
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, h_out_data_e)
            elif selection_EorD == 2:  # Dec operation
                #   'mode' Judgment - single DES does't need a mode selection
                #   ECB as a default mode
                # mode = DES.MODE_ECB
                obj = DES3.new(hkey_xDES, mode, hiv_xDES)
                #   Decryption !!
                output_raw_d = obj.decrypt(h_in_data_xDES)
                h_out_data_d = output_raw_d.encode('hex')
                print "TDES (dec) result:", h_out_data_d
                # print h_out_data_d
                # print output_raw_d
                # return pt.encode('hex')
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, h_out_data_d)
            else:
                print "\nUnknow error. Please info Nigel"
        else:
            pass  # algo END
        # else: pass
        #   Crypto function - TDES

    def copy_key_value_TDES(self):
        key_temp_value_TDES = self.output_textbox_TDES.get(1.0, END)
        self.output_textbox_TDES.delete(1.0, END)
        self.key_textbox_TDES.delete(0, END)
        key_temp_value_TDES_no_0 = key_temp_value_TDES.replace("\r", '')
        print "key_temp_value_TDES_no_0", key_temp_value_TDES_no_0, key_temp_value_TDES_no_0
        self.key_textbox_TDES.insert(0, key_temp_value_TDES)
        print "new key value:", key_temp_value_TDES
        print "copy the TDES output value to key value..."

    #   Crypto function - AES
    def execution_AES(self):
        # print "AES Algo is under developing..."
        selection_aes_EorD = operation_SLC_AES.get()
        key_raw_AES = self.key_textbox_AES.get()
        key_len_check_aes = len(key_raw_AES)
        if key_len_check_aes != 32 or key_len_check_aes != 48 or key_len_check_aes != 64:
            self.output_textbox_AES.delete(1.0, END)
            self.output_textbox_AES.insert(1.0, "AES Key length is not correct !")
        else:
            pass
        hkey_AES = key_raw_AES.replace(' ', '').decode('hex')
        print "\nAES key:", hkey_AES.encode('hex')
        iv_raw_AES = self.iv_textbox_AES.get()
        hiv_AES = iv_raw_AES.replace(' ', '').decode('hex')
        print "initial iv:", hiv_AES.encode('hex')
        input_raw_AES = self.input_textbox_AES.get()
        h_in_data_AES = input_raw_AES.replace(' ', '').decode('hex')
        print "initial input data:", h_in_data_AES.encode('hex')
        print "selection_aes_EorD value:", selection_aes_EorD
        key_aes_len = len(key_raw_AES)
        print "key_aes_len:", key_aes_len
        mode_judge = MODE_SLC_AES.get()
        if mode_judge == 1:
            mode = AES.MODE_ECB
        elif mode_judge == 2:
            mode = AES.MODE_CBC
        elif mode_judge == 3:
            mode = AES.MODE_CFB
        elif mode_judge == 4:
            mode = AES.MODE_OFB
        else:
            self.output_textbox_AES.delete(1.0, END)
            self.output_textbox_AES.insert(1.0, "Select a correct mode. Otherwise send this error to nigel.zhai@ul.com")
        # mode = MODE_SLC_AES.get()  #   AES.MODE_ECB, AES.MODE_CBC, AES.MODE_OFB
        print "AES mode is:", mode
        #   'Enc/Dec' Judgment, and execute!!!
        if selection_aes_EorD == 0:
            self.output_textbox_AES.delete(1.0, END)
            self.output_textbox_AES.insert(1.0, "Please select an operation")
        elif selection_aes_EorD == 1 :  # AES Enc operation
            obj = AES.new(hkey_AES, mode, hiv_AES)
            #   Encryption !!
            output_aes_raw_e = obj.encrypt(h_in_data_AES)
            h_out_data_aes_e = output_aes_raw_e.encode('hex')
            print "AES (enc) result:", h_out_data_aes_e
            self.output_textbox_AES.delete(1.0, END)
            self.output_textbox_AES.insert(1.0, h_out_data_aes_e)
        elif selection_aes_EorD == 2 :  # AES Dec operation
            print "key_aes_len, selection_aes_EorD:", key_aes_len, selection_aes_EorD
            obj = AES.new(hkey_AES, mode, hiv_AES)
            #   Decryption !!
            output_aes_raw_d = obj.decrypt(h_in_data_AES)
            h_out_data_aes_d = output_aes_raw_d.encode('hex')
            print "AES (dec) result:", h_out_data_aes_d
            self.output_textbox_AES.delete(1.0, END)
            self.output_textbox_AES.insert(1.0, h_out_data_aes_d)
        else:
            pass

    def copy_key_value_AES(self):
        key_temp_value_AES = self.output_textbox_AES.get(1.0, END)
        self.output_textbox_AES.delete(1.0, END)
        self.key_textbox_AES.delete(0, END)
        self.key_textbox_AES.insert(0, key_temp_value_AES)
        print "new key value:", key_temp_value_AES
        print "copy the TDES output value to key value..."


    #   Crypto function - RSA
    def RSA_key_pair_gen_func(self):
        #get RSA key length:

        #rsa_len = 1024
        #enable the following line on the published version:
        rsa_len = self.RSA_k_len_En.get()
        print 'RSA private key length is:', rsa_len
        #generate private RSA key
        private = RSA.generate(int(rsa_len))
        public  = private.publickey()
        self.RSAgen_pri_key_tx.delete(1.0, END)
        self.RSAgen_pri_key_tx.insert(1.0, private.exportKey())
        self.RSAgen_pub_key_tx.delete(1.0, END)
        self.RSAgen_pub_key_tx.insert(1.0, public.exportKey())


        #   binascii.b2a_hex() is used for converting sth to hex string!!!!!
        print "\n==================================================================================="
        print "private:\n", private
        print "public:\n", public

        with open("pub.pem", "w") as pub_key:
            pub_key.write(public.exportKey())
        with open("pvt.pem", "w") as pvt_key:
            pvt_key.write(private.exportKey())


        self.RSAgen_output_exp_tx.delete(1.0, END)
        self.RSAgen_output_exp_tx.insert(1.0, hex(private.e).rstrip("L").lstrip("0x"))
        self.RSAgen_output_pri_tx.delete(1.0, END)
        self.RSAgen_output_pri_tx.insert(1.0, hex(private.d).rstrip("L").lstrip("0x"))
        self.RSAgen_output_pub_tx.delete(1.0, END)
        self.RSAgen_output_pub_tx.insert(1.0, hex(private.n).rstrip("L").lstrip("0x"))

        self.rsa_key_exp_import_tx.delete(1.0, END)
        self.rsa_key_exp_import_tx.insert(1.0, hex(private.e))
        self.rsa_key_pri_import_tx.delete(1.0, END)
        self.rsa_key_pri_import_tx.insert(1.0, hex(private.d))
        self.rsa_key_pub_import_tx.delete(1.0, END)
        self.rsa_key_pub_import_tx.insert(1.0, hex(private.n))

        with open("RSA_e_imported.imp", "w") as RSA_e:
            RSA_e.write(hex(private.e))
        with open("RSA_d_imported.imp", "w") as RSA_d:
            RSA_d.write(hex(private.d))
        with open("RSA_n_imported.imp", "w") as RSA_n:
            RSA_n.write(hex(private.n))


    def rsa_key_import_func(self):

        import_flag = KEY_IMPORT_METHOD.get()

        if import_flag == 0:
            self.rsa_key_imported_done.delete(1.0, END)
            self.rsa_key_imported_done.insert(1.0, "Please select an  importing method!")
        elif import_flag == 1:  # import keys from .imp files
            with open('RSA_e_imported.imp', 'r') as RSA_e_temp:
                test_value_e = RSA_e_temp.read()
            with open('RSA_d_imported.imp', 'r') as RSA_d_temp:
                test_value_d = RSA_d_temp.read()
            with open('RSA_n_imported.imp', 'r') as RSA_n_temp:
                test_value_n = RSA_n_temp.read()

            #convert hex string to long:
            key_n = long(test_value_n, 16)
            key_e = long(test_value_e, 16)
            key_d = long(test_value_d, 16)

            pri_const = RSA.construct((key_n, key_e, key_d))
            pub_const = RSA.construct((key_n, key_e))

            self.rsa_key_exp_import_tx.delete(1.0, END)
            self.rsa_key_exp_import_tx.insert(1.0, test_value_e)
            self.rsa_key_pri_import_tx.delete(1.0, END)
            self.rsa_key_pri_import_tx.insert(1.0, test_value_d)
            self.rsa_key_pub_import_tx.delete(1.0, END)
            self.rsa_key_pub_import_tx.insert(1.0, test_value_n)


            self.rsa_key_imported_done.delete(1.0, END)
            self.rsa_key_imported_done.insert(1.0, "Keys are imported!Go to RSA Crypto.!")

        elif import_flag == 2:  # import keys from following 3 boxes

            rsa_exp_import = self.rsa_key_exp_import_tx.get("1.0", END)    #"1.0", END
            rsa_pri_import = self.rsa_key_pri_import_tx.get("1.0", END)
            rsa_pub_import = self.rsa_key_pub_import_tx.get("1.0", END)


            with open("RSA_e_imported.imp", "w") as RSA_e_imported:
                RSA_e_imported.write(rsa_exp_import)
            with open("RSA_d_imported.imp", "w") as RSA_d_imported:
                RSA_d_imported.write(rsa_pri_import)
            with open("RSA_n_imported.imp", "w") as RSA_n_imported:
                RSA_n_imported.write(rsa_pub_import)


            with open('RSA_e_imported.imp', 'r') as RSA_e_temp:
                test_value_e = RSA_e_temp.read()
            with open('RSA_d_imported.imp', 'r') as RSA_d_temp:
                test_value_d = RSA_d_temp.read()
            with open('RSA_n_imported.imp', 'r') as RSA_n_temp:
                test_value_n = RSA_n_temp.read()

            #   number will only be printed in decimal format!!
            print "\ncomparing!!===================\n"
            print "test_value_e:\n", long(test_value_e, 16)
            print "test_value_d:\n", long(test_value_d, 16)
            print "test_value_n:\n", long(test_value_n, 16)
            print "rsa_exp_import:\n", rsa_exp_import
            print "\ncomparing!!===================\n"
            print "\ncomparing!!===================\n"


            #convert hex string to long:
            key_n = long(test_value_n, 16)
            key_e = long(test_value_e, 16)
            key_d = long(test_value_d, 16)

            pri_const = RSA.construct((key_n, key_e, key_d))
            pub_const = RSA.construct((key_n, key_e))

            print "\n#  4.7  -----------------------------------------------------------------------------"
            print "\npub_const:\n", pub_const


            print "\n#  5  -----------------------------------------------------------------------------"
            print "rsa_input_exp:\n", rsa_exp_import
            print "rsa_input_pri:\n", rsa_pri_import
            print "rsa_input_pub:\n", rsa_pub_import
            print "pri_const\n", pri_const, "\npub_const\n", pub_const
            print "\n#  6  -----------------------------------------------------------------------------"
            '''print "rsa_input_exp(hex)", hex(rsa_input_exp)
            print "rsa_input_pri(hex)", hex(rsa_input_pub)
            print "rsa_input_pub(hex)", hex(rsa_input_pub)'''
            print "\n#  7  -----------------------------------------------------------------------------"

            self.rsa_key_exp_import_tx.delete(1.0, END)
            self.rsa_key_exp_import_tx.insert(1.0, test_value_e)
            self.rsa_key_pri_import_tx.delete(1.0, END)
            self.rsa_key_pri_import_tx.insert(1.0, test_value_d)
            self.rsa_key_pub_import_tx.delete(1.0, END)
            self.rsa_key_pub_import_tx.insert(1.0, test_value_n)

            self.rsa_key_imported_done.delete(1.0, END)
            self.rsa_key_imported_done.insert(1.0, "Keys are imported!Go to RSA Crypto.!")


    def execution_RSA_enc(self):
        rsa_exp_4enc = self.rsa_key_exp_import_tx.get("1.0", END)
        rsa_pri_4enc = self.rsa_key_pri_import_tx.get("1.0", END)
        rsa_pub_4enc = self.rsa_key_pub_import_tx.get("1.0", END)

        plaintext_input_raw = self.rsa_data_in.get("1.0", END)
        plaintext_input = long(plaintext_input_raw, 16)

        key_e_4enc = long(rsa_exp_4enc, 16)
        key_d_4enc = long(rsa_pri_4enc, 16)
        key_n_4enc = long(rsa_pub_4enc, 16)

        pub_const = RSA.construct((key_n_4enc, key_e_4enc))

        ciphertext_output = pub_const.encrypt(plaintext_input, 0)[0]

        self.rsa_data_out.delete(1.0, END)
        self.rsa_data_out.insert(1.0, hex(ciphertext_output))

    def execution_RSA_dec(self):
        rsa_exp_4dec = self.rsa_key_exp_import_tx.get("1.0", END)
        rsa_pri_4dec = self.rsa_key_pri_import_tx.get("1.0", END)
        rsa_pub_4dec = self.rsa_key_pub_import_tx.get("1.0", END)

        ciphertext_input_raw = self.rsa_data_in.get("1.0", END)
        ciphertext_input = long(ciphertext_input_raw, 16)

        key_e_4dec = long(rsa_exp_4dec, 16)
        key_d_4dec = long(rsa_pri_4dec, 16)
        key_n_4dec = long(rsa_pub_4dec, 16)

        pri_const = RSA.construct((key_n_4dec, key_e_4dec, key_d_4dec))

        plaintext_output = pri_const.decrypt(ciphertext_input)

        self.rsa_data_out.delete(1.0, END)
        self.rsa_data_out.insert(1.0, hex(plaintext_output))

    #   HASH function - SHA, SHA224, SHA256, SHA384, SHA512, MD4, MD5, HMAC ??
    def execution_HASH(self):
        hash_algo_selector = operation_SLC_HASH.get()
        hash_algo_selector_hmac = operation_SLC_HASH_hmac.get()
        print "Here hmac:", hash_algo_selector_hmac
        if hash_algo_selector_hmac ==0:
            #self.hash_hmac_key_entry.configure(state='normal')
            #hmac_key = self.hash_hmac_key_entry.get()
            #print hmac_key
            #h_hmac_key = hmac_key.replace(' ', '').decode('hex')
            #print h_hmac_key
            if hash_algo_selector == 0:
                self.hash_output_text.delete(1.0, END)
                self.hash_output_text.insert(1.0, "Please select a hash alogrithm")
            elif hash_algo_selector == 1:
                hash_algo = SHA
            elif hash_algo_selector ==2:
                hash_algo = MD4
            elif hash_algo_selector ==3:
                hash_algo = MD5
            elif hash_algo_selector ==5:
                hash_algo = SHA224
            elif hash_algo_selector ==6:
                hash_algo = SHA256
            elif hash_algo_selector ==7:
                hash_algo = SHA384
            elif hash_algo_selector ==8:
                hash_algo = SHA512
            else:
                pass

            hash_input_data = self.hash_input_entry.get()
            print hash_input_data
            h_hash_data = hash_input_data.replace(' ', '').decode('hex')
            print h_hash_data

            if hash_algo_selector ==1 or hash_algo_selector == 2 or \
                        hash_algo_selector == 3 or hash_algo_selector == 5 or hash_algo_selector == 6 or \
                        hash_algo_selector == 7 or hash_algo_selector == 8 :
                obj = hash_algo.new()
                obj.update(h_hash_data)
                ret = obj.digest()
                h_output_hash = ret.encode('hex')
                print  "\n", hash_algo, ":", h_output_hash
                self.hash_output_text.delete(1.0, END)
                self.hash_output_text.insert(1.0, h_output_hash)
            else:
                pass

        elif hash_algo_selector_hmac == 1:
            #self.hash_hmac_key_entry.configure(state='normal')
            hmac_key = self.hash_hmac_key_entry.get()
            print "\nhmac_key", hmac_key
            h_hmac_key = hmac_key.replace(' ', '').decode('hex')
            print "\nh_hmac_key", h_hmac_key

            hmac_data = self.hash_input_entry.get()
            print "\nhmac_data", hmac_data
            h_hmac_data = hmac_data.replace(' ', '').decode('hex')
            print "\nh_hmac_data", h_hmac_data

            if hash_algo_selector == 0:
                self.hash_output_text.delete(1.0, END)
                self.hash_output_text.insert(1.0, "Please select a hash alogrithm")
            elif hash_algo_selector == 1:
                hash_algo = "SHA"
            elif hash_algo_selector ==2:
                hash_algo = "MD4"
            elif hash_algo_selector ==3:
                hash_algo = "MD5"
            elif hash_algo_selector ==5:
                hash_algo = SHA224
            elif hash_algo_selector ==6:
                hash_algo = "SHA256"
            elif hash_algo_selector ==7:
                hash_algo = SHA384
            elif hash_algo_selector ==8:
                hash_algo = SHA512
            else:
                pass

            print "\nalgo:", hash_algo
            obj_hmac = HMAC.new(h_hmac_key, hash_algo)
            obj_hmac.update(h_hmac_data)
            ret = obj_hmac.digest()
            #h_hmac_output = obj_hmac.digest('hex')
            #print  "\n", hash_algo, ":", h_output_hash
            print "\nret:", ret
            print "\nret.encode:", ret.encode('hex')
            self.hash_output_text.delete(1.0, END)
            self.hash_output_text.insert(1.0, ret.encode('hex'))

    #   Crypto function - XOR
    def execution_XOR(self):
        data_A = self.xor_inputA_value.get()
        data_B = self.xor_inputB_value.get()
        '''
        Description: Performs an exclusive or (XOR) operation
        Arguments:
        str1: A hex encoded string containing data to xor
        str2: A hex encoded string containing more data to xor
        Returns:
        A strong containing the xor'ed value as hex string
        '''
        if len(data_A) != len(data_A):
            print 'String lengths must be equal'

        hstr1 = data_A.decode('hex')
        hstr2 = data_B.decode('hex')
        out_str = ''
        for offset in range(0, len(hstr1)):
            valA = int(hstr1[offset].encode('hex'), 16)
            valB = int(hstr2[offset].encode('hex'), 16)
            out_str += chr(valA ^ valB).encode('hex')
        self.xor_result_value.delete(1.0, END)
        self.xor_result_value.insert(1.0, out_str)
        # return out_str

    #   Crypto function - HMAC
    #   Crypto function - RND
    #   RNG function - gerate a 8 bytes random number
    def rng_gen_8B(self):
        rndfile = Random.new()
        rnd = rndfile.read(8)
        h_rnd = rnd.encode('hex')
        self.rng_8B_textbox.delete(1.0, END)
        self.rng_8B_textbox.insert(1.0, h_rnd)
        print h_rnd

    def rng_gen_32B(self):
        rndfile = Random.new()
        rnd = rndfile.read(32)
        h_rnd = rnd.encode('hex')
        self.rng_32B_textbox.delete(1.0, END)
        self.rng_32B_textbox.insert(1.0, h_rnd)
        print h_rnd

    def rng_gen_88B(self):
        rndfile = Random.new()
        rnd = rndfile.read(88)
        h_rnd = rnd.encode('hex')
        self.rng_88B_textbox.delete(1.0, END)
        self.rng_88B_textbox.insert(1.0, h_rnd)
        print h_rnd
    '''
    def close_CryptoBox(self):
        global root
        root.destroy()
    '''

    def p120_start(self):
        # 1. get the current time!
        log_time_temp = time.strftime("%Y/%m/%d  %H:%M:%S")
        realtime.configure(text=log_time_temp)
        # 2. write it into the text box
        self.start_tm.delete(1.0, END)
        self.last_tm.delete(1.0, END)
        self.start_tm.insert(1.0, log_time_temp)
        self.last_tm.insert(1.0, "***Entry started at: " + log_time_temp + "\n")
        global p120_butt_clicked
        p120_butt_clicked = 0

    def p120_go(self):
        global p120_butt_clicked
        p120_butt_clicked += 1
        # 1. get the current time to log_time_temp:
        log_time_temp = time.strftime("%Y/%m/%d  %H:%M:%S")
        realtime.configure(text=log_time_temp)
        print "current time:", log_time_temp
        # 2. write time to text box
        if 0<p120_butt_clicked<10:
            filled_text = "#00" + str(p120_butt_clicked) + " PIN entered at: " + str(log_time_temp)
        elif 10<=p120_butt_clicked<100:
            filled_text = "#0" + str(p120_butt_clicked) + " PIN entered at: " + str(log_time_temp)
        else:
            filled_text = "#" + str(p120_butt_clicked) + " PIN entered at: " + str(log_time_temp)
        print "filled_text", filled_text
        self.last_tm.insert(0.0, filled_text + "\n")

    def p120_end(self):
        # 1. get the current time to log_time_temp:
        log_time_temp = time.strftime("%Y/%m/%d  %H:%M:%S")
        realtime.configure(text=log_time_temp)
        print "end time:", log_time_temp
        # 2. write time to text box
        self.last_tm.insert(0.0, "**The last entry at: " + log_time_temp + "\n")
        self.last_tm.insert(0.0, "--------- Online PIN entry test ---------\n--------- Elapsed timetable log ---------\n")
        # 3. write whole log to the log file
        log_120pin = self.last_tm.get("1.0", END)
        with open("Online PIN_120_per_hour_test.txt", "w") as log_write:
            log_write.write(log_120pin)
        global p120_butt_clicked
        p120_butt_clicked = 0

    def contact_developer(self):
        tkMessageBox.showinfo("Developer info", "nigel.zhai@ul.com\n\nThank you for your feedback!")
        #webbrowser.open_new(r"fill-a-web-address-start-with-http://")

    def input_file():
        global input_filename
        input_filename = askopenfilename(defaultextension='.txt')
        if input_filename == '':
            input_filename = None
        else:
            root.title('Key FileName:' + os.path.basename(input_filename))
            textPad.delete(1.0, END)
            f = open(input_filename, 'r')
            textPad.insert(1.0, f.read())
            f.close()




    #=========================================================================================================
    #   Create Frame/Label/Text/...etc
    def __init__(self, *args, **kwargs):

        #   1.1 TDES - Encryption or Decryption Selection Frame
        self.algo_bar_TDES = tk.LabelFrame(frame_1_TDES, text="DES/TDES", font=("Helvetica", 12, "bold"),
                                           padx=5, pady=5, bd=4)
        self.algo_bar_TDES.grid(row=0, column=1, rowspan=4, sticky=W)
        self.algo_label_DES = tk.Radiobutton(self.algo_bar_TDES, text="DES ", indicatoron=0, value=1, width=10,
                                             variable=algo_SLC_TDES)
        self.algo_label_DES.grid(row=1, column=1, padx=5, pady=5)
        self.algo_label_TDES = tk.Radiobutton(self.algo_bar_TDES, text="TDES", indicatoron=0, value=2, width=10,
                                              variable=algo_SLC_TDES)
        self.algo_label_TDES.grid(row=2, column=1, padx=5, pady=5)
        self.operation_bar_TDES = tk.LabelFrame(frame_1_TDES, text="Enc/Dec", font=("Helvetica", 12, "bold"),
                                                padx=5, pady=5, bd=4)
        self.operation_bar_TDES.grid(row=0, column=2, rowspan=4, sticky=N)
        self.Enc_label_TDES = tk.Radiobutton(self.operation_bar_TDES, text="Enc ", indicatoron=0, value=1, width=10,
                                             variable=operation_SLC_TDES)
        self.Enc_label_TDES.grid(row=1, column=2, padx=5, pady=5)
        self.Dec_label_TDES = tk.Radiobutton(self.operation_bar_TDES, text="Dec ", indicatoron=0, value=2, width=10,
                                             variable=operation_SLC_TDES)
        self.Dec_label_TDES.grid(row=2, column=2, padx=5, pady=5)
        #   1.2 Modes Selection Frame
        self.Mode_bar_TDES = tk.LabelFrame(frame_1_TDES, text="Modes", font=("Helvetica", 12, "bold"),
                                           padx=5, pady=5, bd=4)
        self.Mode_bar_TDES.grid(row=0, column=3, rowspan=4, sticky=E)
        self.mode_ECB_TDES = tk.Radiobutton(self.Mode_bar_TDES, text="ECB ", indicatoron=0, value=1, width=10,
                                            variable=MODE_SLC_TDES)
        self.mode_ECB_TDES.grid(row=1, column=3, padx=5, pady=5)
        self.mode_CBC_TDES = tk.Radiobutton(self.Mode_bar_TDES, text="CBC ", indicatoron=0, value=2, width=10,
                                            variable=MODE_SLC_TDES)
        self.mode_CBC_TDES.grid(row=2, column=3, padx=5, pady=5)
        self.mode_CFB_TDES = tk.Radiobutton(self.Mode_bar_TDES, text="CFB ", indicatoron=0, value=3, width=10,
                                            variable=MODE_SLC_TDES)
        self.mode_CFB_TDES.grid(row=1, column=4, padx=5, pady=5)
        self.mode_OFB_TDES = tk.Radiobutton(self.Mode_bar_TDES, text="OFB ", indicatoron=0, value=4, width=10,
                                            variable=MODE_SLC_TDES)
        self.mode_OFB_TDES.grid(row=2, column=4, padx=5, pady=5)
        #   1.3 Key Entry Textbox
        self.key_label_TDES = tk.Label(frame_1_TDES, text="Key value")
        self.key_label_TDES.grid(row=5, column=0, sticky=E)
        self.key_textbox_TDES = tk.Entry(frame_1_TDES, font = "Courier 9", width=64)
        self.key_textbox_TDES.grid(row=5, column=1, columnspan=3, padx=5, pady=5, sticky=W)
        #   RULER !
        self.ruler = tk.Label(frame_1_TDES, text="|----8 Bytes---||----8 Bytes---||----8 Bytes---|", font="Courier 9",width=48)
        self.ruler.grid(row=6, column=1, columnspan=3, padx=6, sticky=W)
        '''
        #   1.3.1 key length
        self.key_ck_TDES = tk.Label(frame_1_TDES, text="len:")
        self.key_ck_TDES.grid(row=5, column=4)
        self.key_ck_value_TDES = tk.Text(frame_1_TDES, font = "Courier 9", height=1, width=4)
        self.key_ck_value_TDES.grid(row=5, column=5)
        '''
        #   1.4 IV Entry Textbox
        self.iv_label_TDES = tk.Label(frame_1_TDES, text="IV")
        self.iv_label_TDES.grid(row=7, column=0, sticky=E)
        self.iv_textbox_TDES = tk.Entry(frame_1_TDES, font = "Courier 9", width=64)
        self.iv_textbox_TDES.grid(row=7, column=1, columnspan=3, padx=5, pady=5, sticky=W)

        #   1.5 Input  Data Entry Textbox
        self.input_label_TDES = tk.Label(frame_1_TDES, text="Input")
        self.input_label_TDES.grid(row=8, column=0, sticky=E)
        self.input_textbox_TDES = tk.Entry(frame_1_TDES, font = "Courier 9", width=64)
        self.input_textbox_TDES.grid(row=8, column=1, columnspan=3, padx=5, pady=5, sticky=W)

        #   Scroll of the input text box
        # self.input_scroll = Scrollbar(self.input_textbox)
        # self.input_scroll.config(yscrollcommand = self.input_scroll.set)
        # self.input_scroll.config(command = self.input_scroll.yview)
        # self.input_scroll.pack(side = RIGHT, fill = Y)
        #   RULER !
        self.ruler = tk.Label(frame_1_TDES, text="|----8 Bytes---||----8 Bytes---||----8 Bytes---|", font="Courier 9",width=48)
        self.ruler.grid(row=9, column=1, columnspan=3, padx=6, sticky=W)
        #   1.6 Output Data Entry Textbox
        self.output_label_TDES = tk.Label(frame_1_TDES, text="Output")
        self.output_label_TDES.grid(row=10, column=0, sticky=E)
        self.output_textbox_TDES = tk.Text(frame_1_TDES, font = "Courier 9", height=8, width=64)
        self.output_textbox_TDES.grid(row=10, column=1, columnspan=3, padx=5, pady=5, sticky=W)
        #self.scroll = Scrollbar(root, command=self.output_label_TDES.yview)
        #self.output_textbox_TDES.configure(yscrollcommand=scroll.set)

        #   Scroll of the output text box
        # self.input_scroll = Scrollbar(self.input_textbox)
        # self.input_scroll.config(yscrollcommand = self.input_scroll.set)
        # self.input_scroll.config(command = self.input_scroll.yview)
        # self.input_scroll.pack(side = RIGHT, fill = Y)

        #   1.7 Go Button and Exit Button
        self.go_button_TDES = tk.Button(frame_1_TDES, text="Use output\nas the key", width=10,
                                        command=self.copy_key_value_TDES)
        self.go_button_TDES.grid(row=11, column=1, padx=5, pady=5, sticky=W)
        self.go_button_TDES = tk.Button(frame_1_TDES, text="Go!", width=10, command=self.execution_TDES)
        self.go_button_TDES.grid(row=11, column=3, padx=5, pady=5, sticky=E)

        #   2.1 AES - Encryption or Decryption Selection Frame
        self.EncOrDec_bar_AES = tk.LabelFrame(frame_2_AES, text="Enc/Dec", font=("Helvetica", 12, "bold"), padx=5, pady=5, bd=4)
        self.EncOrDec_bar_AES.grid(row=1, column=2, rowspan=4, sticky=N)
        self.Enc_label_AES = tk.Radiobutton(self.EncOrDec_bar_AES, text="Enc ", indicatoron=0, value=1, width=10,
                                            variable=operation_SLC_AES)
        self.Enc_label_AES.grid(row=2, column=2, padx=5, pady=5)
        self.Dec_label_AES = tk.Radiobutton(self.EncOrDec_bar_AES, text="Dec ", indicatoron=0, value=2, width=10,
                                            variable=operation_SLC_AES)
        self.Dec_label_AES.grid(row=3, column=2, padx=5, pady=5)
        #   2.2 Modes Selection Frame
        self.Mode_bar_AES = tk.LabelFrame(frame_2_AES, text="Modes", font=("Helvetica", 12, "bold"), padx=5, pady=5, bd=4)
        self.Mode_bar_AES.grid(row=1, column=3, rowspan=4, sticky=E)
        self.mode_ECB_AES = tk.Radiobutton(self.Mode_bar_AES, text="ECB ", indicatoron=0, value=1, width=10,
                                           variable=MODE_SLC_AES)
        self.mode_ECB_AES.grid(row=2, column=3, padx=5, pady=5)
        self.mode_CBC_AES = tk.Radiobutton(self.Mode_bar_AES, text="CBC ", indicatoron=0, value=2, width=10,
                                           variable=MODE_SLC_AES)
        self.mode_CBC_AES.grid(row=3, column=3, padx=5, pady=5)
        self.mode_CFB_AES = tk.Radiobutton(self.Mode_bar_AES, text="CFB ", indicatoron=0, value=3, width=10,
                                           variable=MODE_SLC_AES)
        self.mode_CFB_AES.grid(row = 2, column = 4, padx=5, pady=5)
        self.mode_OFB_AES = tk.Radiobutton(self.Mode_bar_AES, text="OFB ", indicatoron=0, value=4, width=10,
                                           variable=MODE_SLC_AES)
        self.mode_OFB_AES.grid(row=3, column=4, padx=5, pady=5)
        #   2.3 Key Entry Textbox
        self.key_label_AES = tk.Label(frame_2_AES, text="Key value")
        self.key_label_AES.grid(row=5, column=0, sticky=E)
        self.key_textbox_AES = tk.Entry(frame_2_AES, font = "Courier 9", width=64)
        self.key_textbox_AES.grid(row=5, column=1, columnspan=3, padx=5, pady=5, sticky=W)
        #   RULER !
        self.ruler = tk.Label(frame_2_AES, text="|----8 Bytes---||----8 Bytes---||----8 Bytes---||----8 Bytes---|", font="Courier 9", width=64)
        self.ruler.grid(row=6, column=1, columnspan=3, padx=6, sticky=W)
        #   2.4 IV Entry Textbox
        self.iv_label_AES = tk.Label(frame_2_AES, text="IV")
        self.iv_label_AES.grid(row=7, column=0, sticky=E)
        self.iv_textbox_AES = tk.Entry(frame_2_AES, font = "Courier 9", width=64)
        self.iv_textbox_AES.grid(row=7, column=1, columnspan=3, padx=5, pady=5, sticky=W)
        #   2.5 Input  Data Entry Textbox
        self.input_label_AES = tk.Label(frame_2_AES, text="Input")
        self.input_label_AES.grid(row=8, column=0, sticky=E)
        self.input_textbox_AES = tk.Entry(frame_2_AES, font = "Courier 9", width=64)
        self.input_textbox_AES.grid(row=8, column=1, columnspan=3, padx=5, pady=5, sticky=W)
        #   RULER !
        self.ruler = tk.Label(frame_2_AES, text="|----8 Bytes---||----8 Bytes---||----8 Bytes---||----8 Bytes---|", font="Courier 9", width=64)
        self.ruler.grid(row=9, column=1, columnspan=3, padx=6, sticky=W)
        #   Scroll of the input text box
        # self.input_scroll = Scrollbar(self.input_textbox)
        # self.input_scroll.config(yscrollcommand = self.input_scroll.set)
        # self.input_scroll.config(command = self.input_scroll.yview)
        # self.input_scroll.pack(side = RIGHT, fill = Y)
        #   2.6 Output Data Entry Textbox
        self.output_label_AES = tk.Label(frame_2_AES, text="Output")
        self.output_label_AES.grid(row=10, column=0, sticky=E)
        self.output_textbox_AES = tk.Text(frame_2_AES, font = "Courier 9", height=8, width=64)
        self.output_textbox_AES.grid(row=10, column=1, columnspan=3, padx=5, pady=5, sticky=W)
        #   Scroll of the output text box
        # self.input_scroll = Scrollbar(self.input_textbox)
        # self.input_scroll.config(yscrollcommand = self.input_scroll.set)
        # self.input_scroll.config(command = self.input_scroll.yview)
        # self.input_scroll.pack(side = RIGHT, fill = Y)
        #   2.7 Go Button and Exit Button
        self.go_button_AES = tk.Button(frame_2_AES, text="Use output\nas the key", width=10,
                                       command=self.copy_key_value_AES)
        self.go_button_AES.grid(row=11, column=1, padx=5, pady=5, sticky=W)
        self.go_button_AES = tk.Button(frame_2_AES, text="Go!", width=10, command=self.execution_AES)
        self.go_button_AES.grid(row=11, column=3, padx=5, pady=5, sticky=E)

        #   3_1   RSA Gen.

        #   3_1.1 RSA Key Gen
        self.Key_Gen = tk.LabelFrame(frame_3_1_RSA, text=" RSA Key Pair Generation (PEM) ", font=("Helvetica", 12, "bold"), padx=5, pady=5)
        self.Key_Gen.grid(row=1, column=2, rowspan=4, sticky=W)
        self.RSAgen_pri_key_lb = tk.Label(self.Key_Gen, text="Private\n(.pem)\n(d)")
        self.RSAgen_pri_key_lb.grid(row=2, column=1, padx=5, pady=5, sticky=W+N)
        self.RSAgen_pri_key_tx = tk.Text(self.Key_Gen, font = "Courier 9", height=4, width=64)
        self.RSAgen_pri_key_tx.grid(row=2, column=2, padx=5, pady=5, sticky=W)
        self.RSAgen_pub_key_lb = tk.Label(self.Key_Gen, text="Public \n(.pem)\n(n)")
        self.RSAgen_pub_key_lb.grid(row=3, column=1, padx=5, pady=5, sticky=W+N)
        self.RSAgen_pub_key_tx = tk.Text(self.Key_Gen, font = "Courier 9", height=4, width=64)
        self.RSAgen_pub_key_tx.grid(row=3, column=2, padx=5, pady=5, sticky=W)

        self.RSAgen_output_exp_lb = tk.Label(self.Key_Gen, text="exp.\n(hex)")
        self.RSAgen_output_exp_lb.grid(row=4, column=1, padx=5, pady=5, sticky=W+N)
        self.RSAgen_output_exp_tx = tk.Text(self.Key_Gen, font = "Courier 9", height=1, width=64)
        self.RSAgen_output_exp_tx.grid(row=4, column=2, padx=5, pady=5, sticky=W)
        self.RSAgen_output_pri_lb = tk.Label(self.Key_Gen, text="Private\n(hex)\n(d)")
        self.RSAgen_output_pri_lb.grid(row=5, column=1, padx=5, pady=5, sticky=W+N)
        self.RSAgen_output_pri_tx = tk.Text(self.Key_Gen, font = "Courier 9", height=4, width=64)
        self.RSAgen_output_pri_tx.grid(row=5, column=2, padx=5, pady=5, sticky=W)
        self.RSAgen_output_pub_lb = tk.Label(self.Key_Gen, text="Public \n(hex)\n(n)")
        self.RSAgen_output_pub_lb.grid(row=6, column=1, padx=5, pady=5, sticky=W+N)
        self.RSAgen_output_pub_tx = tk.Text(self.Key_Gen, font = "Courier 9", height=4, width=64)
        self.RSAgen_output_pub_tx.grid(row=6, column=2, padx=5, pady=5, sticky=W)

        self.RSA_key_pair_gen_bot = tk.Button(self.Key_Gen, text="Gen RSA key pair", width=17, command=self.RSA_key_pair_gen_func)
        self.RSA_key_pair_gen_bot.grid(row=7, column=2, padx=5, pady=5, sticky=N+E)

        self.RSA_k_len_lb = tk.Label(self.Key_Gen, text="key len")
        self.RSA_k_len_lb.grid(row=7, column=1, padx=5, pady=5, sticky=N+W)
        self.RSA_k_len_En = tk.Entry(self.Key_Gen, width=5)
        self.RSA_k_len_En.grid(row=7, column=2, padx=5, pady=5, sticky=N+W)

        #   3_1.4 output file - enciphered/plaintext binary data

        #   3_2     RSA key Import # with Dave's great help
        self.rsa_key_import = tk.LabelFrame(frame_3_2_RSA, text = " Import your RSA key pair ",
                                            font=("Helvetica", 12, "bold"), padx=5, pady=5)
        self.rsa_key_import.grid(row=1, column=2, rowspan=4, sticky=W)


        self.rsa_import_meth_1 = tk.Radiobutton(self.rsa_key_import, text="Import keys from .imp files",
                                                indicator=0, value=1, width=22, variable=KEY_IMPORT_METHOD)
        self.rsa_import_meth_1.grid(row=2, column=2, padx=5, pady=1, sticky = W)

        self.rsa_import_meth_2 = tk.Radiobutton(self.rsa_key_import, text="Import keys to the 3 boxes ",
                                                indicator=0, value=2, width=22, variable=KEY_IMPORT_METHOD)
        self.rsa_import_meth_2.grid(row=3, column=2, padx=5, pady=1, sticky = W)

        self.rsa_key_exp_import_lb = tk.Label(self.rsa_key_import, text="exp.   ")
        self.rsa_key_exp_import_lb.grid(row=4, column=1, padx=5, pady=5, sticky =W+N)
        self.rsa_key_exp_import_tx = tk.Text(self.rsa_key_import, font = "Courier 9", height=1, width=64)
        self.rsa_key_exp_import_tx.grid(row=4, column=2, padx=5, pady=5, sticky=W)
        self.rsa_key_pri_import_lb = tk.Label(self.rsa_key_import, text="Private\n(d)")
        self.rsa_key_pri_import_lb.grid(row=5, column=1, padx=5, pady=5, sticky =W+N)
        self.rsa_key_pri_import_tx = tk.Text(self.rsa_key_import, font = "Courier 9", height=6, width=64)
        self.rsa_key_pri_import_tx.grid(row=5, column=2, padx=5, pady=5, sticky=W)
        self.rsa_key_pub_import_lb = tk.Label(self.rsa_key_import, text="Public \n(n)")
        self.rsa_key_pub_import_lb.grid(row=6, column=1, padx=5, pady=5, sticky =W+N)
        self.rsa_key_pub_import_tx = tk.Text(self.rsa_key_import, font = "Courier 9", height=6, width=64)
        self.rsa_key_pub_import_tx.grid(row=6, column=2, padx=5, pady=5, sticky=W)

        self.rsa_key_imported_done = tk.Text(self.rsa_key_import, font="Courier 9", height=2, width=18)
        self.rsa_key_imported_done.grid(row=7, column=2, padx=5, pady=5, sticky=N + W)

        self.rsa_key_pub_import_bot = tk.Button(self.rsa_key_import, text="Import your RSA key pair",
                                                width=20, command=self.rsa_key_import_func)
        self.rsa_key_pub_import_bot.grid(row=7, column=2, padx=5, pady=5, sticky=N+E)


        #   3_3     RSA Crypto.
        #   3_3.1 Operation selection
        '''
        self.EncOrDec_bar_RSA = tk.LabelFrame(frame_3_3_RSA, text="Operation", padx=10, pady=10)
        self.EncOrDec_bar_RSA.grid(row=1, column=1, rowspan=4, sticky=W+N)
        self.Enc_label_RSA = tk.Radiobutton(self.EncOrDec_bar_RSA, text="Enc", indicatoron=0, value=1, width=10,
                                            variable=operation_SLC_RSA)
        self.Enc_label_RSA.grid(row=2, column=1, padx=3, pady=5)
        self.Dec_label_RSA = tk.Radiobutton(self.EncOrDec_bar_RSA, text="Dec", indicatoron=0, value=2, width=10,
                                            variable=operation_SLC_RSA)
        self.Dec_label_RSA.grid(row=3, column=1, padx=3, pady=5)
        '''

        #   3_3.2 input file - plaintext/enciphered binary data
        self.rsa_data_work = tk.LabelFrame(frame_3_3_RSA, text=" RSA Calculator ",
                                     font=("Helvetica", 12, "bold"), padx=5, pady=5)
        self.rsa_data_work.grid(row=1, column=2, rowspan=4, sticky=W)

        self.rsa_data_in_lb = tk.Label(self.rsa_data_work, text="Input")
        self.rsa_data_in_lb.grid(row=2, column=1, padx=5, pady=5, sticky=W+N)
        self.rsa_data_in = tk.Text(self.rsa_data_work, font = "Courier 9", height=8, width=64)
        self.rsa_data_in.grid(row=2, column=2, padx=5, pady=5, sticky=W)

        self.rsa_data_out_lb = tk.Label(self.rsa_data_work, text="Output")
        self.rsa_data_out_lb.grid(row=3, column=1, padx=5, pady=5, sticky=W+N)
        self.rsa_data_out = tk.Text(self.rsa_data_work, font = "Courier 9", height=8, width=64)
        self.rsa_data_out.grid(row=3, column=2, padx=5, pady=5, sticky=W)


        #   3_3.1 RSA Enc/Dec
        self.key_pub_butt_RSA = tk.Button(self.rsa_data_work, text="Encrypt Input data", width=17, command=self.execution_RSA_enc)
        self.key_pub_butt_RSA.grid(row=4, column=2, padx=5, pady=5, sticky=N+E)
        self.key_pri_butt_RSA = tk.Button(self.rsa_data_work, text="Decrypt Input data", width=17, command=self.execution_RSA_dec)
        self.key_pri_butt_RSA.grid(row=5, column=2, padx=5, pady=5, sticky=N+E)

        self.rsa_note = tk.Label(self.rsa_data_work,
                                      text="\nNote:\nPrivate key, Public key, and exp. must be\npre-imported under 'RSA import.' tag",
                                      font=("Helvetica", 8))
        self.rsa_note.config(justify=LEFT)
        self.rsa_note.grid(row=4, column=2, rowspan=3, padx=5, sticky=W+N)

        '''
        self.key_label_RSA = tk.Label(frame_3_1_RSA, text="Key value: ")
        self.key_label_RSA.grid(row = 5, column = 0)
        self.key_textbox_AES= tk.Entry(frame_2_AES, width = 41)
        self.key_textbox_AES.grid(row = 5, column = 1, columnspan = 2, padx=5, pady=5, sticky=W)
        '''

        #   4   Hash - (SHA, SHA224, SHA256, SHA384, SHA512, MD4, MD5, HMAC??)
        self.HASH_frame = tk.LabelFrame(frame_4_HASH, text=" Algorithms ", font=("Helvetica", 12, "bold"), padx=5, pady=5, bd=4)
        self.HASH_frame.grid(row=1, column=1, rowspan=4, columnspan=4, sticky=W)
        #   4.1 algorithm selection buttons
        self.hash_SHA = tk.Radiobutton(self.HASH_frame, text="SHA", indicator=0, value=1, width=11,
                                       variable=operation_SLC_HASH)
        self.hash_SHA.grid(row=2, column=1, padx=5, pady=5)
        self.hash_MD4 = tk.Radiobutton(self.HASH_frame, text="MD4", indicator=0, value=2, width=11,
                                       variable=operation_SLC_HASH)
        self.hash_MD4.grid(row=2, column=2, padx=5, pady=5)
        self.hash_MD5 = tk.Radiobutton(self.HASH_frame, text="MD5", indicator=0, value=3, width=11,
                                       variable=operation_SLC_HASH)
        self.hash_MD5.grid(row=2, column=3, padx=5, pady=5)
        self.hash_HMAC = tk.Checkbutton(self.HASH_frame, text="HMAC", width=10, variable=operation_SLC_HASH_hmac)
        self.hash_HMAC.grid(row=2, column=4, padx=5, pady=5)
        self.hash_SHA224 = tk.Radiobutton(self.HASH_frame, text="SHA224", indicator=0, value=5, width=11,
                                          variable=operation_SLC_HASH)
        self.hash_SHA224.grid(row=3, column=1, padx=5, pady=5)
        self.hash_SHA256 = tk.Radiobutton(self.HASH_frame, text="SHA256", indicator=0, value=6, width=11,
                                          variable=operation_SLC_HASH)
        self.hash_SHA256.grid(row=3, column=2, padx=5, pady=5)
        self.hash_SHA384 = tk.Radiobutton(self.HASH_frame, text="SHA384", indicator=0, value=7, width=11,
                                          variable=operation_SLC_HASH)
        self.hash_SHA384.grid(row=3, column=3, padx=5, pady=5)
        self.hash_SHA512 = tk.Radiobutton(self.HASH_frame, text="SHA512", indicator=0, value=8, width=11,
                                          variable=operation_SLC_HASH)
        self.hash_SHA512.grid(row=3, column=4, padx=5, pady=5)
        #   4.2 HMAC key input
        self.hash_hmac_key_label = tk.Label(frame_4_HASH, text="HMAC key")
        self.hash_hmac_key_label.grid(row=6, column=0, padx=5, pady=5, sticky=E)
        self.hash_hmac_key_entry = tk.Entry(frame_4_HASH, font = "Courier 9", width=64)
        self.hash_hmac_key_entry.grid(row=6, column=1, columnspan=2, padx=5, pady=5, sticky=W)

        #   RULER !
        self.ruler = tk.Label(frame_4_HASH, text="|----8 Bytes---||----8 Bytes---||----8 Bytes---||----8 Bytes---|", font="Courier 9", width=64)
        self.ruler.grid(row=7, column=1, columnspan=3, padx=6, sticky=W)

        #   4.3 Data Input
        self.hash_input_label = tk.Label(frame_4_HASH, text="Input")
        self.hash_input_label.grid(row=8, column=0, padx=5, pady=5, sticky=E)
        self.hash_input_entry = tk.Entry(frame_4_HASH, font = "Courier 9", width=64)
        self.hash_input_entry.grid(row=8, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   4.4 Data Output
        self.hash_output_label = tk.Label(frame_4_HASH, text="Output")
        self.hash_output_label.grid(row=9, column=0, sticky=E)
        self.hash_output_text = tk.Text(frame_4_HASH, font = "Courier 9", height=8, width=64)
        self.hash_output_text.grid(row=9, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   4.4 Go button
        self.go_button_hash = tk.Button(frame_4_HASH, text="Go!", width=10, command=self.execution_HASH)
        self.go_button_hash.grid(row=10, column=2, padx=5, pady=5, sticky=E)

        #   5   XOR
        self.XOR_frame = tk.LabelFrame(frame_5_XOR, text=" XOR ", font=("Helvetica", 12, "bold"), padx=5, pady=5)
        self.XOR_frame.grid(row=1, column=1, rowspan=4, columnspan=4, sticky=NS)
        #   5.1 data A & B & result labels
        self.xor_inputA_label = tk.Label(self.XOR_frame, text="Input A")
        self.xor_inputA_label.grid(row=2, column=1, padx=5, sticky=W)
        self.xor_inputB_label = tk.Label(self.XOR_frame, text="Input B")
        self.xor_inputB_label.grid(row=4, column=1, padx=5, sticky=W)
        self.xor_result_label = tk.Label(self.XOR_frame, text="Output")
        self.xor_result_label.grid(row=5, column=1, padx=5, sticky=W)

        #   RULER !
        self.ruler = tk.Label(self.XOR_frame, text="|----8 Bytes---||----8 Bytes---||----8 Bytes---||----8 Bytes---|", font="Courier 9", width=64)
        self.ruler.grid(row=3, column=2, padx=6, sticky=W)

        #   5.2 data A & B Entry widgets
        self.xor_inputA_value = tk.Entry(self.XOR_frame, font = "Courier 9", width=64)
        self.xor_inputA_value.grid(row=2, column=2, columnspan=2, padx=5, pady=5, sticky=W)
        self.xor_inputB_value = tk.Entry(self.XOR_frame, font = "Courier 9", width=64)
        self.xor_inputB_value.grid(row=4, column=2, columnspan=2, padx=5, pady=5, sticky=W)
        self.xor_result_value = tk.Text(self.XOR_frame, font = "Courier 9", height=8, width=64)
        self.xor_result_value.grid(row=5, column=2, columnspan=2, padx=5, pady=5, sticky=W)
        #   5.3 button GO!
        self.go_button_XOR = tk.Button(frame_5_XOR, text="Go!", width=10, command=self.execution_XOR)
        self.go_button_XOR.grid(row=9, column=4, padx=5, pady=5, sticky=E)

        #   6   Random number generator button
        self.rng_bar_bar = tk.LabelFrame(frame_6_RNG, text=" Random number ", font=("Helvetica", 12, "bold"), padx=5, pady=5)
        self.rng_bar_bar.grid(row=1, column=1, rowspan=4)
        self.rng_butt_8B = tk.Button(self.rng_bar_bar, text="Generate 8byte", command=self.rng_gen_8B)
        self.rng_butt_8B.grid(row=2, column=1, padx=5, pady=5, sticky=W)
        self.rng_8B_textbox = tk.Text(self.rng_bar_bar, font = "Courier 9", height=1, width=64)
        self.rng_8B_textbox.grid(row=5, column=1, padx=5, pady=5, sticky=N+W)

        self.rng_butt_32B = tk.Button(self.rng_bar_bar, text="Generate 32byte", command=self.rng_gen_32B)
        self.rng_butt_32B.grid(row=6, column=1, padx=5, pady=5, sticky=W)
        self.rng_32B_textbox = tk.Text(self.rng_bar_bar, font = "Courier 9", height=4, width=64)
        self.rng_32B_textbox.grid(row=7, column=1, padx=5, pady=5, sticky=N+W)

        self.rng_butt_88B = tk.Button(self.rng_bar_bar, text="Generate 88byte", command=self.rng_gen_88B)
        self.rng_butt_88B.grid(row=8, column=1, padx=5, pady=5, sticky=W)
        self.rng_88B_textbox = tk.Text(self.rng_bar_bar, font = "Courier 9", height=4, width=64)
        self.rng_88B_textbox.grid(row=9, column=1, padx=5, pady=5, sticky=N+W)


        #   7   120 PINs
        self.pin_120_bar = tk.LabelFrame(frame_7_120, text=" Elapsed time of 120 online PIN entry test ", font=("Helvetica", 12, "bold"), padx=5, pady=5)
        self.pin_120_bar.grid(row=1, column=1, columnspan=4)

        self.start_lb = tk.Label(self.pin_120_bar, text="PIN entry started at:")
        self.start_lb.grid(row=1, column=1, sticky=E, padx=5, pady=5)
        self.start_tm = tk.Text(self.pin_120_bar, font=("Courier", 9), height=1, width=42)
        self.start_tm.grid(row=1, column=2, sticky=W, padx=5, pady=5)

        self.last_lb = tk.Label(self.pin_120_bar, text="Last PIN entered at:")
        self.last_lb.grid(row=2, column=1, sticky=E, padx=5, pady=5)
        self.last_tm = tk.Text(self.pin_120_bar, font=("Courier", 9), height=15, width=42)
        self.last_tm.grid(row=2, column=2, sticky=W, padx=5, pady=5)

        self.pin_entry_start_bt = tk.Button(self.pin_120_bar, text="Start!", width=10, command=self.p120_start)
        self.pin_entry_start_bt.grid(row=3, column=2, columnspan=2, padx=5, pady=5, sticky=W)

        self.pin_entry_going_bt = tk.Button(self.pin_120_bar, text="Go!", width=10, command=self.p120_go)
        self.pin_entry_going_bt.grid(row=3, column=2, columnspan=2, padx=5, pady=5, sticky=E)

        self.pin_entry_end_bt = tk.Button(self.pin_120_bar, text="Terminate!", width=10, command=self.p120_end)
        self.pin_entry_end_bt.grid(row=4, column=2, columnspan=2, padx=5, pady=5, sticky=E)

        #   8   About CryptoBox
        self.abt_bar = tk.LabelFrame(frame_8_ABT, text=" --- CryptoBox --- ", font=("Helvetica", 12, "bold"))
        self.abt_bar.grid(row=1, column=1)

        self.CB_about_label = tk.Label(self.abt_bar, justify=LEFT, anchor=N, text=abt_msg)
        self.CB_about_label.grid(row=2, column=2, columnspan=2, sticky='new', padx=5, pady=5)

        self.developer = tk.Button(self.abt_bar, text="Contact me!", width=15, command=self.contact_developer)
        self.developer.grid(row=3, column=2, columnspan=2, padx=5, pady=5)

def quit():
    global root
    root.quit()

update_timeText()
app = CryptoBox()
root.mainloop()
