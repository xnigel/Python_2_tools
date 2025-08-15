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

#                                                                                #
#   Version Number Defination:                                                   #
#   v00.09.09 XXXX                                                               #
#    -- -- --                                                                    #
#     |  |  |                                                                    #
#     |  |  +------     GUI Updates                                              #
#     |  +---------     Crypto Function Updates                                  #
#     +------------     Published Version (Major Change)                         #
#   2016.12.08.                                                                  #
# _______________________________________________________________________________#
#
#   DES operation works very well on v00.09.09.x
#   v00.09.09 has been added new buttons:
#   01. TDES algorithm has been added !!! Works well !!!
#   02. AES  algorithm has been added !!! Works well !!!
#   03. Random number generator has been added !!! Works well !!!
#   04. Added a Exit button to quit program !!! Works well !!!
#   05. Added algo_tab (x6). SHA and RSA are not completed xxx
#   06. Adding the menu bar.............(No idea so far how to do so :( )
#   07. DES/TDES function is corrected !!!
#   08. Adding length counter after key and iv fileds..............(No idea :( )
#   09. Adding fileopen function for RSA key-file and data-file import
#   10. Adding Hash function and GUI...........all done except HMAC operation
#   11. Scrollbar has not been added due to lack of knowledge............
# ________________________________________________________________________________#
#   GUI import
# from Tkinter import *
from Tkinter import *
# fomr Tkinter import Tk # ?? does it have Tk? or ttk?
from tkMessageBox import *
from tkFileDialog import *
import os
import tkFont
import tkMessageBox
import socket
import string
import select
import Tkinter as tk
import ttk
import binascii
#   Crypto import
from Crypto.Cipher import DES, DES3, AES
from Crypto.Hash import SHA, SHA224, SHA256, SHA384, SHA512, MD4, MD5, HMAC
from Crypto.PublicKey import RSA
# from crcmod import predefined
from Crypto import Random

key_pub_filename = ''
key_pri_filename = ''
input_filename = ''
'''
def author(): showinfo('Author','UL-TS Australia\n' 'Nigel Z.\n')
def about():
    about_window = Toplevel(root)
    about_window.geometry("250x50+100+1000")
    about_label = Label(about_window, text='CryptoBox\n Version 00.01.02\n Copyright 2016  Nigel Z.  All rights reserved.')
    about_label.pack(fill=X)
'''
root = tk.Tk()
root.title('CryptoBox v00.09.09.x')
root.geometry("560x420+0+0")
algo_tab = ttk.Notebook(root)
frame_1_TDES = ttk.Frame(algo_tab)
frame_2_AES = ttk.Frame(algo_tab)
frame_3_1_RSA = ttk.Frame(algo_tab)
frame_3_2_RSA = ttk.Frame(algo_tab)
frame_4_HASH = ttk.Frame(algo_tab)
frame_5_XOR = ttk.Frame(algo_tab)
frame_6_RNG = ttk.Frame(algo_tab)
frame_7_ABT = ttk.Frame(algo_tab)
algo_tab.add(frame_1_TDES, text='TDES\n')
algo_tab.add(frame_2_AES, text='AES\n')
algo_tab.add(frame_3_1_RSA, text='RSA\nGen.')
algo_tab.add(frame_3_2_RSA, text='RSA\nCrypto.')
algo_tab.add(frame_4_HASH, text='HASH\n')
algo_tab.add(frame_5_XOR, text='XOR\n')
algo_tab.add(frame_6_RNG, text='RNG\n')
algo_tab.add(frame_7_ABT, text='About CryptoBox\n')
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


class MenuBar(Frame):
    def __init__(self):
        Frame.__int__(self)
        self.menubar = Menu(self)
        menu = Menu(self.menubar, tearoff=0)
        self.menubar.add_cascade(lable="About", menu=menu)
        menu.add_command(label="Copyright")


class CryptoBox(tk.Tk):
    #   GUI interface definition
    def __init__(self, *args, **kwargs):
        '''
        #   Algorithm Selection Frame
        self.Algorithm_bar = tk.LabelFrame(frame_1_DES, text="Algorithm", padx=10, pady=10)
        self.Algorithm_bar.grid(row=1, column=0, rowspan = 4)
        self.DES_label = tk.Radiobutton(self.Algorithm_bar, text="DES", indicatoron=0, value=1, width=10, variable=Algo_SLC)
        self.DES_label.grid(row=2, column=0, padx=5, pady=5)
        self.TDES_label = tk.Radiobutton(self.Algorithm_bar, text="TDES", indicatoron=0, value=2, width=10, variable=Algo_SLC)
        self.TDES_label.grid(row=3, column=0, padx=5, pady=5)
        self.AES_label = tk.Radiobutton(self.Algorithm_bar, text="AES", indicatoron=0, value=3, width=10, variable=Algo_SLC)
        self.AES_label.grid(row=4, column=0, padx=5, pady=5)
        '''
        #   1.1 TDES - Encryption or Decryption Selection Frame
        self.algo_bar_TDES = tk.LabelFrame(frame_1_TDES, text="DES/TDES", padx=10, pady=10)
        self.algo_bar_TDES.grid(row=0, column=0, rowspan=4, sticky=NS)
        self.algo_label_DES = tk.Radiobutton(self.algo_bar_TDES, text="DES", indicatoron=0, value=1, width=10,
                                             variable=algo_SLC_TDES)
        self.algo_label_DES.grid(row=1, column=0, padx=3, pady=5)
        self.algo_label_TDES = tk.Radiobutton(self.algo_bar_TDES, text="TDES", indicatoron=0, value=2, width=10,
                                              variable=algo_SLC_TDES)
        self.algo_label_TDES.grid(row=2, column=0, padx=3, pady=5)
        self.operation_bar_TDES = tk.LabelFrame(frame_1_TDES, text="Operation", padx=10, pady=10)
        self.operation_bar_TDES.grid(row=0, column=1, rowspan=4, sticky=NS)
        self.Enc_label_TDES = tk.Radiobutton(self.operation_bar_TDES, text="Enc", indicatoron=0, value=1, width=10,
                                             variable=operation_SLC_TDES)
        self.Enc_label_TDES.grid(row=1, column=1, padx=5, pady=5)
        self.Dec_label_TDES = tk.Radiobutton(self.operation_bar_TDES, text="Dec", indicatoron=0, value=2, width=10,
                                             variable=operation_SLC_TDES)
        self.Dec_label_TDES.grid(row=2, column=1, padx=5, pady=5)
        #   1.2 Modes Selection Frame
        self.Mode_bar_TDES = tk.LabelFrame(frame_1_TDES, text="Modes", padx=10, pady=10)
        self.Mode_bar_TDES.grid(row=0, column=2, rowspan=4, sticky=NS)
        self.mode_ECB_TDES = tk.Radiobutton(self.Mode_bar_TDES, text="ECB", indicatoron=0, value=1, width=10,
                                            variable=MODE_SLC_TDES)
        self.mode_ECB_TDES.grid(row=1, column=2, padx=5, pady=5)
        self.mode_CBC_TDES = tk.Radiobutton(self.Mode_bar_TDES, text="CBC", indicatoron=0, value=2, width=10,
                                            variable=MODE_SLC_TDES)
        self.mode_CBC_TDES.grid(row=2, column=2, padx=5, pady=5)
        # self.mode_CFB_TDES = tk.Radiobutton(self.Mode_bar_TDES, text="CFB", indicatoron=0, value=3, width=10, variable=MODE_SLC_TDES)
        # self.mode_CFB_TDES.grid(row = 2, column = 2, padx=5, pady=5)
        self.mode_OFB_TDES = tk.Radiobutton(self.Mode_bar_TDES, text="OFB", indicatoron=0, value=4, width=10,
                                            variable=MODE_SLC_TDES)
        self.mode_OFB_TDES.grid(row=2, column=3, padx=5, pady=5)
        #   1.3 Key Entry Textbox
        self.key_label_TDES = tk.Label(frame_1_TDES, text="Key value: ")
        self.key_label_TDES.grid(row=5, column=0, sticky=W)
        self.key_textbox_TDES = tk.Entry(frame_1_TDES, width=41)
        self.key_textbox_TDES.grid(row=5, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   1.3.1 key length
        self.key_ck_TDES = tk.Label(frame_1_TDES, text="len:")
        self.key_ck_TDES.grid(row=5, column=3)
        self.key_ck_value_TDES = tk.Text(frame_1_TDES, height=1, width=4)
        self.key_ck_value_TDES.grid(row=5, column=4)
        #   1.4 IV Entry Textbox
        self.iv_label_TDES = tk.Label(frame_1_TDES, text="IV value: ")
        self.iv_label_TDES.grid(row=6, column=0, sticky=W)
        self.iv_textbox_TDES = tk.Entry(frame_1_TDES, width=41)
        self.iv_textbox_TDES.grid(row=6, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   1.5 Input  Data Entry Textbox
        self.input_label_TDES = tk.Label(frame_1_TDES, text="Input  value:")
        self.input_label_TDES.grid(row=7, column=0, sticky=W)
        self.input_textbox_TDES = tk.Entry(frame_1_TDES, width=41)
        self.input_textbox_TDES.grid(row=7, column=1, columnspan=2, padx=5, pady=5, sticky=W)

        #   Scroll of the input text box
        # self.input_scroll = Scrollbar(self.input_textbox)
        # self.input_scroll.config(yscrollcommand = self.input_scroll.set)
        # self.input_scroll.config(command = self.input_scroll.yview)
        # self.input_scroll.pack(side = RIGHT, fill = Y)

        #   1.6 Output Data Entry Textbox
        self.output_label_TDES = tk.Label(frame_1_TDES, text="Output value: ")
        self.output_label_TDES.grid(row=8, column=0, sticky=W)
        self.output_textbox_TDES = tk.Text(frame_1_TDES, height=8, width=47)
        self.output_textbox_TDES.grid(row=8, column=1, columnspan=2, padx=5, pady=5, sticky=W)
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
        self.go_button_TDES.grid(row=9, column=0, padx=5, pady=5, sticky=S)
        self.go_button_TDES = tk.Button(frame_1_TDES, text="Go!", width=10, command=self.execution_TDES)
        self.go_button_TDES.grid(row=9, column=1, padx=5, pady=5, sticky=S)
        self.exit_button_TDES = tk.Button(frame_1_TDES, text="Exit", width=10, command=self.close_CryptoBox)
        self.exit_button_TDES.grid(row=9, column=2, padx=5, pady=5, sticky=S)
        #   2.1 AES - Encryption or Decryption Selection Frame
        self.EncOrDec_bar_AES = tk.LabelFrame(frame_2_AES, text="Operation", padx=10, pady=10)
        self.EncOrDec_bar_AES.grid(row=1, column=1, rowspan=4, sticky=NS)
        self.Enc_label_AES = tk.Radiobutton(self.EncOrDec_bar_AES, text="Enc", indicatoron=0, value=1, width=10,
                                            variable=operation_SLC_AES)
        self.Enc_label_AES.grid(row=2, column=1, padx=5, pady=5)
        self.Dec_label_AES = tk.Radiobutton(self.EncOrDec_bar_AES, text="Dec", indicatoron=0, value=2, width=10,
                                            variable=operation_SLC_AES)
        self.Dec_label_AES.grid(row=3, column=1, padx=5, pady=5)
        #   2.2 Modes Selection Frame
        self.Mode_bar_AES = tk.LabelFrame(frame_2_AES, text="Modes", padx=10, pady=10)
        self.Mode_bar_AES.grid(row=1, column=2, rowspan=4, sticky=NS)
        self.mode_ECB_AES = tk.Radiobutton(self.Mode_bar_AES, text="ECB", indicatoron=0, value=1, width=10,
                                           variable=MODE_SLC_AES)
        self.mode_ECB_AES.grid(row=2, column=2, padx=5, pady=5)
        self.mode_CBC_AES = tk.Radiobutton(self.Mode_bar_AES, text="CBC", indicatoron=0, value=2, width=10,
                                           variable=MODE_SLC_AES)
        self.mode_CBC_AES.grid(row=3, column=2, padx=5, pady=5)
        # self.mode_CFB_AES = tk.Radiobutton(self.Mode_bar_AES, text="CFB", indicatoron=0, value=3, width=10, variable=MODE_SLC_AES)
        # self.mode_CFB_AES.grid(row = 2, column = 3, padx=5, pady=5)
        self.mode_OFB_AES = tk.Radiobutton(self.Mode_bar_AES, text="OFB", indicatoron=0, value=4, width=10,
                                           variable=MODE_SLC_AES)
        self.mode_OFB_AES.grid(row=3, column=3, padx=5, pady=5)
        #   2.3 Key Entry Textbox
        self.key_label_AES = tk.Label(frame_2_AES, text="Key value: ")
        self.key_label_AES.grid(row=5, column=0, sticky=W)
        self.key_textbox_AES = tk.Entry(frame_2_AES, width=41)
        self.key_textbox_AES.grid(row=5, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   2.4 IV Entry Textbox
        self.iv_label_AES = tk.Label(frame_2_AES, text="IV value: ")
        self.iv_label_AES.grid(row=6, column=0, sticky=W)
        self.iv_textbox_AES = tk.Entry(frame_2_AES, width=41)
        self.iv_textbox_AES.grid(row=6, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   2.5 Input  Data Entry Textbox
        self.input_label_AES = tk.Label(frame_2_AES, text="Input  value: ")
        self.input_label_AES.grid(row=7, column=0, sticky=W)
        self.input_textbox_AES = tk.Entry(frame_2_AES, width=41)
        self.input_textbox_AES.grid(row=7, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   Scroll of the input text box
        # self.input_scroll = Scrollbar(self.input_textbox)
        # self.input_scroll.config(yscrollcommand = self.input_scroll.set)
        # self.input_scroll.config(command = self.input_scroll.yview)
        # self.input_scroll.pack(side = RIGHT, fill = Y)
        #   2.6 Output Data Entry Textbox
        self.output_label_AES = tk.Label(frame_2_AES, text="Output value: ")
        self.output_label_AES.grid(row=8, column=0, sticky=W)
        self.output_textbox_AES = tk.Text(frame_2_AES, height=8, width=47)
        self.output_textbox_AES.grid(row=8, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   Scroll of the output text box
        # self.input_scroll = Scrollbar(self.input_textbox)
        # self.input_scroll.config(yscrollcommand = self.input_scroll.set)
        # self.input_scroll.config(command = self.input_scroll.yview)
        # self.input_scroll.pack(side = RIGHT, fill = Y)
        #   2.7 Go Button and Exit Button
        self.go_button_AES = tk.Button(frame_2_AES, text="Use output\nas the key", width=10,
                                       command=self.copy_key_value_AES)
        self.go_button_AES.grid(row=9, column=0, padx=5, pady=5, sticky=S)
        self.go_button_AES = tk.Button(frame_2_AES, text="Go!", width=10, command=self.execution_AES)
        self.go_button_AES.grid(row=9, column=1, padx=5, pady=5, sticky=S)
        self.exit_button_AES = tk.Button(frame_2_AES, text="Exit", width=10, command=self.close_CryptoBox)
        self.exit_button_AES.grid(row=9, column=2, padx=5, pady=5, sticky=S)
        #   3_1   RSA Gen.

        #   3_1.1 RSA Key Gen
        self.Key_Gen = tk.LabelFrame(frame_3_1_RSA, text="RSA Key Pair Generation (PEM)", padx=10, pady=10)
        self.Key_Gen.grid(row=1, column=2, rowspan=4, sticky=W)
        self.RSA_pri_key_lb = tk.Label(self.Key_Gen, text="Private")
        self.RSA_pri_key_lb.grid(row=2, column=2, padx=3, pady=3, sticky=W+N)
        self.pri_key_textbox = tk.Text(self.Key_Gen, height=8, width=64)
        self.pri_key_textbox.grid(row=2, column=3, columnspan=2, padx=3, pady=3, sticky=W)
        self.RSA_pub_key_lb = tk.Label(self.Key_Gen, text="Public")
        self.RSA_pub_key_lb.grid(row=3, column=2, padx=3, pady=4, sticky=W+N)
        self.pub_key_textbox = tk.Text(self.Key_Gen, height=8, width=64)
        self.pub_key_textbox.grid(row=3, column=3, columnspan=2, padx=3, pady=3, sticky=W)
        self.RSA_key_pair_gen_bot = tk.Button(self.Key_Gen, text="Gen RSA key pair", width=11, command=self.RSA_key_pair_gen_func)
        self.RSA_key_pair_gen_bot.grid(row=4, column=4, padx=3, pady=3, sticky=E)

        self.RSA_k_len_lb = tk.Label(self.Key_Gen, text="key len")
        self.RSA_k_len_lb.grid(row=4, column=2, padx=3, pady=4, sticky=W)
        self.RSA_k_len_En = tk.Entry(self.Key_Gen, width=5)
        self.RSA_k_len_En.grid(row=4, column=3, padx=3, pady=3, sticky=W)

        #   3_1.4 output file - enciphered/plaintext binary data


        #   3_2     RSA Crypto.
        #   3_2.1 Operation selection
        '''
        self.EncOrDec_bar_RSA = tk.LabelFrame(frame_3_2_RSA, text="Operation", padx=10, pady=10)
        self.EncOrDec_bar_RSA.grid(row=1, column=1, rowspan=4, sticky=W+N)
        self.Enc_label_RSA = tk.Radiobutton(self.EncOrDec_bar_RSA, text="Enc", indicatoron=0, value=1, width=10,
                                            variable=operation_SLC_RSA)
        self.Enc_label_RSA.grid(row=2, column=1, padx=3, pady=5)
        self.Dec_label_RSA = tk.Radiobutton(self.EncOrDec_bar_RSA, text="Dec", indicatoron=0, value=2, width=10,
                                            variable=operation_SLC_RSA)
        self.Dec_label_RSA.grid(row=3, column=1, padx=3, pady=5)
        '''

        #   3_2.2 input file - plaintext/enciphered binary data
        self.rsa_data_in_lb = tk.Label(frame_3_2_RSA, text="\nNote: Private key and Public key must be\nstored in the pvt.rsa and pub.rsa files\n\n")
        self.rsa_data_in_lb.grid(row=0, column=1, columnspan=3, sticky=W)
        self.rsa_data_in_lb = tk.Label(frame_3_2_RSA, text="Data Input ")
        self.rsa_data_in_lb.grid(row=1, column=1, sticky=W)
        self.rsa_data_in = tk.Entry(frame_3_2_RSA, width=56)
        self.rsa_data_in.grid(row=1, column=2, columnspan=3, padx=3, pady=3, sticky=W)

        self.rsa_data_in_lb = tk.Label(frame_3_2_RSA, text="Data Output")
        self.rsa_data_in_lb.grid(row=2, column=1, sticky=W)
        self.rsa_data_out = tk.Text(frame_3_2_RSA, height=8, width=64)
        self.rsa_data_out.grid(row=2, column=2, columnspan=3, padx=3, pady=3, sticky=W)


        #   3_2.1 key file
        self.key_pub_butt_RSA = tk.Button(frame_3_2_RSA, text="Encrypt data", width=11, command=self.execution_RSA_enc)
        self.key_pub_butt_RSA.grid(row=3, column=3, padx=3, pady=5, sticky=E)
        self.key_pri_butt_RSA = tk.Button(frame_3_2_RSA, text="Decrypt data", width=11, command=self.execution_RSA_dec)
        self.key_pri_butt_RSA.grid(row=3, column=4, padx=3, pady=5, sticky=E)
        '''
        self.key_label_RSA = tk.Label(frame_3_1_RSA, text="Key value: ")
        self.key_label_RSA.grid(row = 5, column = 0)
        self.key_textbox_AES= tk.Entry(frame_2_AES, width = 41)
        self.key_textbox_AES.grid(row = 5, column = 1, columnspan = 2, padx=5, pady=5, sticky=W)
        '''





        #   4   Hash - (SHA, SHA224, SHA256, SHA384, SHA512, MD4, MD5, HMAC??)
        self.HASH_frame = tk.LabelFrame(frame_4_HASH, text="Algorithms", padx=10, pady=10)
        self.HASH_frame.grid(row=1, column=1, rowspan=4, columnspan=4, sticky=NS)
        #   4.1 algorithm selection buttons
        self.hash_SHA = tk.Radiobutton(self.HASH_frame, text="SHA", indicator=0, value=1, width=10,
                                       variable=operation_SLC_HASH)
        self.hash_SHA.grid(row=2, column=1, padx=5, pady=5)
        self.hash_MD4 = tk.Radiobutton(self.HASH_frame, text="MD4", indicator=0, value=2, width=10,
                                       variable=operation_SLC_HASH)
        self.hash_MD4.grid(row=2, column=2, padx=5, pady=5)
        self.hash_MD5 = tk.Radiobutton(self.HASH_frame, text="MD5", indicator=0, value=3, width=10,
                                       variable=operation_SLC_HASH)
        self.hash_MD5.grid(row=2, column=3, padx=5, pady=5)
        self.hash_HMAC = tk.Checkbutton(self.HASH_frame, text="HMAC", width=10, variable=operation_SLC_HASH_hmac)
        self.hash_HMAC.grid(row=2, column=4, padx=5, pady=5)
        self.hash_SHA224 = tk.Radiobutton(self.HASH_frame, text="SHA224", indicator=0, value=5, width=10,
                                          variable=operation_SLC_HASH)
        self.hash_SHA224.grid(row=3, column=1, padx=5, pady=5)
        self.hash_SHA256 = tk.Radiobutton(self.HASH_frame, text="SHA256", indicator=0, value=6, width=10,
                                          variable=operation_SLC_HASH)
        self.hash_SHA256.grid(row=3, column=2, padx=5, pady=5)
        self.hash_SHA384 = tk.Radiobutton(self.HASH_frame, text="SHA384", indicator=0, value=7, width=10,
                                          variable=operation_SLC_HASH)
        self.hash_SHA384.grid(row=3, column=3, padx=5, pady=5)
        self.hash_SHA512 = tk.Radiobutton(self.HASH_frame, text="SHA512", indicator=0, value=8, width=10,
                                          variable=operation_SLC_HASH)
        self.hash_SHA512.grid(row=3, column=4, padx=5, pady=5)
        #   4.2 HMAC key input
        self.hash_hmac_key_label = tk.Label(frame_4_HASH, text="HMAC key:")
        self.hash_hmac_key_label.grid(row=6, column=0, padx=5, pady=5, sticky=W)
        self.hash_hmac_key_entry = tk.Entry(frame_4_HASH,  width=47)
        self.hash_hmac_key_entry.grid(row=6, column=1, columnspan=2, padx=5, pady=5, sticky=W)

        #   4.3 Data Input
        self.hash_input_label = tk.Label(frame_4_HASH, text="Input  value:")
        self.hash_input_label.grid(row=7, column=0, padx=5, pady=5, sticky=W)
        self.hash_input_entry = tk.Entry(frame_4_HASH,  width=47)
        self.hash_input_entry.grid(row=7, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   4.4 Data Output
        self.hash_output_label = tk.Label(frame_4_HASH, text="Output value:")
        self.hash_output_label.grid(row=8, column=0, sticky=W)
        self.hash_output_text = tk.Text(frame_4_HASH, height=8, width=47)
        self.hash_output_text.grid(row=8, column=1, columnspan=2, padx=5, pady=5, sticky=W)
        #   4.4 Go button
        self.go_button_hash = tk.Button(frame_4_HASH, text="Go!", width=10, command=self.execution_HASH)
        self.go_button_hash.grid(row=9, column=1, padx=5, pady=5, sticky=S)
        self.exit_button_hash = tk.Button(frame_4_HASH, text="Exit", width=10, command=self.close_CryptoBox)
        self.exit_button_hash.grid(row=9, column=2, padx=5, pady=5, sticky=S)
        #   5   XOR
        self.XOR_frame = tk.LabelFrame(frame_5_XOR, text="XOR", padx=10, pady=10)
        self.XOR_frame.grid(row=1, column=1, rowspan=4, columnspan=4, sticky=NS)
        #   5.1 data A & B & result labels
        self.xor_inputA_label = tk.Label(self.XOR_frame, text="input data A:")
        self.xor_inputA_label.grid(row=2, column=1, sticky=W)
        self.xor_inputB_label = tk.Label(self.XOR_frame, text="input data B:")
        self.xor_inputB_label.grid(row=3, column=1, sticky=W)
        self.xor_result_label = tk.Label(self.XOR_frame, text="output data :")
        self.xor_result_label.grid(row=4, column=1, sticky=W)
        #   5.2 data A & B Entry widgets
        self.xor_inputA_value = tk.Entry(self.XOR_frame, width=41)
        self.xor_inputA_value.grid(row=2, column=2, columnspan=2, padx=5, pady=5, sticky=W)
        self.xor_inputB_value = tk.Entry(self.XOR_frame, width=41)
        self.xor_inputB_value.grid(row=3, column=2, columnspan=2, padx=5, pady=5, sticky=W)
        self.xor_result_value = tk.Text(self.XOR_frame, height=8, width=47)
        self.xor_result_value.grid(row=4, column=2, columnspan=2, padx=5, pady=5, sticky=W)
        #   5.3 button GO!
        self.go_button_XOR = tk.Button(frame_5_XOR, text="Go!", width=10, command=self.execution_XOR)
        self.go_button_XOR.grid(row=9, column=1, padx=5, pady=5, sticky=S)
        self.exit_button_XOR = tk.Button(frame_5_XOR, text="Exit", width=10, command=self.close_CryptoBox)
        self.exit_button_XOR.grid(row=9, column=2, padx=5, pady=5, sticky=S)
        #   6   Random number generator button
        self.rng_bar_bar = tk.LabelFrame(frame_6_RNG, text="Random number", padx=20, pady=10)
        self.rng_bar_bar.grid(row=1, column=1, rowspan=4)
        self.rng_butt_8B = tk.Button(self.rng_bar_bar, text="Generate 8byte", command=self.rng_gen_8B)
        self.rng_butt_8B.grid(row=2, column=1, padx=5, pady=5, sticky=W)
        self.rng_8B_textbox = tk.Text(self.rng_bar_bar, height=1, width=32)
        self.rng_8B_textbox.grid(row=5, column=1, padx=5, pady=5)

        self.rng_butt_32B = tk.Button(self.rng_bar_bar, text="Generate 32byte", command=self.rng_gen_32B)
        self.rng_butt_32B.grid(row=6, column=1, padx=5, pady=5, sticky=W)
        self.rng_32B_textbox = tk.Text(self.rng_bar_bar, height=4, width=32)
        self.rng_32B_textbox.grid(row=7, column=1, padx=5, pady=5)

        self.rng_butt_88B = tk.Button(self.rng_bar_bar, text="Generate 88byte", command=self.rng_gen_88B)
        self.rng_butt_88B.grid(row=8, column=1, padx=5, pady=5, sticky=W)
        self.rng_88B_textbox = tk.Text(self.rng_bar_bar, height=4, width=32)
        self.rng_88B_textbox.grid(row=9, column=1, padx=5, pady=5)
        #   7   About CryptoBox
        self.abt_bar = tk.LabelFrame(frame_7_ABT, text=" --- CryptoBox --- ")
        self.abt_bar.grid(row=1, column=1)
        msg = ["Ttk is the new Tk themed widget set. One of the widgets ",
               "The CryptoBox is a UL internal cryptografic calculator developed internally.",
               "Supported algorithms include DES/TDES, AES, RSA, and HASH, ",
               "as well as exclusive OR operation and random number generator."]
        CB_about_label = tk.Label(self.abt_bar, justify=LEFT, anchor=N, text='fill sth here!')
        # CB_about_label = tk.Label(self.abt_bar, wraplenth='4i', justify=LEFT, anchor=N, text=''.join(msg))
        CB_about_label.grid(row=2, column=2, columnspan=2, sticky='new', padx=5, pady=5)

    #   Crypto function - DES
    def execution_TDES(self):
        #   algo & operation Judgment
        selection_Algo = algo_SLC_TDES.get()
        selection_EorD = operation_SLC_TDES.get()
        key_raw_xDES = self.key_textbox_TDES.get()
        key_len_check = len(key_raw_xDES)
        print 'key len:', key_len_check, '\n', key_len_check/2
        if key_len_check != 16 or key_len_check != 32 or key_len_check != 48:
            self.output_textbox_TDES.delete(1.0, END)
            self.output_textbox_TDES.insert(1.0, "Key length is not correct")
        else:
            pass
        self.key_ck_value_TDES.delete(1.0, END)
        self.key_ck_value_TDES.insert(1.0, " B")
        self.key_ck_value_TDES.insert(1.0, key_len_check / 2)
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
            self.output_textbox_TDES.insert(1.0, "Please selection an algorithm")
        elif selection_Algo == 1:  # DES algo
            key_len = len(key_raw_xDES)
            print "key_len:", key_len
            '''
            if key_len != "16":
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, "Please enter correct key")
            #   'Enc/Dec' Judgment, and execute!!!
            '''
            if key_len != 16 or selection_EorD == 0:
                self.output_textbox_TDES.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, "Key length or Operation is not correct")
            elif key_len == 16 and selection_EorD == 1:  # Enc operation
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
            elif key_len == 16 and selection_EorD == 2:  # Dec operation
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
            key_len = len(key_raw_xDES)
            print "DES key length:", key_len
            mode_judge = MODE_SLC_TDES.get()
            if mode_judge == 1:
                mode = DES.MODE_ECB
            elif mode_judge == 2:
                mode = DES.MODE_CBC
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
                self.output_textbox_TDES.insert(1.0, "Please selection operation")
            elif selection_EorD == 1 and key_len == 32 or key_len == 48:  # Enc operation
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
            elif selection_EorD == 2 and key_len == 32 or key_len == 48:  # Dec operation
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
                self.xor_result_value.delete(1.0, END)
                self.output_textbox_TDES.insert(1.0, h_out_data_d)
            else:
                print "\nUnknow error. Please info Nigel"
        else:
            pass  # algo END
        # else: pass
        #   Crypto function - TDES

    def copy_key_value_TDES(self):
        self.output_textbox_TDES.delete(1.0, END)
        self.output_textbox_TDES.insert(1.0, "This is a reserved feature")
        '''
        key_temp_value = self.output_textbox_TDES.get(1.0, END)
        print "new key value:", key_temp_value
        print "copy the TDES output value to key value..."
        # WRONG WIDGET BELOW??
        key_textbox_TDES.delete(1.0, END)
        key_textbox_TDES.insert(1.0, key_temp_value)
        key_textbox_TDES.pack()
        '''

    #   Crypto function - AES
    def execution_AES(self):
        # print "AES Algo is under developing..."
        selection_aes_EorD = operation_SLC_AES.get()
        key_raw_AES = self.key_textbox_AES.get()
        key_len_check_aes = len(key_raw_AES)
        if key_len_check_aes != 32 or key_len_check_aes != 48 or key_len_check_aes != 64:
            self.output_textbox_AES.delete(1.0, END)
            self.output_textbox_AES.insert(1.0, "Key length is not correct")
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
            self.output_textbox_AES.insert(1.0, "Please selection operation")
        elif selection_aes_EorD == 1 and key_aes_len == 32 or key_aes_len == 48 or key_aes_len == 64:  # AES Enc operation
            obj = AES.new(hkey_AES, mode, hiv_AES)
            #   Encryption !!
            output_aes_raw_e = obj.encrypt(h_in_data_AES)
            h_out_data_aes_e = output_aes_raw_e.encode('hex')
            print "AES (enc) result:", h_out_data_aes_e
            self.output_textbox_AES.delete(1.0, END)
            self.output_textbox_AES.insert(1.0, h_out_data_aes_e)
        elif selection_aes_EorD == 2 and key_aes_len == 32 or key_aes_len == 48 or key_aes_len == 64:  # AES Dec operation
            #   debug:
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
            # print "\nUnknow error. Please info Nigel"
            # else:
            #   pass  # algo END
            # else: pass
            #   Crypto function - AES

    def copy_key_value_AES(self):
        print "copy the AES output value to key value..."

    #   Crypto function - RSA
    def RSA_key_pair_gen_func(self):
        #get RSA key length:
        rsa_len = self.RSA_k_len_En.get()
        print 'RSA private key length is:', rsa_len
        #generate private RSA key
        private = RSA.generate(int(rsa_len))
        public  = private.publickey()
        self.pri_key_textbox.delete(1.0, END)
        self.pri_key_textbox.insert(1.0, private.exportKey())
        self.pub_key_textbox.delete(1.0, END)
        self.pub_key_textbox.insert(1.0, public.exportKey())
        print 'pri:', private.e, private.d, private.p, private.q
        print 'pub:', public
        with open("pub.rsa", "w") as pub_key:
            pub_key.write(public.exportKey())
        with open("pvt.rsa", "w") as pvt_key:
            pvt_key.write(private.exportKey())

    def execution_RSA_enc(self):
        #rsa_p_data = StringVar()
        rsa_p_data = self.rsa_data_in.get()
        print 'rsa_p_data:', rsa_p_data
        with open('pub.rsa', 'r') as pub_key_file:
            pub_key = RSA.importKey(pub_key_file.read())
            print "pub_key", pub_key
            enciphered_data = pub_key.encrypt(rsa_p_data, 0)[0].encode('hex')
            print 'enciphered_data:', enciphered_data
            self.rsa_data_out.delete(1.0, END)
            self.rsa_data_out.insert(1.0, enciphered_data)

    def execution_RSA_dec(self):
        rsa_c_data = self.rsa_data_in.get()
        print 'rsa_c_data:', rsa_c_data
        with open('pvt.rsa', 'r') as pvt_key_file:
            pvt_key = RSA.importKey(pvt_key_file.read())
            print "pvt_key", pvt_key
            deciphered_data = pvt_key.decrypt(rsa_c_data).encode('hex')
            #deciphered_data_h = deciphered_data.encode('hex')
            print 'deciphered_data:', deciphered_data
            self.rsa_data_out.delete(1.0, END)
            self.rsa_data_out.insert(1.0, deciphered_data)

    '''
    def pub_key_filename():
        global key_pub_filename
        key_pub_filename = askopenfilename(defaultextension='.txt')
        if key_pub_filename == '':
            key_pub_filename = None
        else:
            root.title('Key FileName:' + os.path.basename(key_pub_filename))
            textPad.delete(1.0, END)
            f = open(key_filename, 'r')
            textPad.insert(1.0, f.read())
            f.close()

    def pri_key_filename():
        global key_pri_filename
        key_pri_filename = askopenfilename(defaultextension='.txt')
        if key_pri_filename == '':
            key_pri_filename = None
        else:
            root.title('Key FileName:' + os.path.basename(key_pri_filename))
            textPad.delete(1.0, END)
            f = open(key_filename, 'r')
            textPad.insert(1.0, f.read())
            f.close()
    '''

    #   HASH function - SHA, SHA224, SHA256, SHA384, SHA512, MD4, MD5, HMAC ??

    def execution_HASH(self):

        hash_algo_selector = operation_SLC_HASH.get()
        hash_algo_selector_hmac = operation_SLC_HASH_hmac.get()
        print "Here hmac:", hash_algo_selector_hmac
        if hash_algo_selector_hmac ==1:
            hmac_key = self.hash_hmac_key_entry.get()
            print hmac_key
            h_hmac_key = hmac_key.replace(' ', '').decode('hex')
            print h_hmac_key
        elif hash_algo_selector == 0:
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

        if hash_algo_selector_hmac == 1:
            obj_hmac = HMAC.new(h_hmac_key, digestmod=SHA)
            obj_hmac.update(h_hash_data)
            h_hmac_output = obj_hmac.digest('hex')
            self.hash_output_text.delete(1.0, END)
            self.hash_output_text.insert(1.0, h_hmac_output)
        elif hash_algo_selector_hmac == 0 and hash_algo_selector ==1 or hash_algo_selector == 2 or \
                        hash_algo_selector == 3 or hash_algo_selector == 5 or hash_algo_selector == 6 or \
                        hash_algo_selector == 7 or hash_algo_selector == 8 :
            obj = hash_algo.new()
            obj.update(h_hash_data)
            ret = obj.digest()
            h_output_hash = ret.encode('hex')
            print  "\n", hash_algo, ":", h_output_hash
            self.hash_output_text.delete(1.0, END)
            self.hash_output_text.insert(1.0, h_output_hash)

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

    def close_CryptoBox(self):
        global root
        root.destroy()

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


app = CryptoBox()
root.mainloop()
