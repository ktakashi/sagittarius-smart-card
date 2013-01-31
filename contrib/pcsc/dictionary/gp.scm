;;; -*- mode:scheme; coding: utf-8 -*-
;;;
;;; pcsc/dictionary/gp.scm - Global platform tag dictionary
;;;  
;;;   Copyright (c) 2013  Takashi Kato  <ktakashi@ymail.com>
;;;   
;;;   Redistribution and use in source and binary forms, with or without
;;;   modification, are permitted provided that the following conditions
;;;   are met:
;;;   
;;;   1. Redistributions of source code must retain the above copyright
;;;      notice, this list of conditions and the following disclaimer.
;;;  
;;;   2. Redistributions in binary form must reproduce the above copyright
;;;      notice, this list of conditions and the following disclaimer in the
;;;      documentation and/or other materials provided with the distribution.
;;;  
;;;   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
;;;   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
;;;   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
;;;   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
;;;   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
;;;   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
;;;   TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
;;;   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
;;;   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
;;;   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
;;;   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
;;;  

(library (pcsc dictionary gp)
    (export *gp-dictionary*)
    (import (only (rnrs) quote)
	    (only (sagittarius) define-constant))

  (define-constant *gp-dictionary*
    '((#x42 "CA Identifier" text)
      (#x45 "CA Security Domain Image Number")
      (#x4F "AID" text)
      (#x53 "Discretionary Data")
      (#x5F20 "Subject Identifier" text)
      (#x5F24 "Expiration Date")
      (#x5F25 "Effective Date")
      (#x5F37 "Signature")
      (#x5F38 "Public Key Modulus Remainder")
      (#x93   "Certificate Serial Number")
      (#x66   "Card or Security Domain Management data")
      (#x7F21 "Certificate")
      (#x7F49 "Public Key")
      (#x84   "Executable Module AID")
      (#x93   "Certificate Serial Number")
      (#x95   "Key Usage")
      (#x9F70 "Life Cycle State")
      (#xB6   "Control Reference Template for Digital Signature (Token)")
      (#xC0   "Key Information Data")
      (#xC1   "Sequence Counter of the default Key Version Number")
      (#xC2   "Confirmation Counter")
      (#xC4   "Application's Executable Load File AID")
      (#xC5   "Privileges")
      (#xC7   "Volatile Memory Quota")
      (#xC8   "Non volatile Memory Quota")
      (#xCA   "TS 102 226 specific parameter")
      (#xCB   "Global Service Parameters")
      (#xCC   "Associated Security Domain AID")
      (#xCE   "Executable Load File Version Number")
      (#xCF   "Implicit Selection Parameters")
      (#xD3   "Current Security Level")
      (#xD7   "Volatile Reserved Memory")
      (#xD8   "Non volatile Reserved Memory")
      (#xE0   "Key Information Template")
      (#xE3   "GlobalPlatform Registry related data")
      (#xEA   "TS 102 226 specific template")
      (#xEF   "System Specifc Parameters")))
)