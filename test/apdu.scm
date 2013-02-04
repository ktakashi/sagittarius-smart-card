(import (rnrs)
	(pcsc operations apdu)
	(srfi :64))

(test-begin "APDU utilities tests")

(test-equal "compose-apdu(1)"
	    (integer->bytevector #x80F24002024F00)
	    (compose-apdu #x80 #xF2 #x40 #x02 #vu8(#x4F #x00)))

(test-equal "compose-apdu"
	    (integer->bytevector #x80F24002024F0000)
	    (compose-apdu #x80 #xF2 #x40 #x02 #vu8(#x4F #x00) #x00))

(test-equal "decompose-apdu"
	    '(#x80 #xF2 #x40 #x02 #vu8(#x4F #x00) #x00)
	    (receive r (decompose-apdu 
			(integer->bytevector #x80F24002024F0000 8))
	      r))

(test-equal "decompose-apdu (2)"
	    `(#x00 #xA4 #x04 #x00 ,(string->utf8 "2PAY.SYS.DDF01") #f)
	    (receive r (decompose-apdu 
			(integer->bytevector 
			 #x00A404000E325041592E5359532E4444463031
			 19))
	      r))

(test-end)