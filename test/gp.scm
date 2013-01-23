(import (pcsc operations gp) 
	(pcsc operations control) 
	(sagittarius object)
	(srfi :64))
;; some tests
(define context (make-secure-channel-context #x20 0 :option #x55))
(define answer #vu8(#x00 #x00 #x50 #xD9 #xE6 #x58 #x8C #x38 #x2F 
			 #x00 #x20 #x02 #x00 #x31 #x18 #x30 #x3B
			 #x30 #xDA #xD7 #xB1 #xA3 #x12 #x50 #x5B
			 #x4E #x53 #x2A #x90 #x00))
(define key (integer->bytevector #x10101010101010101010101010101010))
(test-begin "GP library tests")
(test-assert "card authentication"
	     (authenticate-card context answer key key key derive-key-none))
(test-equal "static enc key"  key (~ context 'enc-key))
(test-equal "static mac key"  key (~ context 'mac-key))
(test-equal "static dek key"  key (~ context 'dek-key))

(test-equal "enc session key"
	    "7D8BF68FC5C0CB3ABE3D8D2DDC4C853E"
	    (bytevector->hex-string (~ context 'enc-session-key)))
(test-equal "mac session key"
	    "90DAECAE39D31DDC243A935310BB7890"
	    (bytevector->hex-string (~ context 'mac-session-key)))
(test-equal "dek session key"
	    "E7B9AB29B9F1DE10212665CB2F1144BB"
	    (bytevector->hex-string (~ context 'dek-session-key)))
(test-equal "external auth and encode-apdu"
	    "8482010010E6357A57C39A14B8CD796FECC260A406"
	    (bytevector->hex-string 
	     (external-authenticate context *security-level-mac*)))

(test-end)