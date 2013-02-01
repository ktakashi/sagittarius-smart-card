(import (rnrs)
	(pcsc operations gp)
	(pcsc operations control)
	(pcsc shell commands)
	(pcsc dictionary gp)
	(srfi :39))

(establish-context)
(card-connect)
(select)

;; you must provide proper key to open secure channel
;;(channel)

;; These are how to get status and dump the response APDU
;; to use this in real world, you might need to open a
;; secure channel.
(parameterize ((*tag-dictionary* *gp-dictionary*))
  (print "issuer")
  (apdu-pretty-print (strip-return-code (invoke-command get-status issuer)))
  (print "applications")
  (apdu-pretty-print (strip-return-code
		      (invoke-command get-status application)))
  (print "loadfiles")
  (apdu-pretty-print (strip-return-code (invoke-command get-status loadfile)))
  (print "modules")
  (apdu-pretty-print (strip-return-code (invoke-command get-status module))))

(card-disconnect)
(release-context)