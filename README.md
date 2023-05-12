# wafaas-api
Web Application Firewall as a Service API

If the /api/lib/ directory is not in the search path, you can add it by running the following command:
export PYTHONPATH=$PYTHONPATH:/api/lib/

Check the Python interpreter's search path by running the following command:
python -c "import sys; print(sys.path)"

decrypt_data(header=header, key=key, cipher_text=cipher_text, tag=tag, nonce=nonce)
decrypt_data(**{'header': header, 'key': key, 'cipher_text': cipher_text, 'tag': tag, 'nonce': nonce})


# SecRuleEngine DetectionOnly
# SecAuditEngine RelevantOnly
# SecAuditLog /var/log/apache2/audit.log
# SecAuditLogParts ABHZ
# SecRequestBodyAccess On
# SecDataDir /tmp/modsec/data
# SecPcreMatchLimit 10000000
# SecPcreMatchLimitRecursion 10000000
# SecResponseBodyAccess On
# SecCollectionTimeout 600
# SecContentInjection On

# Sets the number of seconds before the data collected in the audit log for a
# transaction is flushed to disk. This directive helps ensure that collected
# data is not lost if a system error or crash occurs. In this case, it is set
# to 600 seconds (10 minutes).
SecCollectionTimeout 600

# Enables or disables content injection functionality. When enabled, ModSecurity
# can inject content into the response body of a transaction. This can be useful,
# for example, to add a banner to all responses from a particular web application.
SecContentInjection On

SecAction \
 "id:900990,\
  phase:1,\
  nolog,\
  pass,\
  t:none,\
  setvar:tx.crs_setup_version=330"


