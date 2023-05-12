#!/bin/bash

MODSEC_PATH="/etc/apache2/modsecurity-crs/";
MODSEC_CRS_PATH="/etc/apache2/modsecurity-crs/coreruleset";
MODSEC_STATIC_PATH="/etc/apache2/modsec_static_files";

# Check if the MODSEC_PATH directory exists, if not then create it and clone the OWASP ModSecurity Core Rule Set (CRS) repository from GitHub
if [ ! -d "$MODSEC_PATH" ]; then
        mkdir ${MODSEC_PATH};
        cd ${MODSEC_PATH};
        /usr/bin/git clone https://github.com/coreruleset/coreruleset.git;
fi

# Change directory to the ModSecurity CRS path
cd ${MODSEC_CRS_PATH}/;
# Update the CRS repository with the latest changes from GitHub
/usr/bin/git pull;
# Copy the crs-setup.conf file from the ModSecurity static directory to the ModSecurity CRS path to use it as the default configuration file
cp ${MODSEC_STATIC_PATH}/crs-setup.conf ${MODSEC_CRS_PATH}/crs-setup.conf;

# Change the modsecurity configuration to use the latest OWASP CRS
# Replace the line that loads the default CRS files
sed -i '/IncludeOptional \/usr\/share\/modsecurity-crs\/\*\.load/c\
        IncludeOptional \/etc\/apache2\/modsecurity-crs\/coreruleset\/crs-setup.conf\n        IncludeOptional \/etc\/apache2\/modsecurity-crs\/coreruleset\/rules\/\*.conf' /etc/apache2/mods-enabled/security2.conf

# Restart apache
service apache2 restart

