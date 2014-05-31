#!/bin/sh

/usr/share/privilege-control/db/updater.sh

/usr/bin/api_feature_loader --verbose --dir=/usr/share/privilege-control/
/usr/bin/api_feature_loader --verbose --rules=/usr/share/privilege-control/ADDITIONAL_RULES.smack
