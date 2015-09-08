#!/bin/sh

/usr/share/privilege-control/db/updater.sh

/usr/bin/api_feature_loader --verbose --clear-permissions
/usr/bin/api_feature_loader --verbose --rules=/usr/share/privilege-control/ADDITIONAL_RULES.smack
