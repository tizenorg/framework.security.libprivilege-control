#!/bin/sh

#database updater requires making proper sql scripts

if [ $# -eq 2 -a "$1" = "--check-files" ]
then
    echo "Checking sql update files"
    check="1"
    dir="$2"
    sqlitecmd="true"
elif [ $# -eq 0 ]
then
    echo "Applying sql update files on db"
    check="0"
    dir=""
    sqlitecmd="sqlite3"
else
    exit 1
fi


database="$dir/opt/dbspace/.rules-db.db3"
scripts_dir="$dir/usr/share/privilege-control/db"
updates_dir="$dir/usr/share/privilege-control/db/updates"

echo $database


if [ $check -eq 0 -a ! -e "$database" ]
then
    echo "Creating database from scratch"
    $sqlitecmd "$database" < "$scripts_dir/rules-db.sql"
    $sqlitecmd "$database" < "$scripts_dir/rules-db-data.sql"
else
    db_version="`$sqlitecmd $database "PRAGMA user_version;"`"
    # Parsing DB version from rules-db.sql
    db_version_to_install="`grep $scripts_dir/rules-db.sql -e '^[[:space:]]*PRAGMA user_version'`"
    db_version_to_install="`echo \"$db_version_to_install\" | sed -r 's/.*([0-9]+).*/\1/'`"

    if [ -z "$db_version_to_install" ]
    then echo "Version to be installed: unknown: '$db_version_to_install'"
         exit 1
    fi

    if [ 0"$db_version" -eq 0 ]
    then echo "user_version PRAGMA is not set on database. Assuming version 1 or 2"
         #minor hack for backward compatibility,
         #workaround for older databases that were not versioned properly.
         db_version="`$sqlitecmd $database \"PRAGMA table_info(app_path)\"`"
         db_version="`echo \"$db_version\" | grep -e \"access_reverse\"`"
         if [ -z "$db_version" ]
         then db_version=1
         else db_version=2
         fi
    fi

    echo "Current database version is $db_version"
    echo "Version being installed now is $db_version_to_install"

    if [ "$db_version" -gt "$db_version_to_install" ]
    then echo "Downgrade database version not possible without data loss,"
         echo "Remove current database manually (rm $database) and retry."
         exit 1
    fi
    for i in `seq $((db_version+1)) $db_version_to_install`
    do
        echo "Database upgrade to version $i:"
        update_script="$updates_dir/update-rules-db-to-v$i.sql"
        update_data_script="$updates_dir/update-rules-db-data-to-v$i.sql"
        if [ ! -e  "$update_script" ]
        then
            echo "No $update_script available, make one"
            exit 1
        fi
        if [ ! -e  "$update_data_script" ]
        then
            echo "No $update_data_script available, make one"
            exit 1
        fi
        echo "Loading $update_script"
        $sqlitecmd "$database" < "$update_script"
        echo "Loading $update_data_script"
        $sqlitecmd "$database" < "$update_data_script"
    done
    #after updating schema, make veiws etc.
    $sqlitecmd "$database" < "$scripts_dir/rules-db.sql"
    $sqlitecmd "$database" < "$scripts_dir/rules-db-data.sql"

fi

