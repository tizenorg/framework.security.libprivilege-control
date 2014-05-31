CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT(libprivilege-control C)

SET(TARGET_PRIVILEGE_CONTROL "privilege-control")
SET(PREFIX ${CMAKE_INSTALL_PREFIX})
SET(EXEC_PREFIX "\${prefix}")
SET(SHAREDIR "${PREFIX}/share/privilege-control")
SET(HOMEDIR "/opt/home")
SET(VERSION 1.0)

SET(VERSION_MAJOR 0)
SET(VERSION "${VERSION_MAJOR}.0.2")

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/include)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED libsmack libiri dlog sqlite3)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

# TIZEN_ENGINEER_MODE is used in  dlog.h file.
# Without this flag all logs defined with SLOGD macro
# will be expanded to empty instruction.

SET(CMAKE_C_FLAGS_CCOV    "--coverage")
SET(CMAKE_C_FLAGS_DEBUG   "-O0 -g -ggdb -DDLOG_DEBUG_ENABLED -DTIZEN_ENGINEER_MODE")
SET(CMAKE_C_FLAGS_RELEASE "-O2 -g")

SET(src_dir "./src")
SET(include_dir "./include")


## Additional flag
ADD_DEFINITIONS("-fvisibility=hidden")
ADD_DEFINITIONS("-DSHAREDIR=${SHAREDIR}")
ADD_DEFINITIONS("-DHOMEDIR=${HOMEDIR}")
#ADD_DEFINITIONS("-Wall -Werror -Wextra")
ADD_DEFINITIONS("-Wall -Wextra")

ADD_DEFINITIONS("-DDLOG_WARN_ENABLED")
ADD_DEFINITIONS("-DDLOG_ERROR_ENABLED")

###################################################################################################
## for libprivilege-control.so (library)
INCLUDE_DIRECTORIES(${pkgs_INCLUDE_DIRS})
SET(libprivilege-control_SOURCES
	${src_dir}/privilege-control.c
	${src_dir}/access-db.c
	${src_dir}/common.c
	${src_dir}/rules-db.c
	${src_dir}/rules-db-internals.c
	)
SET(libprivilege-control_LDFLAGS " -module ")
SET(libprivilege-control_CFLAGS  " ${CFLAGS} -fPIC -I${include_dir}")
SET(libprivilege-control_LIBADD  "${pkgs_LDFLAGS} -lcap -lcrypt")

ADD_LIBRARY(${TARGET_PRIVILEGE_CONTROL} SHARED ${libprivilege-control_SOURCES})
TARGET_LINK_LIBRARIES(${TARGET_PRIVILEGE_CONTROL} ${libprivilege-control_LIBADD} ${pkgs_LIBRARIES})
SET_TARGET_PROPERTIES(${TARGET_PRIVILEGE_CONTROL} PROPERTIES COMPILE_FLAGS "${libprivilege-control_CFLAGS}")
SET_TARGET_PROPERTIES(${TARGET_PRIVILEGE_CONTROL} PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(${TARGET_PRIVILEGE_CONTROL} PROPERTIES VERSION ${VERSION})
###################################################################################################
## for rules-db-sql-udf.so (library)
SET(rules-db-sql-udf_SOURCES ./db/rules-db-sql-udf.c)
SET(rules-db-sql-udf_LDFLAGS " -module ")
SET(rules-db-sql-udf_CFLAGS  " ${CFLAGS} -fPIC")

ADD_LIBRARY(rules-db-sql-udf MODULE ${rules-db-sql-udf_SOURCES})
SET_TARGET_PROPERTIES(rules-db-sql-udf PROPERTIES COMPILE_FLAGS "${rules-db-sql-udf_CFLAGS}")
SET_TARGET_PROPERTIES(rules-db-sql-udf PROPERTIES LINK_FLAGS "${rules-db-sql-udf_LDFLAGS}")

###################################################################################################
## for slp-su (excutable)
SET(slp-su_SOURCES ${src_dir}/slp-su.c)
SET(slp-su_LDFLAGS " -module ")
SET(slp-su_CFLAGS  " ${CFLAGS} -fPIC -I${include_dir}")

ADD_EXECUTABLE(slp-su ${slp-su_SOURCES})
TARGET_LINK_LIBRARIES(slp-su ${pkgs_LDFLAGS} ${pkgs_LIBRARIES} ${TARGET_PRIVILEGE_CONTROL})
SET_TARGET_PROPERTIES(slp-su PROPERTIES COMPILE_FLAGS "${slp-su_CFLAGS}")
###################################################################################################


CONFIGURE_FILE(libprivilege-control.pc.in libprivilege-control.pc @ONLY)

INSTALL(TARGETS ${TARGET_PRIVILEGE_CONTROL} DESTINATION  ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)
INSTALL(TARGETS rules-db-sql-udf DESTINATION  ${LIB_INSTALL_DIR} COMPONENT RuntimeLibraries)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/libprivilege-control.pc DESTINATION  ${LIB_INSTALL_DIR}/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/passwd DESTINATION /opt/etc/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/group DESTINATION /opt/etc/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/smack_default_labeling DESTINATION /etc/rc.d/init.d/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/smack_rules DESTINATION /etc/rc.d/init.d/)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/privilege-control.h DESTINATION ${INCLUDE_INSTALL_DIR})
INSTALL(FILES .privilege_control_app_gids.db DESTINATION /opt/dbspace)
#INSTALL(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/udev/ DESTINATION lib/udev)
INSTALL(PROGRAMS ${CMAKE_CURRENT_SOURCE_DIR}/slp-su DESTINATION bin)

INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/db/rules-db.sql DESTINATION /opt/dbspace)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/db/rules-db-data.sql DESTINATION /opt/dbspace)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/db/load-rules-db.sql DESTINATION /opt/etc/smack/)

INSTALL(FILES ${PROJECT_SOURCE_DIR}/smack-rules.service
	DESTINATION /usr/lib/systemd/system
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

ADD_SUBDIRECTORY(api_feature_loader)
