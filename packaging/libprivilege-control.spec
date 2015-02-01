#%define udev_libdir /usr/lib/udev

Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.89
Release:    1
Group:      System/Security
License:    Apache 2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    %{name}.manifest
Source2:    %{name}-conf.manifest
Source3:    smack-default-labeling.service
BuildRequires: cmake
BuildRequires: libcap-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(libiri)
BuildRequires: pkgconfig(sqlite3)
Requires:   smack-privilege-config
Requires:   sqlite

%description
development package of library to control privilege of in-house application

%package devel
Summary:    Control privilege of application (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
Requires: pkgconfig(libsmack)

%description devel
Library to control privilege of application (devel)

%package conf
Summary:    Control privilege of application files
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
Requires:   /usr/bin/chsmack

%description conf
Library to control privilege of application files


%prep
%setup -q

%build
%if %{?tizen_profile_name} == "wearable"
        __PROFILE_TYPE="WEARABLE"
%elseif %{?tizen_profile_name} == "mobile"
        __PROFILE_TYPE="MOBILE"
%endif

export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
export CFLAGS="${CFLAGS} -Wno-implicit-function-declaration"

%cmake . -DCMAKE_VERBOSE_MAKEFILE=ON %{?seccomp_enabled:-DSECCOMP_ENABLED=ON} \
         -DPROFILE_TYPE="${__PROFILE_TYPE}"

VERBOSE=1 make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
%make_install
cp -a %{SOURCE1} %{buildroot}%{_datadir}/
cp -a %{SOURCE2} %{buildroot}%{_datadir}/
#install -D -d %{buildroot}/etc/rc.d/rc3.d/
#install -D -d %{buildroot}/etc/rc.d/rc4.d/
#ln -sf ../init.d/smack_default_labeling %{buildroot}/etc/rc.d/rc3.d/S44smack_default_labeling
#ln -sf ../init.d/smack_default_labeling %{buildroot}/etc/rc.d/rc4.d/S44smack_default_labeling
mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
ln -sf /usr/lib/systemd/system/smack-rules.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service

mkdir -p %{buildroot}/usr/lib/systemd/system/tizen-runtime.target.wants
install -m 644 %{SOURCE3} %{buildroot}/usr/lib/systemd/system/
ln -s /usr/lib/systemd/system/smack-default-labeling.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-default-labeling.service

mkdir -p %{buildroot}/smack
mkdir -p %{buildroot}/opt/etc/smack-app/accesses.d
mkdir -p %{buildroot}/opt/etc/smack-app-early/accesses.d
mkdir -p %{buildroot}/opt/dbspace
mkdir -p %{buildroot}/home/app
mkdir -p %{buildroot}/home/developer

%post
touch /smack/load2

/usr/share/privilege-control/db/updater.sh

api_feature_loader --verbose --clear-permissions
api_feature_loader --verbose --rules=/usr/share/privilege-control/ADDITIONAL_RULES.smack

%check
./db/updater.sh --check-files %{buildroot}

%files
%{_libdir}/*.so.*
%{_libdir}/librules-db-sql-udf.so
%{_bindir}/slp-su
%manifest %{_datadir}/%{name}.manifest
#%{udev_libdir}/rules.d/*
#%attr(755,root,root) %{udev_libdir}/uname_env
%{_datadir}/license/%{name}
#systemd service
/usr/lib/systemd/system/smack-rules.service
/usr/bin/api_feature_loader
/usr/bin/smack_rules_buffer
#link to activate systemd service
/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service
/usr/share/privilege-control/db/rules-db.sql
/usr/share/privilege-control/db/rules-db-data.sql
/usr/share/privilege-control/db/updater.sh
/usr/share/privilege-control/db/updates/*.sql
/usr/share/privilege-control/db/load-rules-db.sql
/etc/opt/upgrade/220.libprivilege-updater.patch.sh
%dir /smack
%dir /opt/etc/smack-app/accesses.d
%dir /opt/etc/smack-app-early/accesses.d
%attr(755, root, app) %dir /opt/dbspace
%attr(755, app, app) %dir /home/app
%attr(755, developer, developer) %dir /home/developer

%files conf
%attr(755,root,root) /etc/rc.d/*
/usr/lib/systemd/system/smack-default-labeling.service
/usr/lib/systemd/system/multi-user.target.wants/smack-default-labeling.service
%manifest %{_datadir}/%{name}-conf.manifest

%files devel
%{_includedir}/*.h
%{_libdir}/libprivilege-control.so
%{_libdir}/pkgconfig/*.pc
