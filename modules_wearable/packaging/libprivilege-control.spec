#%define udev_libdir /usr/lib/udev

Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.66.SLP
Release:    1
Group:      System/Security
License:    Apache 2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    %{name}.manifest
Source2:    %{name}-conf.manifest
Source3:    smack-default-labeling.service
BuildRequires: cmake
%if ("%{sec_build_project_name}" == "redwood8974_jpn_dcm") || ("%{sec_build_project_name}" == "redwood8974_eur_open")
#!BuildIgnore: kernel-headers
BuildRequires: kernel-headers-3.4-msm8974
%define seccomp_enabled 1
%endif
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
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif

export CFLAGS="${CFLAGS} -Wno-implicit-function-declaration"
%cmake . -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
         -DCMAKE_VERBOSE_MAKEFILE=ON %{?seccomp_enabled:-DSECCOMP_ENABLED=ON}

VERBOSE=1 make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/%{name}-conf
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

%post
if [ ! -e "/home/app" ]
then
        mkdir -p /home/app
fi

if [ ! -e "/home/developer" ]
then
        mkdir -p /home/developer
fi

chown 5000:5000 /home/app
chmod 755 /home/app
chown 5100:5100 /home/developer
chmod 755 /home/developer

if [ ! -e "/smack" ]
then
	mkdir /smack
fi
touch /smack/load2

if [ ! -e "/opt/etc/smack-app/accesses.d" ]
then
	mkdir -p /opt/etc/smack-app/accesses.d
fi

if [ ! -e "/opt/etc/smack-app-early/accesses.d" ]
then
	mkdir -p /opt/etc/smack-app-early/accesses.d
fi

if [ ! -e "/opt/dbspace" ]
then
    mkdir -p /opt/dbspace
    chown 0:5000 /opt/dbspace
    chmod 775 /opt/dbspace
fi

/usr/share/privilege-control/db/updater.sh

api_feature_loader --verbose --dir=/usr/share/privilege-control/
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
#link to activate systemd service
/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service
/usr/share/privilege-control/db/rules-db.sql
/usr/share/privilege-control/db/rules-db-data.sql
/usr/share/privilege-control/db/updater.sh
/usr/share/privilege-control/db/updates/*
/usr/share/privilege-control/db/load-rules-db.sql
/etc/opt/upgrade/220.libprivilege-updater.patch.sh

%files conf
%attr(755,root,root) /etc/rc.d/*
/usr/lib/systemd/system/smack-default-labeling.service
/usr/lib/systemd/system/multi-user.target.wants/smack-default-labeling.service
%manifest %{_datadir}/%{name}-conf.manifest
%{_datadir}/license/%{name}-conf
/opt/dbspace/.privilege_control*.db

%files devel
%{_includedir}/*.h
%{_libdir}/libprivilege-control.so
%{_libdir}/pkgconfig/*.pc
