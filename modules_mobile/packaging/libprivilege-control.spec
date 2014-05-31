#%define udev_libdir /usr/lib/udev

Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.43.TIZEN
Release:    1
Group:      System/Security
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    %{name}-conf.manifest
Source2:    smack-default-labeling.service
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
Requires:   pkgconfig(libsmack)

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
export CFLAGS="${CFLAGS} -Wno-implicit-function-declaration"
%cmake . -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
         -DCMAKE_VERBOSE_MAKEFILE=ON

VERBOSE=1 make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/%{name}-conf
cp LICENSE %{buildroot}/usr/share/license/%{name}-devel
%make_install

mkdir -p %{buildroot}/etc
mv %{buildroot}/opt/etc/passwd %{buildroot}/etc/passwd
mv %{buildroot}/opt/etc/group %{buildroot}/etc/group

cp -a %{SOURCE1} %{buildroot}%{_datadir}/
cp -a %{SOURCE2} %{buildroot}%{_datadir}/

mkdir -p %{buildroot}/usr/lib/systemd/system/basic.target.wants
install -m 644 %{SOURCE2} %{buildroot}/usr/lib/systemd/system/
ln -s ../smack-default-labeling.service %{buildroot}/usr/lib/systemd/system/basic.target.wants/

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
ln -sf /usr/lib/systemd/system/smack-rules.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service

mkdir -p %{buildroot}/usr/lib/systemd/system/tizen-runtime.target.wants
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


if [ ! -e "/opt/etc/smack-app/accesses.d" ]
then
	mkdir -p /opt/etc/smack-app/accesses.d
fi

if [ ! -e "/opt/etc/smack-app-early/accesses.d" ]
then
	mkdir -p /opt/etc/smack-app-early/accesses.d
fi

sqlite3 /opt/dbspace/.rules-db.db3 < /opt/dbspace/rules-db.sql
rm -f /opt/dbspace/rules-db.sql

sqlite3 /opt/dbspace/.rules-db.db3 < /opt/dbspace/rules-db-data.sql
rm -f /opt/dbspace/rules-db-data.sql

api_feature_loader --verbose --dir=/usr/share/privilege-control/
api_feature_loader --verbose --rules=/usr/share/privilege-control/ADDITIONAL_RULES.smack

%files
%{_libdir}/*.so.*
%{_libdir}/librules-db-sql-udf.so
%{_bindir}/slp-su
#%{udev_libdir}/rules.d/*
#%attr(755,root,root) %{udev_libdir}/uname_env
/usr/share/license/%{name}
#systemd service
/usr/lib/systemd/system/smack-rules.service
/usr/bin/api_feature_loader
#link to activate systemd service
/usr/lib/systemd/system/multi-user.target.wants/smack-rules.service
/opt/dbspace/rules-db.sql
/opt/dbspace/rules-db-data.sql
/opt/etc/smack/load-rules-db.sql

%files conf
/etc/group
/etc/passwd
%attr(755,root,root) /etc/rc.d/*
/usr/share/smack-default-labeling.service
/usr/lib/systemd/system/smack-default-labeling.service
/usr/lib/systemd/system/basic.target.wants/smack-default-labeling.service
/usr/lib/systemd/system/multi-user.target.wants/smack-default-labeling.service
%manifest %{_datadir}/%{name}-conf.manifest
/opt/dbspace/.privilege_control*.db
/usr/share/license/%{name}-conf

%files devel
%{_includedir}/*.h
%{_libdir}/libprivilege-control.so
%{_libdir}/pkgconfig/*.pc
/usr/share/license/%{name}-devel
