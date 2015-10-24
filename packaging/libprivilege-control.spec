#%define udev_libdir /usr/lib/udev

Name:       libprivilege-control
Summary:    Library to control privilege of application
Version:    0.0.93
Release:    1
Group:      System/Security
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    %{name}.manifest
BuildRequires: cmake
BuildRequires: libcap-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(security-server)

%description
development package of library to control privilege of in-house application

%package devel
Summary:    Control privilege of application (devel)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}
Requires: pkgconfig(libsmack)
Requires: pkgconfig(security-server)

%description devel
Library to control privilege of application (devel)


%prep
%setup -q

%build
%if "%{?tizen_profile_name}" == "wearable"
        __PROFILE_TYPE="WEARABLE"
%else
%if "%{?tizen_profile_name}" == "tv"
        __PROFILE_TYPE="WEARABLE"
%else
%if "%{?tizen_profile_name}" == "mobile"
        __PROFILE_TYPE="MOBILE"
%endif
%endif
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

mkdir -p %{buildroot}/home/app
mkdir -p %{buildroot}/home/developer
mkdir -p %{buildroot}/home/system

%files
%{_libdir}/*.so.*
%{_bindir}/slp-su
%manifest %{_datadir}/%{name}.manifest
#%{udev_libdir}/rules.d/*
#%attr(755,root,root) %{udev_libdir}/uname_env
%{_datadir}/license/%{name}
%attr(755, app, app) %dir /home/app
%attr(755, developer, developer) %dir /home/developer

%files devel
%{_includedir}/*.h
%{_libdir}/libprivilege-control.so
%{_libdir}/pkgconfig/*.pc
