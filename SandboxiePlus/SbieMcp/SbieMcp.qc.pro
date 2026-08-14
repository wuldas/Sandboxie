TEMPLATE = app
TARGET = SbieMcp

QT += core
CONFIG += console
CONFIG -= app_bundle

CONFIG(release, debug|release): {
  QMAKE_CXXFLAGS_RELEASE = $$QMAKE_CFLAGS_RELEASE_WITH_DEBUGINFO
  QMAKE_LFLAGS_RELEASE = $$QMAKE_LFLAGS_RELEASE_WITH_DEBUGINFO
}

MY_ARCH=$$(build_arch)
equals(MY_ARCH, ARM64) {
  CONFIG(debug, debug|release):LIBS += -L../Bin/ARM64/Debug
  CONFIG(release, debug|release):LIBS += -L../Bin/ARM64/Release
  CONFIG(debug, debug|release):DESTDIR = ../Bin/ARM64/Debug
  CONFIG(release, debug|release):DESTDIR = ../Bin/ARM64/Release
} else:equals(MY_ARCH, x64) {
  CONFIG(debug, debug|release):LIBS += -L../Bin/x64/Debug
  CONFIG(release, debug|release):LIBS += -L../Bin/x64/Release
  CONFIG(debug, debug|release):DESTDIR = ../Bin/x64/Debug
  CONFIG(release, debug|release):DESTDIR = ../Bin/x64/Release
} else {
  CONFIG(debug, debug|release):LIBS += -L../Bin/Win32/Debug
  CONFIG(release, debug|release):LIBS += -L../Bin/Win32/Release
  CONFIG(debug, debug|release):DESTDIR = ../Bin/Win32/Debug
  CONFIG(release, debug|release):DESTDIR = ../Bin/Win32/Release
}

LIBS += -lQSbieAPI -lNtdll -lAdvapi32 -lOle32 -lUser32 -lShell32 -lGdi32

INCLUDEPATH += . ../QSbieAPI
DEPENDPATH += . ../QSbieAPI

SOURCES += main.cpp
