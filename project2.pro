QT += core
QT -= gui

CONFIG += c++11

TARGET = sample1
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp

INCLUDEPATH  += C:/WpdPack/Include
INCLUDEPATH  += "C:\Program Files (x86)\Windows Kits\10\Include\10.0.10240.0\ucrt"

LIBS += -lC:/WpdPack/Lib/x64/wpcap
LIBS += -lWs2_32
LIBS += -l"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.10240.0\ucrt\x64\ucrtd"

HEADERS += \
    packetheader.h
