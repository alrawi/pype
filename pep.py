from pep_def import *
from pymongo import MongoClient
from bson import binary
from timeout import timeout
import hashlib
import pefile
import peutils
import sys
import json
import re
import string
import datetime
import time
import base64
import zlib
import logging as lg
import ssdeep

def is_pe(fc):
    try:
        return pefile.PE(data=fc, fast_load=False)
    except:
        return False


def processMeta(pe,fc, profile):
    profile[PROFILE.STATIC][META.fileSize]=len(fc)
    profile[PROFILE.STATIC][META.timeStamp]=pe.FILE_HEADER.TimeDateStamp
    profile[PROFILE.STATIC][META.dll]=pe.FILE_HEADER.IMAGE_FILE_DLL
    profile[PROFILE.STATIC][META.numberSec]=pe.FILE_HEADER.NumberOfSections
    profile[PROFILE.STATIC][META.importHash]=pe.get_imphash()
    profile[PROFILE.STATIC][META.md5]=hashlib.md5(fc).hexdigest()
    profile[PROFILE.STATIC][META.sha1]=hashlib.sha1(fc).hexdigest()
    profile[PROFILE.STATIC][META.ssdeep]=ssdeep.hash(fc)
    return profile

def processPEHeader(pe, profile):
    try:
        profile[PROFILE.STATIC][PECOFF.arch]=pe.FILE_HEADER.Machine
        profile[PROFILE.STATIC][PECOFF.creationDate] =pe.FILE_HEADER.TimeDateStamp
        profile[PROFILE.STATIC][PECOFF.imageType] = pe.FILE_HEADER.Characteristics
        dwOptionalHeaderSize = pe.FILE_HEADER.SizeOfOptionalHeader
        if dwOptionalHeaderSize>0:
            profile[PROFILE.STATIC][PECOFF.linkerVerMajor] = pe.OPTIONAL_HEADER.MajorLinkerVersion
            profile[PROFILE.STATIC][PECOFF.linkerVerMinor] = pe.OPTIONAL_HEADER.MinorLinkerVersion
            profile[PROFILE.STATIC][PECOFF.baseAddr] = pe.OPTIONAL_HEADER.ImageBase
            profile[PROFILE.STATIC][PECOFF.entryPt] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if dwOptionalHeaderSize>24:
                profile[PROFILE.STATIC][PECOFF.minOSMajor] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
                profile[PROFILE.STATIC][PECOFF.minOSMinor] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
                profile[PROFILE.STATIC][PECOFF.imageVerMajor] = pe.OPTIONAL_HEADER.MajorImageVersion
                profile[PROFILE.STATIC][PECOFF.imageVerMinor] = pe.OPTIONAL_HEADER.MinorImageVersion
                profile[PROFILE.STATIC][PECOFF.subsysVerMajor] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
                profile[PROFILE.STATIC][PECOFF.subsysVerMinor] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
                profile[PROFILE.STATIC][PECOFF.peChksum] = pe.OPTIONAL_HEADER.CheckSum
                profile[PROFILE.STATIC][PECOFF.subsystem] = pe.OPTIONAL_HEADER.Subsystem
                profile[PROFILE.STATIC][PECOFF.imageSize] = pe.OPTIONAL_HEADER.SizeOfImage
    except:
        lg.warning(sys.exc_info())

    return profile

def processDirectories(pe, profile):
    #Exception Table
    try:
        pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION[0].struct
    except:
        try:
            pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION.struct
        except:
            try:
                pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION
            except:
                profile[PROFILE.STATIC][PECOFF.exceptTable] = False
    profile[PROFILE.STATIC][PECOFF.exceptTable] = True
    #Relocation Table
    try:
        pe.IMAGE_DIRECTORY_ENTRY_BASERELOC[0].struct
    except:
        try:
            pe.IMAGE_DIRECTORY_ENTRY_BASERELOC.struct
        except:
            try:
                pe.IMAGE_DIRECTORY_ENTRY_BASERELOC
            except:
                profile[PROFILE.STATIC][PECOFF.reloTable] = False
    profile[PROFILE.STATIC][PECOFF.reloTable] = True
    #Debug Table
    try:
        pe.IMAGE_DIRECTORY_ENTRY_DEBUG[0].struct
    except:
        try:
            pe.IMAGE_DIRECTORY_ENTRY_DEBUG.struct
        except:
            try:
                pe.IMAGE_DIRECTORY_ENTRY_DEBUG
            except:
                profile[PROFILE.STATIC][PECOFF.debugTable] = False
    profile[PROFILE.STATIC][PECOFF.debugTable] = True
    #TLS Table
    try:
        pe.IMAGE_DIRECTORY_ENTRY_TLS[0].struct
    except:
        try:
            pe.IMAGE_DIRECTORY_ENTRY_TLS.struct
        except:
            try:
                pe.IMAGE_DIRECTORY_ENTRY_TLS
            except:
                profile[PROFILE.STATIC][PECOFF.tlsTable] = False
    profile[PROFILE.STATIC][PECOFF.tlsTable] = True
    #Global Table
    try:
        pe.IMAGE_DIRECTORY_ENTRY_GLOBALPTR[0].struct
    except:
        try:
            pe.IMAGE_DIRECTORY_ENTRY_GLOBALPTR.struct
        except:
            try:
                pe.IMAGE_DIRECTORY_ENTRY_GLOBALPTR
            except:
                profile[PROFILE.STATIC][PECOFF.globalTable] = False
    profile[PROFILE.STATIC][PECOFF.globalTable] = True
    #Bound Table
    try:
        pe.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT[0].struct
    except:
        try:
            pe.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT.struct
        except:
            try:
                pe.IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
            except:
                profile[PROFILE.STATIC][PECOFF.boundTable] = False
    profile[PROFILE.STATIC][PECOFF.boundTable] = True
    #Delay Table
    try:
        pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT[0].struct
    except:
        try:
            pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT.struct
        except:
            try:
                pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
            except:
                profile[PROFILE.STATIC][PECOFF.delayTable] = False
    profile[PROFILE.STATIC][PECOFF.delayTable] = True
    #Com Table
    try:
        pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR[0].struct
    except:
        try:
            pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR.struct
        except:
            try:
                pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
            except:
                profile[PROFILE.STATIC][PECOFF.clrTable] = False
    profile[PROFILE.STATIC][PECOFF.clrTable] = True
    #Import Table
    try:
        imports = pe.DIRECTORY_ENTRY_IMPORT[0].struct
    except:
        try:
            imports = pe.DIRECTORY_ENTRY_IMPORT.struct
        except:
            try:
                imports = pe.DIRECTORY_ENTRY_IMPORT
            except:
                profile[PROFILE.STATIC][PECOFF.impTable] = False
    profile[PROFILE.STATIC][PECOFF.impTable] = True
    #Export Table
    try:
        exports = pe.DIRECTORY_ENTRY_EXPORT[0].struct
    except:
        try:
            exports = pe.DIRECTORY_ENTRY_EXPORT.struct
        except:
            try:
                exports = pe.DIRECTORY_ENTRY_EXPORT
            except:
                profile[PROFILE.STATIC][PECOFF.expTable] = False
    profile[PROFILE.STATIC][PECOFF.expTable] = True
    #Resource Table
    try:
        resources = pe.DIRECTORY_ENTRY_RESOURCE[0].struct
    except:
        try:
            resources = pe.DIRECTORY_ENTRY_RESOURCE.struct
        except:
            try:
                resources = pe.DIRECTORY_ENTRY_RESOURCE
            except:
                profile[PROFILE.STATIC][PECOFF.resTable] = False
    profile[PROFILE.STATIC][PECOFF.resTable] = True
    return profile

def processSections(pe, profile):
    try:
        profile[PROFILE.STATIC][PECOFF.peSections]
    except:
        profile[PROFILE.STATIC][PECOFF.peSections]=[]
    for sec in pe.sections:
        tmp={}
        tmp[PESEC.entropy]=sec.get_entropy()
        try:# try to use 7bit ascii first
            tmp[PESEC.name]=sec.Name
        except: # but if that fails, switch to 8bit ascii
            tmp[PESEC.name]=sec.Name.encode('utf-8')
        tmp[PESEC.md5]=sec.get_hash_md5()
        tmp[PESEC.sha1]=sec.get_hash_sha1()
        tmp[PESEC.virtualAddress]=hex(sec.VirtualAddress)
        tmp[PESEC.virtualSize]=hex(sec.Misc_VirtualSize)
        tmp[PESEC.sizeOfRawData]=hex(sec.SizeOfRawData)
        if tmp[PESEC.sizeOfRawData]==0 or (tmp[PESEC.entropy]>0 and tmp[PESEC.entropy]<1) or tmp[PESEC.entropy]>7:
            tmp[PESEC.suspicious]=True
        else:
            tmp[PESEC.suspicious]=False
        profile[PROFILE.STATIC][PECOFF.peSections].append(tmp)

    return profile

def processImports(pe, profile):
    impList={}
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll[:-4]
            if dll not in impList.keys():
                impList[dll]=[]
            for imp in entry.imports:
                function = imp.name
                impList[dll].append(function)

        profile[PROFILE.STATIC][PECOFF.imports]=impList
    except:
        lg.warning(sys.exc_info())
    return profile

def processExports(pe, profile):
    expList=[]
    try:
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            expList.append(exp.name)
        profile[PROFILE.STATIC][PECOFF.exports]=expList
    except:
        lg.warning(sys.exc_info())
    return profile

def processSummaryInfo(pe,profile):
    profile[PROFILE.STATIC][PECOFF.versionInfo]={}
    try:
        for e in pe.FileInfo[0].StringTable[0].entries.items():
            profile[PROFILE.STATIC][PECOFF.versionInfo][e[0]]=e[1]
    except:
        lg.warning(sys.exc_info())
    return profile

def processPEiD(pe, profile):
    signatures = peutils.SignatureDatabase(fn_userdb)
    profile[PROFILE.STATIC][PECOFF.peid]=[]
    try:
        for entry in signatures.match_all(pe,ep_only = True):
            profile[PROFILE.STATIC][PECOFF.peid].append(entry[0])
    except:
        lg.info("no packer info found")
    return profile

def processAntiVM(sfile, profile):
    # Credit: Joxean Koret
    trk     = []
    VM_Str  = {
        "Virtual Box":"VBox",
        "VMware":"WMvare"
    }
    VM_Sign = {
        "Red Pill":"\x0f\x01\x0d\x00\x00\x00\x00\xc3",
        "VirtualPc trick":"\x0f\x3f\x07\x0b",
        "VMware trick":"VMXh",
        "VMCheck.dll":"\x45\xC7\x00\x01",
        "VMCheck.dll for VirtualPC":"\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
        "Xen":"XenVMM",
        "Bochs & QEmu CPUID Trick":"\x44\x4d\x41\x63",
        "Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
        "Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
        }
    buf = sfile
    for string in VM_Str:
        match = re.findall(VM_Str[string], buf, re.IGNORECASE | re.MULTILINE)
        if match:
            trk.append(string)
    for trick in VM_Sign:
        if buf.find(VM_Sign[trick][::-1]) > -1:
            trk.append(trick)
    
    profile[PROFILE.STATIC][PECOFF.vm]=trk
    return profile

#helper function to extract strings
def get_string(data):
    printable = set(string.printable)
    found_str = ""
    if data:
        for char in data:
            if char in printable:
                found_str += char
            elif len(found_str) >= 4:
                yield found_str
                found_str = ""
            else:
                found_str = ""

# Check url and file name
def processFileUrl(fc, profile):
    array          = [] # word raw
    arrayURL       = [] # url
    arrayFILE      = [] # file raw
    arrayFileNames = [] # description and file name

    for found_str in get_string(fc):
        fname = re.findall("(.+\.([a-z]{2,3}$))+", found_str, re.IGNORECASE | re.MULTILINE)
        if fname:
            word = fname[0][0]
            #we found a pdb file
            if len(word) >7 and '.pdb' in word:
                profile[PROFILE.STATIC][PECOFF.pdb]=word
            array.append(word)
            
    for elem in sorted(set(array)):
        match = re.search("^http:|^ftp:|^sftp:|^ssh:|^www|.com$|.org$|.it$|.co.uk$|.ru$|.jp$|.net$|.ly$|.gl$|^([0-9]{1,3})(?:\.[0-9]{1,3}){3}$", elem, re.IGNORECASE)
        if match and len(elem) > 6: # len(c.it) = 4 <- false positive
            arrayURL.append(elem)
        else:
            arrayFILE.append(elem)

    for elem in sorted(set(arrayFILE)):
        file_type = {
            "Video":".3gp",
            "Compressed":".7z",
            "Video":".asf",
            "Web Page":".asp",
            "Web Page":".aspx",
            "Video":".asx",
            "Video":".avi",
            "Backup":".bak",
            "Binary":".bin",
            "Image":".bmp",
            "Cabinet":".cab",
            "Data":".dat",
            "Database":".db",
            "Word":".doc",
            "Word":".docx",
            "Library":".dll",
            "Autocad":".dwg",
            "Executable":".exe",
            "Email":".eml",
            "Video":".flv",
            "FTP Config":".ftp",
            "Image":".gif",
            "Compressed":".gz",
            "Web Page":".htm",
            "Web Page":".html",
            "Disc Image":".iso",
            "Log":".log",
            "Archive Java":".jar",
            "Image":".jpg",
            "Image":".jepg",
            "Audio":".mp3",
            "Video":".mp4",
            "Video":".mpg",
            "Video":".mpeg",
            "Video":".mov",
            "Installer":".msi",
            "Object":".oca",
            "Object":".ocx",
            "Autogen":".olb",
            "Backup":".old",
            "Registry":".reg",
            "Debug":".pdb",
            "Portable":".pdf",
            "Web Page":".php",
            "Image":".png",
            "Slideshow":".pps",
            "Presentation":".ppt",
            "Image":".psd",
            "Email":".pst",
            "Document":".pub",
            "Compressed":".rar",
            "Text":".rtf",
            "Query DB":".sql",
            "Adobe Flash":".swf",
            "Image":".tif",
            "Temporary":".tmp",
            "Text":".txt",
            "Compressed":".tgz",
            "Audio":".wav",
            "Audio":".wma",
            "Video":".wmv",
            "Excel":".xls",
            "Excel":".xlsx",
            "Compressed":".zip"
        }

        for descr in file_type:
            match = re.search(file_type[descr]+"$", elem, re.IGNORECASE)
            if match:
                arrayFileNames.append(elem)
    for itm in arrayURL:
        arrayFileNames.append(itm)
    profile[PROFILE.STATIC][PECOFF.strings]=arrayFileNames
    return profile

fn_userdb='dbs/userdb.txt'
@timeout(300)
def processFile(fc,fn):
    st=time.time()
    lg.info("Meta data extraction starting for file %s"%(fn))
    pe=is_pe(fc)
    if not pe:
        lg.info("File not PE skipping")
        return False

    g_profile={
        PROFILE.STATIC:{}
    }
    g_profile=processMeta(pe, fc, g_profile)
    g_profile=processPEHeader(pe,g_profile)
    g_profile=processDirectories(pe,g_profile)
    g_profile=processSections(pe,g_profile)
    g_profile=processImports(pe,g_profile)
    g_profile=processExports(pe,g_profile)
    g_profile=processSummaryInfo(pe,g_profile)
    g_profile=processPEiD(pe,g_profile)
    g_profile=processAntiVM(fc, g_profile)
    g_profile=processFileUrl(fc, g_profile)
    g_profile[PROFILE.STATIC][META.fileName]=fn
    g_profile[PROFILE.STATIC][META.procDate]=datetime.datetime.utcnow()
    lg.info("Metadata extractoin complete in %f sec"%(time.time()-st))

    #insert into DB
    st=time.time()
    client=MongoClient('10.2.4.34',27017)
    clc=client.malware.meta
    lg.info("inserting meta data ObjectId is %s"%(str(clc.insert(g_profile))))
    clc=client.malware.bins
    binData=binary.Binary(base64.b64encode(zlib.compress(fc)))
    #inserting into binary collection
    lg.info("inserting binary ObjectId is %s"%(str(clc.insert({META.md5:g_profile[PROFILE.STATIC][META.md5],'d':binData}))))
    lg.info("Presisted binary and metadata in %f sec"%(time.time()-st))
    return True
