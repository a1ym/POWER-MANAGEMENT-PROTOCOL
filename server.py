import socket
import pyDH
import psutil
import traceback
import zlib
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import json

PID = 999999 #Enter a valid process ID
SEQ_NUM = 0
address = ("127.0.0.1", 4444)
bufferSize = 4096
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(address)

#Negotiation of shared secret with client
def diffieHellman():
    modp = 14
    server = pyDH.DiffieHellman(group = modp)
    serverPubKey = server.gen_public_key()
    print("Waiting for client to connect...")
    clientPubKey, clientAddress = s.recvfrom(bufferSize)
    global SEQ_NUM
    SEQ_NUM += 1
    packetFlags = "1001" #Connection opened, SYN and AUTH bits are set to 1
    packet = constructPacket(str(bin(serverPubKey)[2:]), packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), None)
    s.sendto(repr(packet).encode('utf-8'), clientAddress)
    checkSum, flags, data, seqNum = unpackPacket(clientPubKey)
    clientPubKey = int(str(data)[2:-2], 2)
    serverSharedKey = server.gen_shared_key(clientPubKey)
    while True:
        listen(serverSharedKey)
        
#Construct packet by combining data, packet flags and sequence number.
def constructPacket(data, packetFlags, seqNum, key):
    header = packetFlags + seqNum
    if key != None:
        data = aesEncrypt(data, key)
        data = bytesToBits(data)
    packet = header + data
    checkSum = zlib.crc32(bin(int(packet, base=2)).encode()) # convert packet to binary
    checkSum = str(bin(checkSum))[2:].zfill(32)
    packet = checkSum + packetFlags + seqNum + data
    return packet

#Unpack the packet and verify data through checksum
def unpackPacket(packet):
    checkSum = packet[0:33]
    flags = packet[33:37]
    seqNum = packet[37:49]
    data = packet[49:]
    checkSumData = flags + seqNum + data
    checkSumData = str(checkSumData)[2:-2]
    checkSumVerify = zlib.crc32(bin(int(checkSumData, base=2)).encode()) # convert packet to binary
    checkSumVerify = str(bin(checkSumVerify))[2:].zfill(32)
    if str(checkSum)[3:-1] != checkSumVerify:
        sentData = {'err': 'Checksum error'}
        sentData = json.dumps(sentData)
        return(sentData)
    else:
        sentData = {'ok': 'Checksum verified'}
        sentData = json.dumps(sentData)
        print(sentData)
    return checkSum, flags, data, seqNum

#Recieve data from client and send a response 
def listen(serverSharedKey):
    message, clientAddress = s.recvfrom(bufferSize)
    checksum, flags, data, seqNum = unpackPacket(message)
    data = str(data)[2:-2]
    final = aesDecrypt(data, serverSharedKey)
    global SEQ_NUM
    packetFlags = "0100"
    SEQ_NUM += 1
    if str(final)[2:-1] == "0000":
        battery = psutil.sensors_battery() #I don't have a laptop to test or output the battery percentage
        if battery == None: 
            response ="0000"
        else:
            response = "0001"
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(repr(packet).encode('utf-8'), clientAddress)
    elif str(final)[2:-1] == "0010":
        battery = psutil.sensors_battery() #I don't have a laptop to test or output the battery percentage
        if battery == None: 
            response ="0010"
        else:
            response = "0011"
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(repr(packet).encode('utf-8'), clientAddress)
    elif str(final)[2:-1] == "0100":
        proc = PID #enter valid process id
        try:
            psutil.Process(pid=proc).suspend()
            response = "0100"
        except Exception as exc:
            print(exc)
            response = "0101"
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(repr(packet).encode('utf-8'), clientAddress)
    elif str(final)[2:-1] == "0110":
        response = "0110"
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(repr(packet).encode('utf-8'), clientAddress)
        os.system("shutdown /r /t 20")
    elif str(final)[2:-1] == "0111":
        response = "0111"
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(repr(packet).encode('utf-8'), clientAddress)
        os.system("shutdown /s /t 20")
    elif str(final)[2:-1] == "1000":
        response = "1000"
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(repr(packet).encode('utf-8'), clientAddress)
        time.sleep(20)
        s.close()
        exit()
    
#Decryption of packet data
def aesDecrypt(data, key):
    key = hashlib.sha256(key.encode()).digest()
    y = 1
    currentBit = ""
    results = []
    for i in str(data):
        currentBit = currentBit + i
        if y % 8 == 0:
            results.append(int(currentBit, base=2))
            currentBit = ""
        y += 1
    data = bytes(results)
    iv = data[-16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[:-16]), 16)

#Encryption of packet data (excludint headers)
def aesEncrypt(data, sharedKey):
    sharedKey = sharedKey.encode()
    key = hashlib.sha256(sharedKey).digest()
    mode = AES.MODE_CBC
    cipher = AES.new(key, mode)
    data = cipher.encrypt(pad(data.encode(), 16)) + cipher.iv
    return data

def bytesToBits(bytesList):
    results = ""
    for i in bytesList:
        results += str(bin(int(i))[2:]).zfill(8)    
    return results

diffieHellman()
