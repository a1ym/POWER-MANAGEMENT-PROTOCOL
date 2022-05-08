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
    packetFlags = "1100" #Connection opened, SYN and AUTH bits are set to 1
    sentData = {"pub_key": serverPubKey}
    sentData = json.dumps(sentData)
    packet = constructPacket(sentData, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), None)
    s.sendto(packet, clientAddress)
    checkSum, flags, data, seqNum = unpackPacket(clientPubKey)
    clientPubKey = json.loads(data)["pub_key"]
    serverSharedKey = server.gen_shared_key(clientPubKey)
    while True:
        listen(serverSharedKey)
        
#Construct packet by combining data, packet flags and sequence number.
def constructPacket(data, packetFlags, seqNum, key):
    header = int(packetFlags + seqNum, 2)
    if key != None:
        data = aesEncrypt(data, key) #encrypting the data
    else:
        data = data.encode()
    packet = bytes.fromhex(format(header, "04x")) + data
    checkSum = zlib.crc32(packet).to_bytes(4, byteorder="big")
    packet = checkSum + packet
    return packet

#Unpack the packet and verify data through checksum
def unpackPacket(packet):
    checkSum = packet[0:4]
    header = format(int.from_bytes(packet[4:6], byteorder="big"), "016b")
    flags = header[:4]
    seqNum = int(header[4:], 2)
    data = packet[6:]
    checkSumData = packet[4:]
    checkSumVerify = zlib.crc32(checkSumData).to_bytes(4, byteorder="big")
    if checkSum != checkSumVerify:
        sentData = {"err": "Checksum error"}
        sentData = json.dumps(sentData)
        return(sentData)
    else:
        sentData = {"ok": "Checksum verified"}
        sentData = json.dumps(sentData)
        print(sentData)
    return checkSum, flags, data, seqNum

#Recieve data from client and send a response 
def listen(serverSharedKey):
    message, clientAddress = s.recvfrom(bufferSize)
    checksum, flags, data, seqNum = unpackPacket(message)
    final = aesDecrypt(data, serverSharedKey)
    global SEQ_NUM
    packetFlags = "0100"
    SEQ_NUM += 1
    cmd = json.loads(final)["cmd"]
    if cmd == "PWR_STAT":
        battery = psutil.sensors_battery() #I don't have a laptop to test or output the battery percentage
        if battery == None: 
            response = json.dumps({"ok": "NONE"})
        else:
            response = json.dumps({"ok": "Battery present"})
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(packet, clientAddress)
    elif cmd == "BTRY_LVL":
        battery = psutil.sensors_battery() #I don't have a laptop to test or output the battery percentage
        if battery == None: 
            response = json.dumps({"ok": "NONE"})
        else:
            response = json.dumps({"ok": "Battery present"})
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(packet, clientAddress)
    elif cmd == "SUSPND":
        proc = PID #enter valid process id
        try:
            psutil.Process(pid=proc).suspend()
            response = json.dumps({"ok": "Process is being suspended..."})
        except Exception as exc:
            print(exc)
            response = json.dumps({"ok": "Process has failed to suspend"})
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(packet, clientAddress)
    elif cmd == "REBOOT":
        response = json.dumps({"ok": "System is beeing restarted..."})
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(packet, clientAddress)
        os.system("shutdown /r /t 20")
    elif cmd == "PWROFF":
        response = json.dumps({"ok": "System is beeing powered off..."})
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(packet, clientAddress)
        os.system("shutdown /s /t 20")
    elif cmd == "END_CONN":
        response = json.dumps({"ok": "Closing connection..."})
        packet = constructPacket(response, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), serverSharedKey)
        s.sendto(packet, clientAddress)
        time.sleep(20)
        s.close()
        exit()
    
#Decryption of packet data
def aesDecrypt(data, key):
    key = hashlib.sha256(key.encode()).digest()
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

diffieHellman()
