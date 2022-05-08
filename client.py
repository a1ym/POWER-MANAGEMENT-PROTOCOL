import socket
import zlib
import pyDH
import time
import hashlib
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

TIMEOUT = 60
bufferSize = 4096
SEQ_NUM = 0
SERVER_IP = "127.0.0.1"
SERVER_PORT = 4444


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(TIMEOUT)


#Negotiation of shared secret with server
def diffieHellman():
    modp = 14
    global SEQ_NUM
    client = pyDH.DiffieHellman(group = modp)
    clientPubKey = client.gen_public_key()
    SEQ_NUM += 1
    packetFlags = "1001" #Connection opened, SYN and AUTH bits are set to 1
    packet = constructPacket(str(bin(clientPubKey)[2:]), packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), None)
    s.sendto(repr(packet).encode('utf-8'), (SERVER_IP, SERVER_PORT))
    sentData = {'modp_id': modp, 'pub_key': clientPubKey}
    sentData = json.dumps(sentData)
    print(sentData)
    #Retransmit packet on response timeout
    try:
        checksum, flags, data, seqNum = recievePacket(None)
        serverPubKey = int(str(data)[2:-2], 2)
        clientSharedKey = client.gen_shared_key(serverPubKey)
        return clientSharedKey
    except:
        err = { "err": "Socket timed out. Re-transmitting packet." }
        err = json.dumps(err)
        print(err)
        print("Retrying...")
        time.sleep(3)
        diffieHellman()
       

#Construct packet by combining data, packet flags and sequence number.
def constructPacket(data, packetFlags, seqNum, key):
    header = packetFlags + seqNum
    if key != None:
        data = aesEncrypt(data, key) #encrypting the data
        data = bytesToBits(data)
    packet = header + data
    checkSum = zlib.crc32(bin(int(packet, base=2)).encode())
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

#Encryption of packet data (excluding headers)
def aesEncrypt(data, sharedKey):
    sharedKey = sharedKey.encode()
    key = hashlib.sha256(sharedKey).digest()
    mode = AES.MODE_CBC
    cipher = AES.new(key, mode)
    data = cipher.encrypt(pad(data.encode(), 16)) + cipher.iv
    print("Encrypted Data: " + str(data[:10]) + "...")
    return data

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

#Send commands to server and recieve response
def sendCommand(command, key):
    global SEQ_NUM
    packetFlags = "0000"
    SEQ_NUM += 2
    packet = constructPacket(command, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), key)
    s.sendto(repr(packet).encode('utf-8'), (SERVER_IP, SERVER_PORT))
    #Retransmit packet on response timeout
    try:
        recievePacket(key)
    except:
        err = { "err": "Socket timed out. Re-transmitting packet." }
        err = json.dumps(err)
        print(err)
        print("Retrying...")
        time.sleep(3)
        sendCommand(command, key)
        
def bytesToBits(bytesList):
    results = ""
    for i in bytesList:
        results += str(bin(int(i))[2:]).zfill(8)    
    return results

#Recieve and ouput a packet
def recievePacket(key):
    packet, serverAddress = s.recvfrom(bufferSize)
    checksum, flags, data, seqNum = unpackPacket(packet)
    print("SYN: " + str(flags)[2], "RES: " + str(flags)[3], "CRP: " + str(flags)[4], "AUTH: " + str(flags)[5])
    print("SEQ " + str(int(seqNum, 2)))
    if key != None:
        data = str(data)[2:-2]
        data = aesDecrypt(data, key)
    if str(data) == str(b'0000'):
        recievedData = { "ok": "NONE" }
        recievedData = json.dumps(recievedData)
        print("DATA: ", recievedData)
    elif str(data) == str(b'0001'):
        recievedData = { "ok": "Battery present" } #I don't have a laptop to test or output the battery percentage
        recievedData = json.dumps(recievedData)
        print("DATA: ", recievedData)
    elif str(data) == str(b'0010'):
        recievedData = { "ok": "NONE" }
        recievedData = json.dumps(recievedData)
        print("DATA: ", recievedData)
    elif str(data) == str(b'0011'):
        recievedData = { "ok": "Battery present" } #I don't have a laptop to test or output the battery percentage
        recievedData = json.dumps(recievedData)
        print("DATA: ", recievedData)
    elif str(data) == str(b'0100'):
        recievedData = { "ok": "Process is being suspended..." } #A valid process ID must be entered
        recievedData = json.dumps(recievedData)
        print("DATA: ", recievedData)
    elif str(data) == str(b'0101'):
        recievedData = { "err": "Process has failed to suspend" }
        recievedData = json.dumps(recievedData)
        print("DATA: ", recievedData)
    elif str(data) == str(b'0110'):
        recievedData = { "ok": "System is beeing restarted..." }
        recievedData = json.dumps(recievedData)
        print("DATA: ", recievedData)
    elif str(data) == str(b'0111'):
        recievedData = { "ok": "System is beeing powered off..." }
        recievedData = json.dumps(recievedData)
        print("DATA: ", recievedData)
    elif str(data) == str(b'1000'):
        recievedData = { "ok": "Closing connection..." }
        recievedData = json.dumps(recievedData)
        print("DATA: ", recievedData)
    return checksum, flags, data, seqNum

#Let user send commands to server, recieve and output the response from server
def main():
    try:
        s.connect((SERVER_IP, SERVER_PORT))
    except:
        recievedData = { "err": "Timedout: failed to connect to server. Please try again." }
        recievedData = json.dumps(recievedData)
        print(recievedData)
        exit()
    print("""
PWR_STAT - Return power status: Charging, On battery power, etc.
BTRY_LVL - Return battery percentage or NONE.
SUSPND - Acknowledge request and wait for 20 sec before suspending.
REBOOT - Acknowledge request and wait for 20 sec before rebooting.
PWROFF - Acknowledge request and wait for 20 sec before powering off.
END_CONN - Acknowledge request and wait for 20 sec before closing the connection.
\n\n""")
    key = diffieHellman()
    while True:
        option = input("::: ")
        if option == "PWR_STAT":
            sendCommand("0000", key)
        elif option == "BTRY_LVL":
            sendCommand("0010", key)
        elif option == "SUSPND":
            sendCommand("0100", key)
        elif option == "REBOOT":
            sendCommand("0110", key)
        elif option == "PWROFF":
            sendCommand("0111", key)
        elif option == "END_CONN":
            sendCommand("1000", key)
            time.sleep(20)
            exit()
        
        else:
            err = { "err": "Wrong command entered" }
            err = json.dumps(err)
            print(err)
        
    
main()






