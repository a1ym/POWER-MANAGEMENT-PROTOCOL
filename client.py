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
    packetFlags = "1000" #Connection opened, SYN bit is set to 1
    sentData = {"modp_id": modp, "pub_key": clientPubKey}
    sentData = json.dumps(sentData)
    packet = constructPacket(sentData, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), None)
    s.sendto(packet, (SERVER_IP, SERVER_PORT))
    print(sentData)
    #Retransmit packet on response timeout
    try:
        checksum, flags, data, seqNum = recievePacket(None)
        serverPubKey = json.loads(data)["pub_key"]
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
    iv = data[-16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[:-16]), 16)


#Send commands to server and recieve response
def sendCommand(command, key):
    global SEQ_NUM
    packetFlags = "0000"
    SEQ_NUM += 2
    packet = constructPacket(command, packetFlags, str(bin(SEQ_NUM)[2:]).zfill(12), key)
    s.sendto(packet, (SERVER_IP, SERVER_PORT))
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
        

#Recieve and ouput a packet
def recievePacket(key):
    packet, serverAddress = s.recvfrom(bufferSize)
    checksum, flags, data, seqNum = unpackPacket(packet)
    print("SYN: " + flags[0], "RES: " + flags[1], "CRP: " + flags[2], "AUTH: " + flags[3])
    print("SEQ: " + str(seqNum))
    if key != None:
        data = aesDecrypt(data, key)

    print("RESPONSE: " + data.decode())
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
            sendCommand(json.dumps({"cmd": "PWR_STAT"}), key)
        elif option == "BTRY_LVL":
            sendCommand(json.dumps({"cmd": "BTRY_LVL"}), key)
        elif option == "SUSPND":
            sendCommand(json.dumps({"cmd": "SUSPND"}), key)
        elif option == "REBOOT":
            sendCommand(json.dumps({"cmd": "REBOOT"}), key)
        elif option == "PWROFF":
            sendCommand(json.dumps({"cmd": "PWROFF"}), key)
        elif option == "END_CONN":
            sendCommand(json.dumps({"cmd": "END_CONN"}), key)
            time.sleep(20)
            exit()
        
        else:
            err = { "err": "Wrong command entered" }
            err = json.dumps(err)
            print(err)
        
    
main()






