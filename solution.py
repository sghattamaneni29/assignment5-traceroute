import socket
from socket import *
import os
import sys
import struct
import time
import select

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1


# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise
def checksum(string):
    # In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.

    # Don’t send the packet yet , just return the final packet in this function.

    myChecksum = 0
    # Make a dummy header with a 0 checksum
    # struct --Interpret strings as packed binary data
    ID = os.getpid() & 0xFFFF
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)  # Checksum is in network order
    if sys.platform == 'darwin':
        # Convert 16-bit integers from host to network  byte order
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, 1
    )
    packet = header + data
    return packet

def get_route(hostname):
    #destAddr1 = gethostbyname(hostname)
    timeLeft = TIMEOUT
    tracelist1 = []  # This is your list to use when iterating through each trace
    tracelist2 = []  # This is your list to contain all traces
    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)
            icmp = getprotobyname('icmp')
            # Make a raw socket named mySocket
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                    tracelist1.append("* * * Request timed out.")
                    tracelist2.add(tracelist1)

                recvPacket, addr = mySocket.recvfrom(1024)
                destAddr = addr
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                    tracelist2.append(tracelist1)
                    return tracelist2
            except timeout:
                continue
            else:

                header = recvPacket[20:28]
                types, code, checksum, ID, seq = struct.unpack("bbHHh", header)
                bytes = struct.calcsize("d")
                try:
                    Hostname = gethostbyaddr(addr[0])[0]
                except herror as msg:
                    Hostname = "(hostname not returnable:" + str(msg) + ")"
                if types == 11:
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    tracelist1.append([str(ttl), str(round((timeReceived - t) * 1000)) + "ms", addr[0], Hostname])
                    tracelist2.append(tracelist1)

                elif types == 3:
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    tracelist1.append([str(ttl), str(round((timeReceived - t) * 1000)) + "ms", addr[0], Hostname])
                    tracelist2.append(tracelist1)
                elif types == 0:
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    tracelist1.append([str(ttl), str(round((timeReceived - timeSent) * 1000)) + "ms", addr[0], Hostname])
                    tracelist2.append(tracelist1)

                else:
                    print("error")
            finally:
                mySocket.close()
                break
    print(tracelist2)
    return tracelist2

if __name__ == '__main__':
    get_route("google.co.il")
