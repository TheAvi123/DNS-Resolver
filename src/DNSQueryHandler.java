import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;
    private static boolean debugTracing = false;

    private static final Random random = new Random();
    private static final int RESPONSE_LENGTH = 1024; 

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server,
                                                      DNSNode node) throws IOException {
        // Encode DNS query into byte array
        int messageSize = encodeQuery(message, node);
        if (debugTracing) {
            System.out.println("Message Size: " + messageSize + "\n");
            System.out.println("Buffer Query:");
            printBufferInHex(message);
        }
        // Retrieve Query ID for tracing and response checking
        int queryID = decodeOctetPair(message[0], message[1]);
        // Prepare DatagramPacket with query to send to the specified server
        DatagramPacket requestPacket = new DatagramPacket(message, messageSize, server, DEFAULT_DNS_PORT);
        if (debugTracing) {
            System.out.println("Request Length: " + requestPacket.getLength());
        }
        // Create ByteBuffer and DatagramPacket for server response
        int responseID = -1;
        ByteBuffer responseBuffer = null;
        DatagramPacket responsePacket = null;   
        // Attempt to send and recieve packets, resending once if needed
        try {
            // Print Query Information
            if (verboseTracing) {
                System.out.println("\n\nQuery ID     " + queryID + " " + node.getHostName() + 
                                   "  " + node.getType() + " --> " +  server.getHostAddress());
            }
            // Send request packet through the socket
            socket.send(requestPacket);
            // Recieve response packet with the same ID
            while (responseID != queryID) {
                // Initialize ByteBuffer and DatagramPacket
                responseBuffer = ByteBuffer.allocate(RESPONSE_LENGTH);
                responsePacket = new DatagramPacket(responseBuffer.array(), RESPONSE_LENGTH);
                // Wait to recieve a packet through the socket
                socket.receive(responsePacket);
                // Update responseID
                responseID = decodeOctetPair(responseBuffer.array()[0], responseBuffer.array()[1]);
                if (debugTracing) {
                    System.out.println("Response ID: " + responseID);
                }
            }
        } catch (IOException e) {
            if (debugTracing) {
                System.out.println("Socket Timeout - Sending Query Again\n");
            }
            // Print Query Information
            if (verboseTracing) {
                System.out.println("\n\nQuery ID     " + queryID + " " + node.getHostName() + 
                                   "  " + node.getType() + " --> " +  server.getHostAddress());
            }
            // Send request packet through the socket
            socket.send(requestPacket);
            // Recieve response packet with the same ID
            while (responseID != queryID) {
                // Initialize ByteBuffer and DatagramPacket
                responseBuffer = ByteBuffer.allocate(RESPONSE_LENGTH);
                responsePacket = new DatagramPacket(responseBuffer.array(), RESPONSE_LENGTH);
                // Wait to recieve a packet through the socket
                socket.receive(responsePacket);
                // Update responseID
                responseID = decodeOctetPair(responseBuffer.array()[0], responseBuffer.array()[1]);
                if (debugTracing) {
                    System.out.println("Response ID: " + responseID);
                }
            }
        }
        // Return DNSServerResponse generated from the response packet
        if (debugTracing) {
            System.out.println("Response Length: " + responsePacket.getLength() + "\n");
        }
        return new DNSServerResponse(responseBuffer, queryID);
    }

    /**
     * Function for encoding a complete DNS query into the provided 
     * byte array using information from the provided DNSNode fields
     * 
     * @return The length of the query
     */
    private static int encodeQuery(byte[] message, DNSNode node) {
        // Set Query ID
        int queryID = random.nextInt(0x0000FFFF);
        if (debugTracing) {
            System.out.println(String.format("Query ID Int: %d", queryID));
            System.out.println(String.format("Query ID Hex: %x", queryID));
        }
        message[0] = (byte) (queryID >>> 8);
        message[1] = (byte) queryID;
        // Set QDCOUNT
        message[4] = 0;
        message[5] = 1;
        // Set QNAME
        String[] domainParts = node.getHostName().split("\\.");
        if (debugTracing) {
            System.out.println("Domain: \n" + Arrays.toString(domainParts));
        }
        int index = 12;
        for (String part : domainParts) {
            message[index++] = (byte) part.length();
            byte[] partBytes = part.getBytes();
            for (int j = 0; j < partBytes.length; j++) {
                message[index++] = partBytes[j];
            }
        }
        message[index++] = 0;
        // Set QTYPE
        int qType = node.getType().getCode();
        if (debugTracing) {
            System.out.println(String.format("QTYPE Int: %d", qType));
            System.out.println(String.format("QTYPE Hex: %x", qType) + "\n");
        }
        message[index++] = (byte) (qType >>> 8);
        message[index++] = (byte) qType;
        // Set QCLASS
        message[index++] = 0;
        message[index++] = 1;
        // Return size of complete query
        return index;
    }

    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer,
                                                             DNSCache cache) {
        // Initialize Set of ResourceRecords
        Set<ResourceRecord> recordSet = new HashSet<ResourceRecord>();
        //Initialize Buffer for Decoding
        responseBuffer.position(2);
        if (debugTracing) {
            System.out.println("Buffer Response:");
            printBufferInHex(responseBuffer.array());
        }
        // Decode Byte 2
        byte byte2 = responseBuffer.get();
        int QR = (byte2 & 0b10000000) >>> 7;
        int OpCode = (byte2 & 0b01111000) >>> 3;
        int AA = (byte2 & 0b00000100) >>> 2;
        int TC = (byte2 & 0b00000010) >>> 1;
        int RD = (byte2 & 0b00000001); 
        if (debugTracing) {
            System.out.println("QR: " + QR);
            System.out.println("OpCode: " + OpCode);
            System.out.println("AA: " + AA);
            System.out.println("TC: " + TC);
            System.out.println("RD: " + RD);
        }
        // Decode Byte 3
        byte byte3 = responseBuffer.get();
        int RA = byte3 >>> 7;
        int RCODE = byte3 & 0b00001111;
        if (debugTracing) {
            System.out.println("RA: " + RA);
            System.out.println("RCODE: " + RCODE);
        }
        // Print Response information
        if (verboseTracing) {
            String authoritative = (AA == 0 ? "false" : "true");
            System.out.println("Response ID: " + transactionID + " Authoritative = " + authoritative);
        }
        // Decode Section Counts
        int QDCOUNT = decodeOctetPair(responseBuffer);  // Bytes 4-5
        int ANCOUNT = decodeOctetPair(responseBuffer);  // Bytes 6-7
        int NSCOUNT = decodeOctetPair(responseBuffer);  // Bytes 8-9
        int ARCOUNT = decodeOctetPair(responseBuffer);  // Bytes 10-11
        if (debugTracing) {
            System.out.println("QDCOUNT: " + QDCOUNT);
            System.out.println("ANCOUNT: " + ANCOUNT);
            System.out.println("NSCOUNT: " + NSCOUNT);
            System.out.println("ARCOUNT: " + ARCOUNT);
        }
        // Skip Over QNAME, QTYPE, and QCLASS
        int currentValue = -1;
        int currentIndex = responseBuffer.position();
        while (currentValue != 0) {
            currentValue = responseBuffer.get(currentIndex);
            currentIndex += currentValue + 1;
        }
        responseBuffer.position(currentIndex + 4);
        // Decode Resource Records
        if (verboseTracing) {
            System.out.println("  Answers (" + ANCOUNT + ")");
        }
        decodeResourceRecords(responseBuffer, ANCOUNT, cache, recordSet, true);
        if (verboseTracing) {
            System.out.println("  Nameservers (" + NSCOUNT + ")");
        }
        decodeResourceRecords(responseBuffer, NSCOUNT, cache, recordSet, false);
        if (verboseTracing) {
            System.out.println("  Additional Information (" + ARCOUNT + ")");
        }
        decodeResourceRecords(responseBuffer, ARCOUNT, cache, recordSet, true);
        // Return final set of ResourceRecords
        if (RCODE != 0) {
            return Collections.emptySet();
        }
        return recordSet;
    }

    /**
     * Helper function for decoding the resource records of a given section
     */
    private static void decodeResourceRecords(ByteBuffer responseBuffer, int numRecords, DNSCache cache, 
                                              Set<ResourceRecord> recordSet, boolean cacheRecords) {
        // Iterate by number of records specified
        for (int i = 0; i < numRecords; i++) {
            // Decode Record Information
            String recordName = decodeRecordDomainName(responseBuffer);
            int recordTypeCode = decodeOctetPair(responseBuffer);
            int recordClass = decodeOctetPair(responseBuffer);
            long recordTTL = decodeInteger(responseBuffer);
            int rdLength = decodeOctetPair(responseBuffer);
            // Check for Record CLASS
            if (recordClass != 1) {
                System.err.println("Record with CLASS != 1: " + recordClass);
                continue;
            }
            // Print Record Information
            if (debugTracing) {
                System.out.println("recordName: " + recordName);
                System.out.println("recordType: " + recordTypeCode);
                System.out.println("recordClass: " + recordClass);
                System.out.println("recordTTL: " + recordTTL);
                System.out.println("rdLength: " + rdLength);
            }
            // Initialize Record Data Variables
            RecordType recordType = RecordType.getByCode(recordTypeCode);
            InetAddress recordData = null;
            ResourceRecord record = null;
            try {
                if (recordType == RecordType.A || recordType == RecordType.AAAA) {
                    // Extract InetAddress RDATA
                    byte[] dataArray = new byte[rdLength];
                    responseBuffer.get(dataArray, 0, rdLength);
                    recordData = InetAddress.getByAddress(dataArray);
                    // Create ResourceRecord with Information
                    record = new ResourceRecord(recordName, recordType, recordTTL, recordData);
                } else {
                    // Extract String RDATA
                    String hostName = decodeRecordDomainName(responseBuffer);
                    if (debugTracing) {
                        System.out.println("Host Name: " + hostName);
                    }
                    // Create ResourceRecord with Information
                    record = new ResourceRecord(recordName, recordType, recordTTL, hostName);
                }
            } catch (UnknownHostException e) {
                e.printStackTrace();
                continue;
            }
            // Print Resource Record Information
            verbosePrintResourceRecord(record, recordTypeCode);
            // Cache or Store Record into DNSCache or Result Set
            if (recordType == RecordType.A || recordType == RecordType.AAAA || 
                recordType == RecordType.CNAME || recordType == RecordType.NS) {
                if (cacheRecords) {
                    cache.addResult(record);
                } else {
                    recordSet.add(record);
                }
            }
        }
    }

    /**
     * Helper function for decoding a domain name given the ByteBuffer
     */
    private static String decodeRecordDomainName(ByteBuffer buffer) {
        // Initialize first byte from buffer at current position
        byte firstByte = buffer.get();
        // Base case for end of domain
        if (firstByte == 0) {
            return "";
        }
        // Recursive cases for labels and pointers
        boolean isLabel = ((firstByte & 0b11000000) >>> 6) == 0;
        if (isLabel) {
            // Recursively Decode Domain as a Label
            byte[] labelArray = new byte[firstByte];
            buffer.get(labelArray, 0, firstByte);
            String label = new String(labelArray);
            String remainder = decodeRecordDomainName(buffer);
            if (remainder.length() > 0) {
                label = label + "." + remainder;
            }
            return label;
        } else {
            // Recursively Decode Domain as a Pointer
            byte secondByte = buffer.get();
            int offset = ((firstByte & 0b00111111) << 8) | (secondByte & 0xFF);
            int currentPosition = buffer.position();
            buffer.position(offset);
            String pointer = decodeRecordDomainName(buffer);
            buffer.position(currentPosition);
            return pointer;
        }
    }

    /**
     * Helper function for printing a byte buffer in hex format
     */
    private static void printBufferInHex(byte[] buffer) {
        System.out.print(String.format("[%x", buffer[0]));
        for (int i = 1; i < buffer.length; i++) {
            System.out.print(String.format(", %x", buffer[i]));
        }
        System.out.print("]\n");
        System.out.println();
    }

    /**
     * Helper function for decoding a pair of octets into an integer
     */
    private static int decodeOctetPair(byte byteA, byte byteB) {
        return ((byteA << 8) & 0x0000FF00) | (byteB & 0x000000FF);
    }

    /**
     * Helper function for decoding a pair of octets into an integer
     */
    private static int decodeOctetPair(ByteBuffer buffer) {
        return ((buffer.get() << 8) & 0x0000FF00) | (buffer.get() & 0x000000FF);
    }

    /**
     * Helper function for decoding a pair of octets into an integer
     */
    private static int decodeInteger(ByteBuffer buffer) {
        return ((buffer.get() << 24) & 0xFF000000) | 
               ((buffer.get() << 16) & 0x00FF0000) | 
               ((buffer.get() <<  8) & 0x0000FF00) |
               ( buffer.get()        & 0x000000FF);
    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }
}

