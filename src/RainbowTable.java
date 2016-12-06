import java.math.BigInteger;
import java.security.*;
import java.util.*;
import java.lang.instrument.Instrumentation;
import java.io.*;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;

public class RainbowTable {

	private static HashMap<String, byte[]> table;
    private static MessageDigest SHA; // 160 bits
    private static final int CHAIN_LENGTH = 300; //MODIFY THIS PARAMETER
    private static final int NUMBER_OF_ROWS = 30000; //MODIFY THIS PARAMETER
    private static final long NUMBER_OF_SHA = 8388608; //2^23 SHA
    private static long t;

	public static void main(String[] args) throws Exception {
        System.out.println("\nInitializing Rainbow Table Program...\n");
        //build the rainbow
		buildTable();
		//write the rainbow table to file (for checking of the rainbow table size)
        writeTableToFile();
        //gotta-go-fast
		speedTest();
        //attack!!!
		rainbowAttack();
	}
	
	private static void rainbowAttack() throws Exception {
        System.out.println("\nPHASE 3: RAINBOW ATTACK\n");
		String fileName = "SAMPLE_INPUT.data";
        System.out.println("\nBEGINNING ATTACK...\n");
		BufferedReader br = new BufferedReader(new FileReader(fileName));
		String currentLine;
		int success = 0, reject = 0, counter = 0;
		byte[][] allDigests = new byte[5000][20]; //20 bytes = 160 bits SHA1
		byte[][] allWords = new byte[5000][3]; 
		//Reading from file
		while((currentLine = br.readLine()) != null) {
			String currentHexString;
			currentHexString = currentLine.substring(2,10) + currentLine.substring(12,20) + currentLine.substring(22,30) + currentLine.substring(32,40) + currentLine.substring(42,50);
			currentHexString = currentHexString.replaceAll("\\s", "0"); //replace spaces with 0
            //System.out.println(currentHexString);
			allDigests[counter] = hexToBytes(currentHexString);
            counter++;
		}
		br.close();
		FileWriter fw = new FileWriter("Results_Output.data");
		fw.write("S T A R T\n");
		fw.write("READ DONE\n");
		byte[] currentDigest, answer;
		long startTime = System.currentTimeMillis();
		for(int i = 0; i < allWords.length; i++) {
			currentDigest = allDigests[i];
			answer = invert(currentDigest);
			allWords[i] = answer;
			if(answer != null) {
				success++;
			}
		}
		long endTime = System.currentTimeMillis();
		//Write answers to file
		for(int i1 = 0; i1 < allWords.length; i1++) {
			if(allWords[i1] == null) {
				fw.write("\n 0");
			} else {
				fw.write("\n " + bytesToHex(allWords[i1]));
			}
		}
		fw.write("\n\nTotal number of words found: " + success + "\n");
		fw.close();
        System.out.println("> END OF ATTACK <");
        System.out.println("\n---- SUMMARY OF RESULTS ----\n");
		System.out.println("Total time SHA1 invoked by INVERT (t): " + t);
        System.out.println("Total number of words found: " + success);
        System.out.println("Percentage of words found (C)= " + success/50.0 + "%");
        System.out.println("Speedup Factor (F) = " + ((NUMBER_OF_SHA * 5000.0)/t));
	}
	
	private static void buildTable() throws Exception {
        System.out.println("PHASE 1: CONSTRUCTING RAINBOW TABLE\n");
		long start, end;
		byte[] plain, word;
		String key;
		table = new HashMap<String, byte[]>();
		SHA = MessageDigest.getInstance("SHA1");
		//Random R = new Random();
		int success = 0, collisions = 0, i = 0;
		start = System.currentTimeMillis();
		while(table.size() < NUMBER_OF_ROWS) {
			i = (int)Math.random();
			plain = intToBytes(i);
			word = generateSingleChain(plain, i);
			key = bytesToHex(word);
			if(!table.containsKey(key)) {
				table.put(key, plain);
				success++;
			} else {
				collisions++;
			}
		}
		end = System.currentTimeMillis();
        System.out.println("> RAINBOW TABLE SPECIFICATIONS <\n");
        System.out.println("NUMBER OF ROWS: " +  NUMBER_OF_ROWS);
        System.out.println("LENGTH OF CHAIN: " + CHAIN_LENGTH);
		System.out.println("GENERATED RAINBOW TABLE IN: " + (end-start)/1000.0 + " SECONDS.\n");
	}

	private static void speedTest() throws Exception{
        System.out.println("\nPHASE 2: CALCULATING TIME TAKEN TO DO 2^23 SHA1 OPERATIONS\n");
		long start, end;
		byte[] word = new byte[3];
		Random r = new Random(30);
		r.nextBytes(word);
		start = System.currentTimeMillis();
		for(int i = 0; i < 8388608; i++) { //2^23 SHA1 operations
			byte[] temp = Hash(word);
		}
		end = System.currentTimeMillis();
		System.out.println("Time taken (Big T) : " + (end-start)/1000.0 + "\n");
        System.out.println("END OF PHASE 2\n");
	}

	private static byte[] generateSingleChain(byte[] plain, int ti) throws Exception {
        byte[] digest = new byte[20];
        byte[] word = plain;
        for (int i = 0; i < CHAIN_LENGTH; i++) {
            digest = Hash(word);
            if(i%3 == 0){
            	word = reduce1(digest, i);
            }else if (i%3 == 1){
            	word = reduce2(digest, i);
            }else{
            	word = reduce3(digest, i);
            }
        }
        return word;
    }
    
    // Reduction functions
    private static byte[] reduce1(byte[] digest, int iteration){
    	byte last_byte = (byte) iteration;
        byte[] word = new byte[3];
        word[0] = (byte) (digest[11] + last_byte);
        word[1] = (byte) (digest[19] + last_byte);
        word[2] = (byte) (digest[15] + last_byte);
        return word;
    }
    
    private static byte[] reduce2(byte[] digest, int iteration){
    	byte last_byte = (byte) iteration;
        byte[] word = new byte[3];
        word[0] = (byte) (digest[11] - last_byte);
        word[1] = (byte) (digest[19] - last_byte);
        word[2] = (byte) (digest[15] - last_byte);
        return word;
    }
    
    private static byte[] reduce3(byte[] digest, int iteration){
    	byte last_byte = (byte) iteration;
        byte[] word = new byte[3];
        word[0] = (byte) (digest[7] + last_byte);
        word[1] = (byte) (digest[11] + last_byte);
        word[2] = (byte) (digest[15] + last_byte);
        return word;
    }
    
    //Hashing function
  	private static byte[] Hash(byte[] plaintext) {
          byte hash[] = new byte[20];
          try {
              hash = SHA.digest(plaintext);
              SHA.reset();
          } catch (Exception e) {
              System.out.println("Exception: " + e);
          }
          return hash;
      }

    private static byte[] invert(byte[] hashToMatch) {
        byte[] result = new byte[3];
        String key = "";
        for (int i = CHAIN_LENGTH - 1; i >=0 ; i--) {
            key = invertHR(hashToMatch, i, 1);
            if (table.containsKey(key)) {
                result = invertChain(hashToMatch, table.get(key));
                if (result != null) {
                    return result;
                }
            }else{
            	key = invertHR(hashToMatch, i, 2);
            	if(table.containsKey(key)){
            		 result = invertChain(hashToMatch, table.get(key));
                     if (result != null) {
                         return result;
                     }
            	}else{
            		key = invertHR(hashToMatch, i, 3);
            		if(table.containsKey(key)){
            			result = invertChain(hashToMatch, table.get(key));
                        if (result != null) {
                            return result;
                        }
            		}
            	}
            }
        }
        return null;
    }

    private static String invertHR(byte[] digest, int start, int r) {
        byte[] word = new byte[3];
        for (int i = start; i < CHAIN_LENGTH; i++) {
        	if(r==1){
        		word = reduce1(digest, i);	
        	}else if(r==2){
        		word = reduce2(digest, i);
        	}else{
        		word = reduce3(digest, i);
        	}
            digest = Hash(word);
            t++;
        }
        return bytesToHex(word);
    }

    private static byte[] invertChain(byte[] hashToMatch, byte[] word) {
        byte[] hash;
        for (int i = 0; i < CHAIN_LENGTH; i++) {
            hash = Hash(word);
            t++;
            if (Arrays.equals(hash, hashToMatch)) {
                return word;
            }
            if(i%3 == 0){
            	word = reduce1(hash, i);
            }else if(i%3 == 1){
            	word = reduce2(hash, i);
            }else{
            	word = reduce3(hash, i);
            }  
        }
        return null;
    }

    private static byte[] hexToBytes(String hexString) {
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        byte[] bytes = adapter.unmarshal(hexString);
        return bytes;
    }

    private static String bytesToHex(byte[] bytes) {
        HexBinaryAdapter adapter = new HexBinaryAdapter();
        String str = adapter.marshal(bytes);
        return str;
    }

    private static byte[] intToBytes(int n) {
        byte plaintext[] = new byte[3];
        plaintext[0] = (byte) ((n >> 16) & 0xFF);
        plaintext[1] = (byte) ((n >> 8) & 0xFF);
        plaintext[2] = (byte) n;
        return plaintext;
    }
    
    private static void writeTableToFile() {
        System.out.println("WRITING TABLE TO: rainbow_table.data");
        ObjectOutputStream oos;
        try {
            oos = new ObjectOutputStream(new FileOutputStream("rainbow_table.data"));
            oos.writeObject(table);
            oos.close();
            System.out.println("WRITING SUCCESS!\n");
        } catch (Exception e) {
            System.out.println("Exception: " + e);
        }
        System.out.println("END OF PHASE 1\n");
    }
}