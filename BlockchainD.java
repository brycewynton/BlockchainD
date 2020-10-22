/*
 * Bryce Jensen
 * 10/16/2020
 *
 *  openjdk 11.0.1 2018-10-16 LTS
 *  to compile:
 *      $ javac BlockchainD.java
 *
 *  to run, in one shell:
 *     $ java BlockchainD
 *
 *  Files needed to run:
 *                     a. checklist-block.html
 *                     b. Blockchain.java
 *                     c. BlockchainLog.txt
 *                     d. BlockchainLedgerSample.json
 *                     e. BlockInput0.txt
 *                     f. BlockInput1.txt
 *                     g. BlockInput2.txt
 *
 * Notes:
 *       This is mini-project D of the Blockchain assignment.
 *
 *       It contains a simple blockchain program with five nodes. A dummy genesis block and
 *       four other simple blocks.
 *
 *       Each block contains some arbitrary data, the hash of the previous block,
 *       a timestamp of its creation, and the hash of the block itself.
 *
 *       When calculating the hash for each block, the contained elements in the block
 *       are turned into strings and concatenated together with a nonce to then be hashed.
 *
 *       The verifying of blocks is done by taking in the block hash prefix and trying every possible
 *       combination by incrementing our nonce  until our prefixString is equal to our designated prefix
 *		
 *	    It currently can marshall its data out into JSON format and compile successfully.
 *
 *      As of 10/17/2020 at 10:41am, I" have my readFromJSON() method flushed out. Will need to clone
 *      and test in the VM to make sure everything still compiles and does what I expect it to.
 *
 *	Starting implementation of my program accepting command line arguments
 * 	today on 10/22/2020.
 */

import java.io.FileWriter;
import java.io.FileReader;
import java.io.Reader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.swing.plaf.synth.SynthLookAndFeel;

class BlockRecord
{
    String BlockID;
    // will hold the blocks ID
    String VerificationProcessID;
    // holds the ID of the process that verifies the block, or tries to
    String PreviousHash;
    // hash of the previous block
    UUID uuid;
    // how we will marshall data to JSON
    String Data;
    // the data contained in the block
    String RandomSeed;
    // this will be our means of trying to verify the block
    String WinningHash;
    // the hash of our winning guess

    public String getBlockID()
    {
        return BlockID;
        // accessor to return block ID
    }
    public void setBlockID(String _BlockID)
    {
        this.BlockID = _BlockID;
        // accessor for setting the block ID
    }

    public String getVerificationProcessID()
    {
        return VerificationProcessID;
        // accessor to return verificationProcessID
    }
    public void setVerificationProcessID(String _VerificationProcessID)
    {
        this.VerificationProcessID = _VerificationProcessID;
    }

    public UUID getUUID()
    {
        return this.uuid;
    }
    public void setUUID(UUID _uuid)
    {
        this.uuid = _uuid;
    }
    // get/setter for unique identifier

    public String getPreviousHash()
    {
        return this.PreviousHash;
    }
    public void setPreviousHash(String _PreviousHash)
    {
        this.PreviousHash = _PreviousHash;
    }
    // getter/setter for previousHash

    public String getData()
    {
        return this.Data;
    }
    public void setData(String _Data)
    {
        this.Data = _Data;
    }
    // getter / setter for obtaining and setting the data contained

    public String getRandomSeed()
    {
        return this.RandomSeed;
    }
    public void setRandomSeed(String _RandomSeed)
    {
        this.RandomSeed = _RandomSeed;
    }
    // getter / setters fro gettting and setting the random seed

    public String getWinningHash()
    {
        return this.WinningHash;
    }
    public void setWinningHash(String _WinningHash)
    {
        this.WinningHash = _WinningHash;
    }
    // getter and setters to obtain or set the winning hash
}


public class BlockchainD
{
    public static String hash;
    public static String previousHash;
    public static String data;
    public static long timeStamp;
    public static int  nonce;
    // declaration of private member variables

    public static String fakeBlock = "This is a fake block, we need to build our blockchain dynamically\n";

    /*
     * public constructor for Blockchain_C
     * @param data var of type String
     * @param previousHash var of type String
     * @param timeStamp variable of type long
     */
    public BlockchainD(String data, String previousHash, long timeStamp)
    {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = timeStamp;
        // getters and setters
        this.hash = calculateBlockHash();
        // assigns hash to itself
    }


    public String calculateBlockHash()
    // method to calculate hash for current block
    {
        String dataToHash = previousHash + Long.toString(timeStamp) + Integer.toString(nonce) + data;
        // concatenation of hash of the previous tx ,time of tx, the tx nonce, ans the tx data
        MessageDigest digest = null;
        // declare new message digest objecgt and isntatntiate to null
        byte[] bytes = null;
        // declare and initialize a new byte array

        try
        {
            digest = MessageDigest.getInstance("SHA-256");
            // get an instance of the SHA256 hashing algorithm and store it in digest
            bytes = digest.digest(dataToHash.getBytes("UTF-8"));
            // generate the hash value of our input data and stick in in our new byte array
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException exception)
        {
            System.err.println("Exception found: " + exception);
            exception.printStackTrace();
            // print exceptions to console
        }

        StringBuffer buffer = new StringBuffer();
        // declare and initialize anew string buffer
        for (byte b: bytes)
        // cycle through all bytes in bytes
        {
            buffer.append(String.format("%02x", b));
            // turn said byte into a hex string
        }
        return buffer.toString();
        // return our string buffer that now holds our hash
    }


    /*
     * method for mining a new block
     * @param a prefix var of type integer
     *
     * please note that this implementation does not verifying any date which
     * is a crucial component of blockchains with real-world application
     */
    public String mineBlock(int prefix)
    {
        String prefixString = new String(new char[prefix]).replace('\0', '0');
        /*
         * declare and intialialize our prefix string to a new string containing our prefix integer with '\0' replaced
         * by '0' to represent the prefix we are looking for
         */

        while (!hash.substring(0, prefix).equals(prefixString))
        // while we do not have our desired solution
        {
            nonce++;
            // increment our nonce
            hash = calculateBlockHash();
            // and calculate the hash
        }
        return hash;
        // return our winning hash w=once we find our desired prefixString
    }

    public String getHash()
    {
        return this.hash;
        // getter to return hash
    }

    public String getPreviousHash()
    {
        return this.previousHash;
        // getter to return previous hash
    }

    public String getData()
    {
        return this.data;
    }

    public void sendData(String data)
    {
        this.data = data;
        // method to send data to the block
    }

    public static void writeToJSON()
    {
        System.out.println("\n___________In writeToJSON___________\n");
        // console header to inform the user whats executing
        UUID b_UUID = UUID.randomUUID();
        String s_uuid = b_UUID.toString();
        // declare and initialize a new random uuid and save it as a string
        System.out.println("Unique Block ID: " + s_uuid + "\n");
        // print out uuid to console

        BlockRecord blockRecord = new BlockRecord();
        // declare and initialize a new blockRecord object
        blockRecord.setVerificationProcessID("Process 2");
        // set the process ID to 2
        blockRecord.setBlockID(s_uuid);
        // set the uuid string
        blockRecord.setUUID(b_UUID);
        // set the binary uuid
        blockRecord.setData("This is the data contained within this transaction block");
        // add in some arbitrary data

        Random rand = new Random();
        // declare3 and initialize a new random variable
        int randVal = rand.nextInt(12777215);
        // the declared bound is a 0xFFFFFF mask, Elliott wants us to pick anew range so play around with this

        String randomSeed = String.format("%06X", randVal & 0x00FFFFF);
        // Masking off ll but the trailing 12 characters
        randVal = rand.nextInt(14333409);
        // this bound is meaningless, I made it up
        String randomSeed2 = Integer.toHexString(randVal);
        // second random seed string
        System.out.println("Our random seed is: " + randomSeed + "... or was it: " + randomSeed2 + "?...\n");
        // print out our two random seeds to confuse the user, we are using randomSeed2

        blockRecord.setRandomSeed(randomSeed2);
        // set the correct random seed in our blockRecord object

        String newBlockRecord = blockRecord.getBlockID() + blockRecord.getVerificationProcessID() +
                blockRecord.getPreviousHash() + blockRecord.getData() + blockRecord.getRandomSeed() +
                blockRecord.getWinningHash();
        // fill a new string up with our block data

        System.out.println("blockRecord is: " + newBlockRecord + "\n");
        // tell the console what the new block record is

        String SHA256string = "";
        // declare new string variable to hold the string version of our SHA256 hash and initialize to empty;

        try {
            MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
            // get and instance of our hashing algorithm from message digest
            ourMD.update(newBlockRecord.getBytes());
            // load up the bytes of our new block record
            byte[] byteArr = ourMD.digest();
            // turn our record into a byte array

            StringBuffer stringBuf = new StringBuffer();
            for (int i = 0; i < byteArr.length; i++)
            {
                stringBuf.append(Integer.toString((byteArr[i] & 0xFF) + 0x100, 16).substring(1));
                // cycle through all bytes in our byte array and add the hexidecimal verion to our string buffer
            }

            SHA256string = stringBuf.toString();
            // more human readable this way
        } catch (NoSuchAlgorithmException noAlgEx)
        {
            System.out.println("No Algorithm exception caught: " + noAlgEx + "\n");
            noAlgEx.printStackTrace();
            // print our exceptions to the console ot be handled
        }

        blockRecord.setWinningHash(SHA256string);
        // we just let the first hash win, try to implement some real work to see how this may work

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        // declare and initialize new gson builder to contain our java object
        String json = gson.toJson(blockRecord);

        System.out.println("\nJSON blockRecord: " + json + "\n");
        // print our json string to console

        try(FileWriter writer = new FileWriter("blockRecord.json"))
        {
            gson.toJson(blockRecord, writer);
        } catch (IOException exception)
        {
            System.out.println("Caught IO exception: " + exception + "\n");
            exception.printStackTrace();
            // print exception to console to be handled
        }
    }

    public static void readFromJSON()
    {
        System.out.println("\n_______________In readFromJSON_______________");
        // crewate a header to indicate to the console what section is executing
        Gson gson = new Gson();
        // declare and initialize a new gson object and store it in var gson
        try (Reader reader = new FileReader("blockRecord.json"))
        {
            BlockRecord blockRecord_Read = gson.fromJson(reader, BlockRecord.class);
            // reads JSON into variable blockRecord_Read object of type BlockRecord
            System.out.println(blockRecord_Read);
            // print out our newly marshalled java object
            System.out.println("Top Secret Data Contained: " + blockRecord_Read.Data + "\n");
            // print the data contained in the read JSON block
            String uuid_read = blockRecord_Read.uuid.toString();
            // declare and initialize var uuid_read to hold the uuid read from the JSON string
            System.out.println("Stirng UUID: " + blockRecord_Read.BlockID + " \nBinary UUID: " + uuid_read + "\n");
            // print our uuid to console in both string format and binary
        } catch (IOException exception)
        {
            System.out.println("Caught an IOException trying to sneak by: " + exception + "\n");
            exception.printStackTrace();
            // print out the caught exceptions to the console to be handled
        }
    }

    public static void demonstrateUtils(String a[]) throws Exception
    {
        System.out.println("\n_____________In demonstrateUtils______________");
        // crate a header so we know what is happening in the console
        int processNum;
        // declare variable hold port number
        int unverifiedBlock_portNum;
        // declare a variable to hold the unverified block's port numbner
        int blockchain_portNum;
        // declare a variable to hold the verified blockchain port number

        /*
            //lets figure out how to implement something extra for some bragging rights

            if (a.length > 2)
            {
                System.out.println("This is my bragging rights code");
            }

            // code and explanation of bragging rights would go hewre
         */

        if (a.length < 1)
        // sets the process id to zero from command line argument if no arguments are given
        {
            processNum = 0;
        }
        else if (a[0].equals("0"))
        // sets process number to 0 according to the command line argument
        {
            processNum = 0;
        }
        else if (a[0].equals("1"))
        // sets process number to 1 according to the command line argument
        {
            processNum = 1;
        }
        else if (a[0].equals("2"))
        // sets process number to 2 according to the command line argument
        {
            processNum = 2;
        }
        else
            // sets process number to 0 by default if there is an invalid command limne argument
        {
            processNum = 0;
        }

        unverifiedBlock_portNum = 4710 +processNum;
        // sets unverified block port number according to its process number
        blockchain_portNum = 4810 + processNum;
        // sets verified blockchain port number according to its process number

        System.out.println("Process number: " + processNum + " Ports: " + unverifiedBlock_portNum + " " + blockchain_portNum + "\n");
        // print out the process number and port port nums being used to the console

        Date date = new Date();
        // declare new date variable to contain in block
        String time = String.format("%1$s %2$tF.%2$tT", "", date);
        // format our date into a string
        String timeStamp = time + "." + processNum + "\n";
        // use our time string and concatenate with the process number that is being run
        System.out.println("Timestamp: " + timeStamp);
        // print out to console

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        // new message digest to get hashing algorithm
        messageDigest.update(fakeBlock.getBytes());
        // update our block
        byte[] byteArr = messageDigest.digest();
        // make a new byte array to hold our bytes

        StringBuffer stringBuffer = new StringBuffer();
        // declare new string buffer to convert our bytes into hex
        for (int i = 0; i < byteArr.length; i++)
        {
            stringBuffer.append(Integer.toString((byteArr[i] & 0xFF) + 0x100, 16).substring(1));
            // conversion to hexadecimal
        }

        String SHA256string = stringBuffer.toString();
        // declare a variable and initialize to hold the string version of our hash

        KeyPair keyPair = generateKeyPair(777);
        // not secure for real world use, need to use a random string

        byte[] sig = signData(SHA256string.getBytes(), keyPair.getPrivate());
        // create a new byte array to hold our signers digital signature

        boolean isVerified = verifySig(SHA256string.getBytes(), keyPair.getPublic(), sig);
        // run the verifySig method to verify the digital signature and store it in the boolean variable isVerified

        System.out.println("Hexadecimal byte[] representation of SHA256 hash: " + SHA256string + "\n");
        // print out the hex hash to the console

        /*
            this SHA256 string will need to be added to the header of our block

            below, we can see how to turn this string back into a byte array
         */

        hash = Base64.getEncoder().encodeToString(sig);
        // encodes the digital signature into string format
        System.out.println("The signed SHA256 hash string: " + hash + "\n");
        // print out the current block's hash to the console

        byte[] testSigArr = Base64.getDecoder().decode(hash);
        // make a byte array to hold the bytes to test turning our hash back into a byte array
        System.out.println("Testing signature restoration to byte[]: " + Arrays.equals(testSigArr, sig));
        // checks to see if our decoded sig matches our sig and prints the boolean

        isVerified = verifySig(SHA256string.getBytes(), keyPair.getPublic(), testSigArr);
        // replaces the bool we declared earlier to tell us if our block is verified or not

        System.out.println("Has the restored digital signature been verified: " + isVerified + "\n");
        // print out if the sig has been verified to the console

        /*
            below proves that if our key is tampered with, it will
            not return as verified
         */

        byte[] bytePublicKey = keyPair.getPublic().getEncoded();
        // saves the public key as a byte array in our var bytePublickey
        System.out.println("Key in byte array format: " + bytePublicKey);
        // print out byte array pub key to console

        String keyString = Base64.getEncoder().encodeToString(bytePublicKey);
        // save the public key from byte array to string
        System.out.println("Key in string format: " + keyString);
        // print out the key to the console in string format

        String keyStringBad = keyString.substring(0,50) + "M" + keyString.substring(51);
        // make arbitrary changes to our key to prove validity test
        System.out.println("\nBad key in string format: " + keyStringBad);
        // print out the unverified key to console

        byte[] bytePublicKey_2 = Base64.getDecoder().decode(keyString);
        // turn it back into a byte array
        System.out.println("Key in byte array format again: " + bytePublicKey_2);
        // print out the key to console in byte form once again

        X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(bytePublicKey_2);
        KeyFactory keyFactory =  KeyFactory.getInstance("RSA");
        // declare and initialize a new key factory variable for an RSA key
        PublicKey restoredKey = keyFactory.generatePublic(publicSpec);
        // get a public key and store it in restoredKey var

        isVerified = verifySig(SHA256string.getBytes(), keyPair.getPublic(), testSigArr);
        // store bool value in our isVerified boolean
        System.out.println("Has signature been verified: " + isVerified + "\n");
        // print out if the signature is verified or not

        isVerified = verifySig(SHA256string.getBytes(), restoredKey, testSigArr);
        // store bool value for our restored key signature
        System.out.println("Has CONVERTED-FROM-STRING signature been verified: " + isVerified + "\n");
        // print out if the restored signature is verified

        X509EncodedKeySpec publicSpecBad = new X509EncodedKeySpec(bytePublicKey_2);
        KeyFactory keyFactoryBad = KeyFactory.getInstance("RSA");
        // declare and initialize a new bad key factory variable for an RSA key
        PublicKey restoredBadKey = keyFactoryBad.generatePublic(publicSpecBad);
        // get a public key version of the bad key to store in our var

        isVerified = verifySig(SHA256string.getBytes(), restoredBadKey, testSigArr);
        // store bool value in isVerified again
        System.out.println("Has CONVERTED-FROM-STRING signature been verified: " + isVerified + "\n");
        // print out if the restored signature is verified

        /*
            below is Elliott's guide on how to simulate work
         */

        System.out.println("Now simulating work: ");
        // print to the console to show the beginning of *work* simulation

        int rVal = 77;
        // new arbitrary value
        int tenths = 0;
        // declare and intitialize tenth var to 0
        Random random = new Random();
        // declare and initialize a new random variable

        for (int i = 0; i < 1000; i++)
        // our safe upper limit is 1000
        {
            Thread.sleep(100);
            // our fake work
            rVal = random.nextInt(100);
            // higher the bound means more work
            System.out.println(".");

            if (rVal < 10)
            // the lower the threshold means more work in this case
            {
                tenths = i;
                break;
            }
        }
        System.out.println(" <-- we did" + tenths + " tenths of a second of *work*\n");
        // print how long it took us to solve the fake work to the console
    }

    public static boolean verifySig(byte[] _data, PublicKey _key, byte[] _sig) throws Exception
    {
        Signature signer = Signature.getInstance("SHA1withRSA");
        // declare and initialize signer variable of type Signature that holds an instance of our encryption type
        signer.initVerify(_key);
        // verify the key being passed as argument
        signer.update(_data);
        // update with new data being passed as argument

        return (signer.verify(_sig));
        // return if it is verified
    }

    public static KeyPair generateKeyPair(long _seed) throws Exception
    {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        // declare and initialize a new key pair generator of type RSA
        SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
        // declare and initialize a new secure random number generator
        rng.setSeed(_seed);
        // set our seed
        keyPairGenerator.initialize(1024, rng);

        return (keyPairGenerator.generateKeyPair());
        // return our new key pair
    }

    public static byte[] signData(byte[] _data, PrivateKey _key) throws Exception
    {
        Signature signer = Signature.getInstance("SHA1withRSA");
        // get a new instance of signer
        signer.initSign(_key);
        // sign with argument key
        signer.update(_data);
        // update with argument data

        return (signer.sign());
    }


    public static void main(String a[])
    {
        List<BlockchainD> blockchain = new ArrayList<>();
        // declare and initialize our new blockchain
        int prefix = 4;
        // declare and initialize our prefix value to 4 leading zeroes
        String prefixString = new String(new char[prefix]).replace('\0', '0');
        // declare and initialize our prefixString for this instance

        BlockchainD genesisBlock = new BlockchainD("This is the genesis Dummy Block.", "0", new Date().getTime());
        // declare and initialize a new genesis block to be our Dummy Block
        genesisBlock.mineBlock(prefix);
        // mine our Dummy Block
        blockchain.add(genesisBlock);
        // add it to our blockchain

        BlockchainD firstBlock = new BlockchainD("This is the first Simple Block.", genesisBlock.getHash(), new Date().getTime());
        // declare and initialize our first Simple Block
        firstBlock.mineBlock(prefix);
        // mine our first Simple block
        blockchain.add(firstBlock);
        // add it to our blockchain

        BlockchainD secondBlock = new BlockchainD("This is the second Simple Block.", firstBlock.getHash(), new Date().getTime());
        // declare and initialize our second Simple Block
        secondBlock.mineBlock(prefix);
        // mine our second Simple block
        blockchain.add(secondBlock);
        // add it to our blockchain

        BlockchainD thirdBlock = new BlockchainD("This is the third Simple Block.", secondBlock.getHash(), new Date().getTime());
        // declare and initialize our third Simple Block
        thirdBlock.mineBlock(prefix);
        // mine our third Simple block
        blockchain.add(thirdBlock);
        // add it to our blockchain

        BlockchainD fourthBlock = new BlockchainD("This is the fourth Simple Block.", blockchain.get(blockchain.size() - 1).getHash(), new Date().getTime());
        // declare and initialize our fourth Simple Block
        fourthBlock.mineBlock(prefix);
        // mine our fourth Simple block
        blockchain.add(fourthBlock);
        // add it to our blockchain


        boolean flag = true;
        // declare and initialize our boolean flag var to true
        String tempData = null;
        // declare adn initialize a tempData var to null
        String tempCurrentHash = null;
        // declare and initialize a tempCurrentHash var to null

        for (int i = 0; i < blockchain.size(); i++)
        // cycle through the size of the chain
        {
            String previousHash = i==0 ? "0" : blockchain.get(i - 1).getHash();
            flag = blockchain.get(i).getHash().equals(blockchain.get(i).calculateBlockHash()) &&
                    previousHash.equals((blockchain.get(i).getPreviousHash())) && blockchain.get(i).getHash().substring(0, prefix).equals(prefixString);
            /*
             * set flag equal to the boolean value if the stored hash for the current block is calculated and stored correctly
             * and if the previous block stored in the current block is actually the hash of the previous block.
             * and if the current block has been mined
             */

            tempCurrentHash = blockchain.get(i).getHash();
            // save current hash to print out
            tempData = blockchain.get(i).getData();
            // save data to tempData to print out

            if (!flag)
            {
                break;
            }
        }
        System.out.println("\nFlag: " + flag + "\nBlock: " + tempCurrentHash + "\nContent: " + tempData + "\nGood Job!\n");
        // print out the results to the console


        /*
            below is what is necessary for implementing Elliott's requirements:
                demonstrateUtil checks the command line argument for the process ID and assigns the blochain
                a port number depending on the process ID and if the blockchain is verified or unverified

                writeToJSOn does exactly that

                readFromJSON does exactly that
         */

        try
        {
            demonstrateUtils(a);
        } catch (Exception e)
        {
            e.printStackTrace();
        }

        writeToJSON();
        // write our output to JSON file
        readFromJSON();
        // read our input from a JSON file
    }
}



