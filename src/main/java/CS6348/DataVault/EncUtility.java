package CS6348.DataVault;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashMap;

// Class for encrypting and decrypting file storing tags and data
public class EncUtility {

	byte[] fill = new byte[]{0x5}; // used to find the split in the data

	public EncUtility() {

	}

	// Read all of the bytes from a given file
	public byte[] readBytes(File file, int size) throws Exception
	{
		DataInputStream in = new DataInputStream(new BufferedInputStream(new FileInputStream(file)));

		int readSize = 0;

		if (size == 0) {
			readSize = in.available();
		} else if (size > 0) {
			readSize = size;
		}

		byte[] b = new byte[readSize];

		in.read(b);
		in.close();

		return b;
	}

	// Write bytes to a file
	public void writeBytes(File file, byte[] b) throws Exception
	{
		if (file == null)
		{
			return;
		}

		DataOutputStream out = new DataOutputStream(new FileOutputStream(file));
		out.write(b);
		out.close();
	}

	// Generate a random byte array of length 'len'
	public byte[] secRand(int len)
	{
		byte[] out = new byte[len];
		SecureRandom sec = new SecureRandom();
		sec.nextBytes(out);
		return out;
	}

	// Append array b to array a and store in new array
	private byte[] combine(byte[] a, byte[] b) throws Exception
	{
		byte[] res = new byte[a.length + b.length];
		System.arraycopy(a, 0, res, 0, a.length);
		System.arraycopy(b, 0, res, a.length, b.length);
		return res;
	}

	// Convert integer to a 4 byte array
	private byte[] intToBytes(int data)
	{
		return new byte[]{(byte) ((data >> 24) & 0xff), (byte) ((data >> 16) & 0xff), (byte) ((data >> 8) & 0xff), (byte) ((data >> 0) & 0xff),};
	}

	// Convert 4 byte array to integer
	private int bytesToInt(byte[] data)
	{
		return (int) ((0xff & data[0]) << 24 | (0xff & data[1]) << 16 | (0xff & data[2]) << 8 | (0xff & data[3]) << 0);
	}

	// Generate a key using a String password and byte[] salt
	// Utilizes PBKDF2 with 1024 iterations
	public byte[] getKey(String password, byte[] salt) throws Exception
	{
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1024, 256);
		SecretKeyFactory kf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] result = kf.generateSecret(spec).getEncoded();
		return result;
	}

	// Encrypt byte array with key and initial vector
	// Option for additional authenticated data (AAD), not required
	public byte[] encrypt(byte[] plainText, byte[] key, byte[] IV, byte[] add) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
		if (add != null)
		{
			cipher.updateAAD(add);
		}
		return cipher.doFinal(plainText);
	}

	// Decrypt byte array with key and initial vector
	// Option for additional authenticated data (AAD), not required
	public byte[] decrypt(byte[] cipherText, byte[] key, byte[] IV, byte[] add) throws Exception
	{
		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, IV);
		cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
		if (add != null)
		{
			cipher.updateAAD(add);
		}
		return cipher.doFinal(cipherText);
	}

	// Generate 256 bit hash of byte array using SHA-256 algorithm
	public static byte[] hash(byte[] message) throws Exception
	{
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		return digest.digest(message);
	}

	// Check if the password provided is the relevant password stored in the encrypted file
	public Boolean verifyPassword(String fileName, String password) throws Exception
	{
		byte[] header = readBytes(new File(fileName), 48);
		byte[] salt = new byte[16]; // store salt
		byte[] hash = new byte[32]; // stored hash in file

		for (int i = 0; i < 16; i++)
		{
			salt[i] = header[i];
		}

		for (int i = 16; i < 48; i++)
		{
			hash[i - 16] = header[i];
		}

		byte[] currPass = password.getBytes(); // get the current password
		byte[] saltedPass = combine(currPass, salt); // get password+salt
		byte[] new_hash = hash(saltedPass); // calculate new hash of password+salt

		if (Arrays.equals(hash, new_hash)) // if both hashes are the same
		{
			return true; // correct password
		}

		return false;
	}

	// Method to write the data to a given file and encrypt with given password
	// Formats and encrypts the file
	public void formatFile(String fileName, String rawData, String password) throws Exception
	{
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		File file = new File(fileName);
		// Format with 16 byte salt and 32 byte hash of password+salt for verification
		// 16 byte IV and 32 byte hash of key for key checking
		// 4 byte for tag section size, 16 byte tag for the name tags
		// 16 byte tags for the data, 16 bytes per tag
		// Tags 32 byte per tag, easy decrypt to index
		// 256 bytes for data
		// 32 byte hash of total data and key for verification
		// With every new addition there will be 304 bytes added to the file (16 for new tag for data, 256 for data, 32 for tag name)
		byte[] salt = secRand(16); // generate random salt
		byte[] initIV = secRand(16); // generate random IV
		byte[] saltedpass = combine(password.getBytes(), salt); // get salted password
		byte[] hashPass = hash(saltedpass); // get salted password hash
		byte[] header = combine(salt, hashPass);
		byte[] key = getKey(password, salt); // get PDKF2 key
		header = combine(header, initIV);
		header = combine(header, hash(key)); // combine all values into header, store hash of key for key checking if password not provided

		String[] out = rawData.split("\n"); // parse rawData

		int tagIVlen = (out.length * 16) + 16; // precalculate size of tags for data
		byte[] data_size = intToBytes(tagIVlen); // set data size to tagIVlen, convert int to bytes
		header = combine(header, data_size); // finalize header, all bytes up until the tags
		outStream.write(header); // write the header to output stream

		ByteArrayOutputStream tagStream = new ByteArrayOutputStream(out.length * 32);

		// Read and store all tags in the given String
		for (int i = 0; i < out.length; i++)
		{
			String[] currData = out[i].split(":");
			String currTag = currData[0];
			byte[] tagBytes = currTag.getBytes();

			if (tagBytes.length > 32) // Too long
			{
				throw new TagLengthException();
			}

			else if (tagBytes.length == 32)
			{
				tagStream.write(tagBytes);
			}
			else // Add split byte and fill any any remaining bytes randomly
			{
				byte[] temp1 = combine(tagBytes, fill);
				byte[] filler = secRand(32 - temp1.length);
				byte[] temp2 = combine(temp1, filler);
				tagStream.write(temp2);
			}
		}

		byte[] tags = tagStream.toByteArray(); // get all of the tags as a byte array
		tagStream.close();

		ByteArrayOutputStream encStream = new ByteArrayOutputStream(out.length * 288); // total length of all encrypted data
		// 288 bytes because 32 bytes for tag and 256 bytes for data
		ByteArrayOutputStream GCMStream = new ByteArrayOutputStream((out.length * 16) + 16); // total length of all enc data tags, 16 bytes per tag

		byte[] encTagGCM = encrypt(tags, key, initIV, header); // encrypt the data tags with the header for AAD which will be checked during reading for file modification
		byte[] encTag = new byte[encTagGCM.length - 16]; // actual encrypted data
		byte[] tagGCM = new byte[16]; // generated GCM tag

		for (int i = 0; i < encTag.length; i++)
		{
			encTag[i] = encTagGCM[i];
		}

		for (int i = encTag.length; i < encTagGCM.length; i++)
		{
			tagGCM[i - encTag.length] = encTagGCM[i];
		}

		GCMStream.write(tagGCM); // store GCM tag, required for decryption
		encStream.write(encTag); // write encrypted data

		BigInteger currIV = new BigInteger(initIV); // use to convert the IV of 16 bytes to bigint since very large number
		BigInteger blockSize = BigInteger.valueOf(256);  // use to add 256 since we are incrementing

		// Encrypt the data for given tag and data with unique IVs generated above
		for (int i = 0; i < out.length; i++)
		{
			currIV = currIV.add(blockSize); // add block size of data to currIV
			byte[] tempIV = currIV.toByteArray(); // convert back to byte array for use in encrypting

			String line = out[i]; // Get current line of data
			byte[] data = line.split(":")[1].getBytes(); // Get the data instead of the tag which is stored in index 0
			byte[] encTagD = new byte[272]; // Length of encrypted data (256 bytes) + 16 byte GCM tag

			if (data.length > 256) // Too long
			{
				throw new DataLengthException();
			}

			else if (data.length == 256)
			{
				encTagD = encrypt(data, key, tempIV, null); // encrypt data
			}

			else // Less than 256 bytes, add split byte and fill in remaining space with random bytes
			{
				byte[] temp1 = combine(data, fill);
				byte[] filler = secRand(256 - data.length - 1);
				byte[] temp2 = combine(temp1, filler);

				encTagD = encrypt(temp2, key, tempIV, null); // encrypt data
			}

			byte[] outputData = new byte[256]; // Actual encrypted data is 256 bytes

			for (int j = 0; j < 256; j++)
			{
				outputData[j] = encTagD[j];
			}

			byte[] genTag = new byte[16]; // GCM tag

			for (int j = 256; j < 256 + 16; j++)
			{
				genTag[j - 256] = encTagD[j];
			}

			GCMStream.write(genTag); // Store GCM tag of data
			encStream.write(outputData); // Write encrypted data
		}

		byte[] tagInfo = GCMStream.toByteArray(); // Get all GCM tags
		byte[] encData = encStream.toByteArray(); // Get all encrypted data
		GCMStream.close();
		encStream.close();

		outStream.write(tagInfo); // Write GCM tags first after header
		outStream.write(encData); // Write encrypted data

		byte[] finalData = outStream.toByteArray(); // convert output stream to byte array
		byte[] tempHash = hash(combine(finalData, initIV));
		byte[] tempHash2 = hash(combine(tempHash, key)); // simple hash to identify end of the data to check for additions
		finalData = combine(finalData, tempHash2); // add verification hash to finalData
		outStream.close();

		writeBytes(file, finalData); // write encrypted information into new file
	}

	// Read an encrypted file by either giving a password or key. Encrypt one tag or all tags at once
	public String readFile(String fileName, String password, byte[] keyProvided, String tag) throws Exception
	{

		// Password was given to decrypt file
		if (password != null)
		{
			boolean passCheck = verifyPassword(fileName, password); // check if password is valid

			if (!passCheck)
			{
				throw new WrongPassException(); // wrong password
			}
		}

		String output = "";

		byte[] totdata = readBytes(new File(fileName), 0); // Get bytes from file
		byte[] data = new byte[totdata.length - 32];

		for (int i = 0; i < data.length; i++)
		{
			data[i] = totdata[i];
		}

		byte[] endHash = new byte[32]; // get the ending hash for data addition verification

		for (int i = data.length; i < data.length + 32; i++)
		{
			endHash[i - data.length] = totdata[i];
		}

		byte[] salt = new byte[16];
		byte[] IV = new byte[16];
		byte[] hashPass = new byte[32];
		byte[] data_size = new byte[4];
		byte[] header = new byte[100];

		if (keyProvided != null) // If key was provided
		{
			byte[] storedKey = new byte[32];

			for (int i = 64; i < 96; i++)
			{
				storedKey[i - 64] = data[i]; // get stored hash of key
			}

			byte[] temp_hash = hash(keyProvided); // get hash of key provided

			if (!Arrays.equals(storedKey, temp_hash)) // if both are the same, then key is valid
			{
				throw new WrongKeyException(); // wrong key
			}
		}

		// Copy the data from the file into multiple arrays which will be used later on
		for (int i = 0; i < 16; i++)
		{
			salt[i] = data[i];
		}

		for (int i = 16; i < 48; i++)
		{
			hashPass[i - 16] = data[i];
		}

		for (int i = 48; i < 64; i++)
		{
			IV[i - 48] = data[i];
		}

		for (int i = 96; i < 100; i++)
		{
			data_size[i - 96] = data[i];
		}

		for (int i = 0; i < 100; i++)
		{
			header[i] = data[i];
		}

		byte[] key = keyProvided != null ? keyProvided : getKey(password, salt); // set decryption key
		byte[] tempHash = hash(combine(data, IV)); // calculate end hash
		byte[] tempHash2 = hash(combine(tempHash, key)); // combine with hash to get final hash

		if (!Arrays.equals(endHash, tempHash2)) // compare end hashes, if the same then no bytes appended
		{
			throw new javax.crypto.AEADBadTagException(); // there are appended bytes
		}

		try
		{

			int len = bytesToInt(data_size); // Get the integer value stored in data_size

			int lines = (len / 16) - 1; // The number of lines of data in the file

			byte[] tagsGCM = new byte[16]; // Stores the GCM tag of the data tags in file

			for (int i = 100; i < 116; i++)
			{
				tagsGCM[i - 100] = data[i];
			}

			byte[] tags = new byte[lines * 32]; // Get the encrypted data tags

			for (int i = 100 + len; i < 100 + len + (lines * 32); i++)
			{
				tags[i - 100 - len] = data[i];
			}

			byte[] test = combine(tags, tagsGCM); // Get the encrypted data tags + GCM tag to prepare for decyption

			// If javax.crypto.AEADBadTagException: Tag mismatch is thrown, then we know that the file was modified

			byte[] decTags = decrypt(test, key, IV, header); // Get the decrypted data tags
			byte[] currTag = new byte[32];
			HashMap<String, Integer> tagInfo = new HashMap<>(); // Assuming that there are no duplicate tags, wouldn't make any sense to have duplicates
			int index = 0;

			// Separate the byte array into String tags based on 32 byte segments and splitting filler data
			for (int i = 0; i < decTags.length; i++)
			{
				if (i != 0 && i % 32 == 0)
				{
					String temp = new String(currTag, StandardCharsets.UTF_8);
					String[] getTag = temp.split("\u0005");
					tagInfo.put(getTag[0], index);
					index++;
				}
				else if (i == decTags.length - 1)
				{
					currTag[i % 32] = decTags[i];
					String temp = new String(currTag, StandardCharsets.UTF_8);
					String[] getTag = temp.split("\u0005");
					tagInfo.put(getTag[0], index);
					break;
				}
				currTag[i % 32] = decTags[i];
			}

			// Check tag decrypt request to see if tag exists in file
			// "" means decrypt the whole file
			if (!tag.equals("") && !tagInfo.containsKey(tag))
			{
				return "ERROR: Tag not found";
			}

			BigInteger currIV = new BigInteger(IV); // Store in BigInt because 16 byte IV will be a large number
			BigInteger blockSize = BigInteger.valueOf(256); // used to add 256 to currIV

			if (tag.equals("")) // Decrypt the whole file and return the String
			{
				byte[] encData = new byte[lines * 256]; // The size of all the encrypted data
				String[] stringTags = new String[lines];

				for (String t : tagInfo.keySet()) // Set the names of tags in order to print out in correct order
				{
					int tagIndex = tagInfo.get(t);
					stringTags[tagIndex] = t;
				}

				int start = 100 + len + (lines * 32); // Where the encrypted data begins
				int end = start + (256 * lines); // the calculated end point of the data

				for (int i = start; i < end; i++)
				{
					encData[i - start] = data[i]; // copy encrypted data to byte array
				}

				byte[] dataGCM = new byte[lines * 16]; // GCM tag array

				for (int i = 116; i < 116 + (lines * 16); i++)
				{
					dataGCM[i - 116] = data[i]; // copy the GCM tags for decryption use
				}

				byte[] currData = new byte[256];
				int curr = 0;
				int currIndex = 0;

				for (int i = 0; i < encData.length; i++)
				{
					if (i != 0 && i % 256 == 0) // Decrypt block
					{
						currIV = currIV.add(blockSize); // get IV
						byte[] tempGCM = new byte[16];
						for (int j = curr; j < curr + 16; j++)
						{
							tempGCM[j - curr] = dataGCM[j]; // get GCM tag
						}
						curr += 16;
						byte[] tempData = combine(currData, tempGCM); // get total GCM enc data

						byte[] tempIV = currIV.toByteArray(); // convert BigInt to byte array IV
						byte[] tempDec = decrypt(tempData, key, tempIV, null); // decrypt
						String print = new String(tempDec, StandardCharsets.UTF_8);
						String tempOut = stringTags[currIndex] + ":" + print.split("\u0005")[0] + "\n";
						output += tempOut; // add data to output string
						currIndex++;
					}
					else if (i == encData.length - 1)  // Decrypt final block
					{
						currData[i % 256] = encData[i];
						currIV = currIV.add(blockSize); // get IV
						byte[] tempGCM = new byte[16];
						for (int j = curr; j < curr + 16; j++)
						{
							tempGCM[j - curr] = dataGCM[j]; // get GCM tag
						}

						byte[] tempData = combine(currData, tempGCM); // get total GCM enc data
						byte[] tempIV = currIV.toByteArray(); // convert BigInt to byte array IV

						byte[] tempDec = decrypt(tempData, key, tempIV, null); // decrypt
						String print = new String(tempDec, StandardCharsets.UTF_8);
						String tempOut = stringTags[currIndex] + ":" + print.split("\u0005")[0] + "\n";
						output += tempOut; // add data to output string
						break; // done with loop
					}

					currData[i % 256] = encData[i]; // add byte data to array
				}

			}
			else // Find the tag and only decrypt the required data, same process as earlier but with only one block
			{
				int target = tagInfo.get(tag);

				byte[] encData = new byte[256];
				byte[] tempTag = new byte[16];

				int start = 116 + (target * 16);

				for (int i = start; i < start + 16; i++)
				{
					tempTag[i - start] = data[i];
				}

				int dataStart = 100 + len + (lines * 32) + (256 * target);

				for (int i = dataStart; i < dataStart + 256; i++)
				{
					encData[i - dataStart] = data[i];
				}

				BigInteger blockSizeOff = BigInteger.valueOf(256 * (target + 1));
				currIV = currIV.add(blockSizeOff);
				byte[] tempIV = currIV.toByteArray();
				byte[] tempData = combine(encData, tempTag);
				byte[] tempDec = decrypt(tempData, key, tempIV, null);

				String print = new String(tempDec, StandardCharsets.UTF_8);
				String tempOut = tag + ":" + print.split("\u0005")[0] + "\n";
				output += tempOut;
			}

			return output; // return string
		}

		catch (Exception e) // If any general exception occurs while reading, this means that the data was modified
		{
			throw new javax.crypto.AEADBadTagException(); // data was modified, indicate modification
		}
	}

	// Change password by first reading the data from the encrypted file and then reformatting the file with the new password
	public void changePassword(String fileName, String oldPassword, String newPassword) throws Exception
	{
		if(verifyPassword(fileName, oldPassword)) // check if old password is correct
		{
			String data = readFile(fileName, oldPassword, null, ""); // read string data
			formatFile(fileName, data, newPassword); // re-format file
		}
	}
}