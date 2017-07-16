package com;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Elad Salti on 13-Jul-17.
 */
public enum Hash {

    MD5("MD5"),

    SHA1("SHA1"),

    SHA256("SHA-256"),

    SHA512("SHA-512");

    private String name;

    Hash(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    //Get input file and return Hash (Sha 1 and MD 5)
    public byte[] checksum(File input) throws IOException, NoSuchAlgorithmException {
        InputStream in = new FileInputStream(input);
        MessageDigest digest = MessageDigest.getInstance(getName());
        byte[] block = new byte[4096];
        int length;
        while ((length = in.read(block)) > 0) {
            digest.update(block, 0, length);
        }
        return digest.digest();
    }
}
