package com;

import org.apache.commons.io.FileUtils;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GHTag;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.PagedIterable;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Elad Salti on 13-Jul-17.
 */
public class Main {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        //Arguments input for the CMD
        String owner = args[0];
        String repositoryName = args[1];
        String startVersion = args[2];
        String endVersion = args[3];
        String cve = args[4];

        PrintWriter writer;
        /* --- C'tor --- */
        VulnerablePackage vulnerablePackage = new VulnerablePackage(new ArrayList<GHTag>(), startVersion, endVersion, owner, repositoryName);

        /* --- Github Connection --- */
        GitHub github = GitHub.connect("elad.salti7@gmail.com", "614dd497a6e41d98eb465ab6acfc9ab396ddc5dd");
        GHRepository repo = github.getRepository(owner + "/" + repositoryName);
        PagedIterable<GHTag> ghTags = repo.listTags();
        List<GHTag> tags = ghTags.asList();

        //Choose the start point
        int startPos = findStartPosInArray(vulnerablePackage.getStartVersion(), tags);

        //Check if the start version exist
        if (startPos == -1) {
            System.out.println("The start version was not found");
            return;
        }

        //Choose the end point
        int endPos = findEndPosInArray(vulnerablePackage.getEndVersion(), tags);

        //Check if the end version exist
        if (endPos == -1) {
            System.out.println("The end version was not found");
            return;
        }

        //Add the vulnerable version to the List
        for (int i = tags.size(); i >= 0; i--) {
            if (i <= startPos && i >= endPos) {
                vulnerablePackage.getVulnerableVersions().add(tags.get(i));
            }
        }

        //Download the vulnerable version from Github
        for (int i = 0; i < vulnerablePackage.getVulnerableVersions().size(); i++) {
            File file = new File("" + repositoryName + "-" + vulnerablePackage.getVulnerableVersions().get(i).getName() + ".tar.gz");
            URL url = new URL("https://github.com/" + owner + "/" + repositoryName + "/archive/" + vulnerablePackage.getVulnerableVersions().get(i).getName() + ".tar.gz");
            FileUtils.copyURLToFile(url, file);
        }

        //Checking the Sha 1 for each vulnerable version and create output.csv
        File dir = new File(System.getProperty("user.dir"));
        File[] directoryListing = dir.listFiles();
        if (directoryListing != null) {
            for (File child : directoryListing) {
                if (!child.getName().equals("GithubApi.jar"))
                    System.out.println(child.getAbsolutePath());
                writer = new PrintWriter(new FileWriter("output.csv", true));
                writer.println("CVE," + cve + "," + toHex(Hash.SHA1.checksum(child)).toLowerCase() + "," + toHex(Hash.MD5.checksum(child)).toLowerCase());
                System.out.println("CVE," + cve + "," + toHex(Hash.SHA1.checksum(child)) + "," + toHex(Hash.MD5.checksum(child)).toLowerCase());
                writer.close();
            }

        } else {
            System.out.println("Didn't found the folder");
        }

        System.out.println("please wait");
    }
    /* --- Private Static Method --- */
    //Find match between the start point with the start point of the list
    private static int findStartPosInArray(String startVersion, List<GHTag> list) {
        for (int i = 0; i < list.size(); i++) {
            if (startVersion.equals(list.get(i).getName())) {
                return i;
            }
        }

        return -1;
    }
    /* --- Private Static Method --- */
    //Find match between the end point with the end point of the list
    private static int findEndPosInArray(String endVersion, List<GHTag> list) {
        for (int i = 0; i < list.size(); i++) {
            if (endVersion.equals(list.get(i).getName())) {
                return i;
            }
        }

        return -1;
    }

    /* --- Private Static Method --- */
    //Convert from bytes to hexadecimal
    private static String toHex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

}
