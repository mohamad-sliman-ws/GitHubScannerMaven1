package com;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;
import org.kohsuke.github.GHTag;

import java.util.List;

/**
 * Created by Elad Salti on 13-Jul-17.
 */
public class VulnerablePackage {
    @SerializedName("versions")
    @Expose

    /* --- Private members --- */
    private List<GHTag> vulnerableVersions;
    private String startVersion;
    private String endVersion;
    private String owner;
    private String repositoryName;

    /* --- C'tor --- */
    public VulnerablePackage(List<GHTag> vulnerableVersions, String startVersion, String endVersion, String owner, String repositoryName) {
        this.vulnerableVersions = vulnerableVersions;
        this.startVersion = startVersion;
        this.endVersion = endVersion;
        this.owner = owner;
        this.repositoryName = repositoryName;
    }

    /* --- Getters and Setters --- */
    public List<GHTag> getVulnerableVersions() {
        return vulnerableVersions;
    }

    public void setVulnerableVersions(List<GHTag> vulnerableVersions) {
        this.vulnerableVersions = vulnerableVersions;
    }

    /* --- Getters and Setters --- */
    public String getStartVersion() {
        return startVersion;
    }

    public void setStartVersion(String startVersion) {
        this.startVersion = startVersion;
    }

    /* --- Getters and Setters --- */
    public String getEndVersion() {
        return endVersion;
    }

    public void setEndVersion(String endVersion) {
        this.endVersion = endVersion;
    }

    /* --- Getters and Setters --- */
    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    /* --- Getters and Setters --- */
    public String getRepositoryName() {
        return repositoryName;
    }

    public void setRepositoryName(String repositoryName) {
        this.repositoryName = repositoryName;
    }
}
