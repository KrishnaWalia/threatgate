package com.threatgate.model;

import java.io.Serial;
import java.io.Serializable;
import java.sql.Timestamp;
import java.util.Objects;

public class Organization implements Identifiable<Integer>, Serializable {
    @Serial
    private static final long serialVersionUID = 1L;

    private int id;
    private String name;
    private Timestamp createdAt;

    public Organization() {
        this.name = "";
        this.createdAt = new Timestamp(System.currentTimeMillis());
    }

    public Organization(int id, String name, Timestamp createdAt) {
        this.id = id;
        this.name = name != null ? name.trim() : "";
        this.createdAt = createdAt != null ? createdAt : new Timestamp(System.currentTimeMillis());
    }

    @Override
    public Integer getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name != null ? name.trim() : "";
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Timestamp createdAt) {
        this.createdAt = createdAt;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        if (!(other instanceof Organization)) {
            return false;
        }
        Organization that = (Organization) other;
        return id == that.id && Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name);
    }

    @Override
    public String toString() {
        return String.format("Organization [id=%d, name='%s', createdAt=%s]", id, name, createdAt);
    }
}
