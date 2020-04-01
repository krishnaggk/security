package com.amazon.opendistroforelasticsearch.security.securityconf.impl.v7;

import com.amazon.opendistroforelasticsearch.security.securityconf.Hideable;
import com.fasterxml.jackson.annotation.JsonIgnore;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SslConfigV7 implements Hideable {
    public Map<String, List<String>> nodes_dn = new HashMap<>();

    @Override
    public String toString() {
        return "Ssl [nodes_dn=" + nodes_dn + ']';
    }

    @JsonIgnore
    @Override
    public boolean isHidden() {
        return false;
    }

    @JsonIgnore
    @Override
    public boolean isReserved() {
        return true;
    }
}
