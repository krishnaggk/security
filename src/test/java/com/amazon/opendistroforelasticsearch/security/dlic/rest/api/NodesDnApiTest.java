package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.helper.rest.RestHelper.HttpResponse;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import org.apache.http.Header;
import org.apache.http.HttpStatus;
import org.elasticsearch.common.settings.Settings;
import org.junit.Test;

import java.util.Collections;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;

public class NodesDnApiTest extends AbstractRestApiUnitTest {
    private HttpResponse response;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private <T> JsonNode asJsonNode(T t) throws Exception {
        return OBJECT_MAPPER.readTree(OBJECT_MAPPER.writeValueAsString(t));
    }

    private void testCrudScenarios(final int expectedStatus, final Header... headers) throws Exception {
        response = rh.executeGetRequest("_opendistro/_security/api/nodesdn?show_all=true", headers);
        assertThat(response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            JsonNode expected = asJsonNode(ImmutableMap.of(
                "connection1", Collections.singletonList("cn=popeye"),
                NodesDnApiAction.STATIC_NODES_DN_KEY, Collections.emptyList()));

            JsonNode node = OBJECT_MAPPER.readTree(response.getBody());
            assertThat(node, equalTo(asJsonNode(expected)));
        }

        response = rh.executeGetRequest("_opendistro/_security/api/nodesdn?show_all=false", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            JsonNode expected = asJsonNode(ImmutableMap.of("connection1", Collections.singletonList("cn=popeye")));
            JsonNode node = OBJECT_MAPPER.readTree(response.getBody());
            assertThat(node, equalTo(asJsonNode(expected)));
        }

        response = rh.executeGetRequest("_opendistro/_security/api/nodesdn", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            JsonNode expected = asJsonNode(ImmutableMap.of("connection1", Collections.singletonList("cn=popeye")));
            JsonNode node = OBJECT_MAPPER.readTree(response.getBody());
            assertThat(node, equalTo(asJsonNode(expected)));
        }

        response = rh.executeGetRequest("_opendistro/_security/api/nodesdn/connection1", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        if (expectedStatus == HttpStatus.SC_OK) {
            JsonNode expected = asJsonNode(ImmutableMap.of("connection1", Collections.singletonList("cn=popeye")));
            JsonNode node = OBJECT_MAPPER.readTree(response.getBody());
            assertThat(node, equalTo(asJsonNode(expected)));
        }

        response = rh.executePutRequest("_opendistro/_security/api/nodesdn/connection1", "{\"nodes_dn\": [\"cn=popeye\"]}", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

        response = rh.executePatchRequest("/_opendistro/_security/api/nodesdn/connection1", "[{ \"op\": \"add\", \"path\": \"/nodes_dn/-\", \"value\": \"bluto\" }]", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

        response = rh.executePatchRequest("/_opendistro/_security/api/nodesdn", "[{ \"op\": \"remove\", \"path\": \"/connection1/nodes_dn/0\"}]", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

        response = rh.executeDeleteRequest("_opendistro/_security/api/nodesdn/connection1", headers);
        assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
    }

    @Test
    public void testNodesDnApiWithDynamicConfigDisabled() throws Exception {
        setup();
        rh.keystore = "restapi/kirk-keystore.jks";
        rh.sendAdminCertificate = true;

        testCrudScenarios(HttpStatus.SC_BAD_REQUEST);
    }

    @Test
    public void testNodesDnApi() throws Exception {
        Settings settings = Settings.builder().put(ConfigConstants.OPENDISTRO_SECURITY_NODES_DN_DYNAMIC_CONFIG_ENABLED, true).build();
        setupWithRestRoles(settings);

        final Header adminCredsHeader = encodeBasicHeader("admin", "admin");
        final Header nonAdminCredsHeader = encodeBasicHeader("sarek", "sarek");

        {
            // No creds, no admin certificate - UNAUTHORIZED
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = false;
            testCrudScenarios(HttpStatus.SC_UNAUTHORIZED);
        }

        {
            // admin creds, no admin certificate - FORBIDDEN
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = false;
            testCrudScenarios(HttpStatus.SC_FORBIDDEN, adminCredsHeader);
        }

        {
            // any creds, admin certificate - OK
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = true;
            testCrudScenarios(HttpStatus.SC_OK, nonAdminCredsHeader);
        }

        {
            // any creds, admin certificate, disallowed key - OK
            rh.keystore = "restapi/kirk-keystore.jks";
            rh.sendAdminCertificate = true;

            final int expectedStatus = HttpStatus.SC_FORBIDDEN;

            response = rh.executePutRequest("_opendistro/_security/api/nodesdn/" + NodesDnApiAction.STATIC_NODES_DN_KEY, "{\"nodes_dn\": [\"cn=popeye\"]}", nonAdminCredsHeader);
            assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

            response = rh.executePatchRequest("/_opendistro/_security/api/nodesdn/" + NodesDnApiAction.STATIC_NODES_DN_KEY,
                "[{ \"op\": \"add\", \"path\": \"/nodes_dn/-\", \"value\": \"bluto\" }]" , nonAdminCredsHeader);
            assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));

            response = rh.executeDeleteRequest("_opendistro/_security/api/nodesdn/" + NodesDnApiAction.STATIC_NODES_DN_KEY, nonAdminCredsHeader);
            assertThat(response.getBody(), response.getStatusCode(), equalTo(expectedStatus));
        }
    }
}
